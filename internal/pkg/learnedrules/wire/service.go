package wire

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	pb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type subscription struct {
	id           string
	sent         uint64
	report       *pb.LearnedRuleApplication
	capabilities []*pb.LearnedCapability
}

// Service exposes one committed store. Authorize must bind a requested source
// to the authenticated transport identity and its current source registration.
type Service struct {
	pb.UnimplementedLearnedControlServiceServer
	store           *learnedrules.Store
	limits          Limits
	authorize       func(context.Context, string) error
	mu              sync.Mutex
	active          map[string]*subscription
	maxApplications int
}

func NewService(store *learnedrules.Store, limits Limits, maxApplications int, authorize func(context.Context, string) error) (*Service, error) {
	if store == nil || authorize == nil || maxApplications <= 0 {
		return nil, errors.New("learned service requires bounded store and source authorizer")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &Service{store: store, limits: limits, authorize: authorize, active: map[string]*subscription{}, maxApplications: maxApplications}, nil
}
func (s *Service) SubscribeLearnedRules(req *pb.LearnedRuleRequest, stream pb.LearnedControlService_SubscribeLearnedRulesServer) error {
	if req == nil || req.ProtocolVersion != Version || req.HunterId == "" || len(req.HunterId) > 4096 {
		return status.Error(codes.InvalidArgument, "invalid learned rule request")
	}
	if err := s.authorize(stream.Context(), req.HunterId); err != nil {
		return err
	}
	if err := ValidateCapabilities(req.Capabilities); err != nil {
		return ruleStatus(err)
	}
	caps := cloneCapabilities(req.Capabilities)
	sub, err := s.store.Subscribe()
	if err != nil {
		return ruleStatus(err)
	}
	defer sub.Close()
	initial := sub.Initial
	if !initial.Ready || req.ProcessorId != initial.Session.ProcessorID {
		return status.Error(codes.FailedPrecondition, "learned authority is not ready or does not match")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return status.Error(codes.Internal, "cannot allocate subscription identity")
	}
	live := &subscription{id: hex.EncodeToString(token), capabilities: cloneCapabilities(caps)}
	s.mu.Lock()
	if s.active[req.HunterId] == nil && len(s.active) >= s.maxApplications {
		s.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "learned application capacity exceeded")
	}
	s.active[req.HunterId] = live
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.active[req.HunterId] == live {
			delete(s.active, req.HunterId)
		}
	}()
	send := func(snapshot learnedrules.Snapshot) error {
		if err := s.authorize(stream.Context(), req.HunterId); err != nil {
			return err
		}
		if !snapshot.Ready || snapshot.Session != initial.Session {
			return status.Error(codes.Aborted, "learned authority generation changed")
		}
		var bindings []learnedrules.Binding
		for _, b := range snapshot.Rules {
			for _, scope := range b.Scope {
				if scope.HunterID == req.HunterId {
					if !Supports(caps, b) {
						return status.Error(codes.Unimplemented, "source lacks required learned capability")
					}
					bindings = append(bindings, b)
					break
				}
			}
		}
		// Scope and revisions are immutable: transmit complete bindings, never a
		// rewritten subset. Store enforces each source's authorized local scope.
		header := &pb.LearnedRuleUpdate{Capabilities: caps, SubscriptionId: live.id}
		overhead := proto.Size(header)
		limits := s.limits
		limits.MaxMessageBytes -= overhead
		limits.MaxSnapshotBytes -= overhead
		if limits.MaxMessageBytes <= 0 {
			return ruleStatus(learnedrules.ErrCapacity)
		}
		chunks, err := SnapshotChunks(snapshot.Session, learnedrules.Revision(snapshot.Sequence), bindings, limits)
		if err != nil {
			return ruleStatus(err)
		}
		total := 0
		for i, chunk := range chunks {
			chunk.SubscriptionId = live.id
			if i == 0 {
				chunk.Capabilities = cloneCapabilities(caps)
			}
			total += proto.Size(chunk)
			if proto.Size(chunk) > s.limits.MaxMessageBytes || total > s.limits.MaxSnapshotBytes {
				return ruleStatus(learnedrules.ErrCapacity)
			}
		}
		for _, chunk := range chunks {
			// A fast peer may report as soon as Send makes the final chunk
			// visible, before Send returns. Publish its admissible revision
			// immediately before that call; stream failure removes the slot.
			if chunk.SnapshotEnd {
				s.mu.Lock()
				if s.active[req.HunterId] == live {
					live.sent = snapshot.Sequence
				}
				s.mu.Unlock()
			}
			if err := stream.Send(chunk); err != nil {
				return err
			}
		}
		return nil
	}
	if err := send(initial.Snapshot); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case change, ok := <-sub.Events:
			if !ok || change.ResyncRequired {
				return status.Error(codes.Aborted, "learned subscription requires complete resynchronization")
			}
			s.mu.Lock()
			current := s.active[req.HunterId] == live
			s.mu.Unlock()
			if !current {
				return status.Error(codes.Aborted, "learned subscription replaced")
			}
			if err := send(change.Snapshot); err != nil {
				return err
			}
		}
	}
}
func (s *Service) ReportLearnedRuleStatus(ctx context.Context, a *pb.LearnedRuleApplication) (*pb.LearnedRuleReceipt, error) {
	if a == nil || a.HunterId == "" || a.SubscriptionId == "" || len(a.Error) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "invalid learned application report")
	}
	if err := s.authorize(ctx, a.HunterId); err != nil {
		return nil, err
	}
	session, err := DecodeSession(a.Session)
	if err != nil {
		return nil, ruleStatus(err)
	}
	current := s.store.Status()
	if !current.Ready || session != current.Session {
		return nil, status.Error(codes.FailedPrecondition, "stale learned application session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.active[a.HunterId]
	if live == nil || live.id != a.SubscriptionId {
		return nil, status.Error(codes.FailedPrecondition, "report requires current source subscription")
	}
	if err := validateApplicationAdapters(a, live.capabilities); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid learned adapter application counts")
	}
	if a.AppliedRevision == 0 || a.AppliedRevision > live.sent || (a.Synchronized && (a.AppliedRevision != live.sent || a.Error != "")) || (live.report != nil && a.AppliedRevision < live.report.AppliedRevision) {
		return nil, status.Error(codes.FailedPrecondition, "invalid learned application revision")
	}
	live.report = proto.Clone(a).(*pb.LearnedRuleApplication)
	return &pb.LearnedRuleReceipt{Accepted: true}, nil
}
func (s *Service) Application(source string) *pb.LearnedRuleApplication {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.active[source]; live != nil && live.report != nil {
		return proto.Clone(live.report).(*pb.LearnedRuleApplication)
	}
	return nil
}
func ruleStatus(err error) error {
	switch {
	case errors.Is(err, learnedrules.ErrCapacity):
		return status.Error(codes.ResourceExhausted, "learned rule capacity exceeded")
	case errors.Is(err, learnedrules.ErrUnsupported):
		return status.Error(codes.Unimplemented, "unsupported learned rule capability")
	case errors.Is(err, learnedrules.ErrAuthority), errors.Is(err, learnedrules.ErrScope):
		return status.Error(codes.PermissionDenied, "learned source is not authorized")
	case errors.Is(err, learnedrules.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid learned rule message")
	default:
		return status.Error(codes.FailedPrecondition, "learned state requires resynchronization")
	}
}

// Capabilities reports only the current authenticated subscription's bounded
// negotiated contracts. A disconnected or replaced stream has no active view.
func (s *Service) Capabilities(source string) []*pb.LearnedCapability {
	s.mu.Lock()
	defer s.mu.Unlock()
	if live := s.active[source]; live != nil {
		return cloneCapabilities(live.capabilities)
	}
	return nil
}
func validateApplicationAdapters(application *pb.LearnedRuleApplication, capabilities []*pb.LearnedCapability) error {
	if len(application.AdapterApplications) > 64 {
		return learnedrules.ErrInvalid
	}
	seen := make(map[adapterApplicationKey]bool)
	var bindings, selectors uint64
	for _, a := range application.AdapterApplications {
		if a == nil {
			return learnedrules.ErrInvalid
		}
		key := adapterApplicationKey{a.AdapterId, a.ContextVersion}
		if seen[key] {
			return learnedrules.ErrInvalid
		}
		seen[key] = true
		supported := false
		for _, c := range capabilities {
			if c.AdapterId == a.AdapterId && c.ContextVersion == a.ContextVersion {
				supported = true
				break
			}
		}
		if !supported {
			return learnedrules.ErrInvalid
		}
		bindings += uint64(a.ActiveBindings)
		selectors += uint64(a.ActiveSelectors)
	}
	if len(application.AdapterApplications) > 0 && (bindings != uint64(application.ActiveBindings) || selectors != uint64(application.ActiveSelectors)) {
		return learnedrules.ErrInvalid
	}
	return nil
}

type adapterApplicationKey struct {
	id      string
	version uint32
}
