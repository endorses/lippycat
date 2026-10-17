package wire

import (
	"context"
	"errors"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Service exposes a publisher store without giving peers mutation authority.
// Authorize must bind the requested hunter to its authenticated connection and
// current registration. Subscription requests cannot choose another issuer.
type Service struct {
	management.UnimplementedMediaControlServiceServer
	store           *mediarules.Store
	limits          Limits
	authorize       func(context.Context, string) error
	mu              sync.Mutex
	applications    map[string]*management.MediaRuleApplication
	activeHunters   map[string]int
	maxApplications int
}

func NewService(store *mediarules.Store, limits Limits, maxApplications int, authorize func(context.Context, string) error) (*Service, error) {
	if store == nil || authorize == nil || maxApplications <= 0 {
		return nil, errors.New("media-rule service requires a bounded store and source authorizer")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &Service{store: store, limits: limits, authorize: authorize, maxApplications: maxApplications,
		applications: make(map[string]*management.MediaRuleApplication), activeHunters: make(map[string]int)}, nil
}

func (s *Service) SubscribeMediaRules(req *management.MediaRuleRequest, stream management.MediaControlService_SubscribeMediaRulesServer) error {
	if req == nil || req.ProtocolVersion != Version || req.HunterId == "" {
		return status.Error(codes.InvalidArgument, "unsupported media-rule subscription")
	}
	if err := s.authorize(stream.Context(), req.HunterId); err != nil {
		return err
	}
	subscription, err := s.store.Subscribe()
	if err != nil {
		return ruleStatus(err)
	}
	defer subscription.Close()
	initial := subscription.Initial
	if !initial.Ready || req.ProcessorId != initial.Session.ProcessorID {
		return status.Error(codes.FailedPrecondition, "media-rule issuer is not ready or does not match the configured processor")
	}
	if err := s.retainApplication(req.HunterId); err != nil {
		return err
	}
	defer s.releaseApplication(req.HunterId)
	previous := scopedRules(initial.Rules, req.HunterId, initial.Sequence)
	if err := s.sendSnapshot(stream, initial.Session, initial.Sequence, previous); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case change, ok := <-subscription.Events:
			if !ok || change.ResyncRequired {
				return status.Error(codes.Aborted, "media-rule subscription requires a new snapshot")
			}
			if err := s.authorize(stream.Context(), req.HunterId); err != nil {
				return err
			}
			if !change.Ready || change.Session != initial.Session {
				return status.Error(codes.Aborted, "media-rule control generation changed")
			}
			next := scopedRules(change.Rules, req.HunterId, change.Sequence)
			update := &management.MediaRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(change.Session), Revision: change.Sequence}
			ids := make(map[string]struct{}, len(next))
			for _, rule := range next {
				ids[rule.ID] = struct{}{}
				update.Rules = append(update.Rules, EncodeRule(rule))
			}
			for _, old := range previous {
				if _, exists := ids[old.ID]; !exists {
					update.RemovedIds = append(update.RemovedIds, old.ID)
				}
			}
			if proto.Size(update) > s.limits.MaxMessageBytes {
				// A complete staged snapshot can replace a delta that exceeds a
				// single message, without exposing any partial replacement.
				if err := s.sendSnapshot(stream, change.Session, change.Sequence, next); err != nil {
					return err
				}
			} else if err := stream.Send(update); err != nil {
				return err
			}
			previous = next
		}
	}
}

func (s *Service) sendSnapshot(stream management.MediaControlService_SubscribeMediaRulesServer, session mediarules.Session, revision uint64, rules []mediarules.Rule) error {
	chunks, err := SnapshotChunks(session, mediarules.Revision(revision), rules, s.limits)
	if err != nil {
		return ruleStatus(err)
	}
	for _, chunk := range chunks {
		if err := stream.Send(chunk); err != nil {
			return err
		}
	}
	return nil
}

// Publisher store sequences include expiry/activation changes, unlike its
// control revision. Project them as the stream revision so a client sees every
// relevant transition, including an empty update for another hunter's change.
func scopedRules(rules []mediarules.Rule, hunterID string, revision uint64) []mediarules.Rule {
	var result []mediarules.Rule
	for _, rule := range rules {
		copy := rule
		copy.Scope = nil
		domains := make(map[uint32]bool)
		for _, scope := range rule.Scope {
			if scope.HunterID == hunterID {
				copy.Scope = append(copy.Scope, scope)
				domains[uint32(scope.Domain)] = true
			}
		}
		if len(copy.Scope) == 0 {
			continue
		}
		copy.Endpoints = nil
		for _, endpoint := range rule.Endpoints {
			if domains[uint32(endpoint.Key.Domain)] {
				copy.Endpoints = append(copy.Endpoints, endpoint)
			}
		}
		if len(copy.Endpoints) == 0 {
			continue
		}
		copy.Revision = mediarules.Revision(revision)
		result = append(result, copy)
	}
	return result
}

func (s *Service) ReportMediaRuleStatus(ctx context.Context, application *management.MediaRuleApplication) (*management.MediaRuleReceipt, error) {
	if application == nil || application.HunterId == "" || len(application.Error) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "invalid media-rule application status")
	}
	if err := s.authorize(ctx, application.HunterId); err != nil {
		return nil, err
	}
	session, err := DecodeSession(application.Session)
	if err != nil {
		return nil, ruleStatus(err)
	}
	current := s.store.Status()
	if !current.Ready || session != current.Session || application.AppliedRevision > current.Sequence {
		return nil, status.Error(codes.FailedPrecondition, "stale media-rule application status")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeHunters[application.HunterId] == 0 {
		return nil, status.Error(codes.FailedPrecondition, "media-rule application status requires a live subscription")
	}
	old := s.applications[application.HunterId]
	if old != nil && old.AppliedRevision > application.AppliedRevision {
		return nil, status.Error(codes.FailedPrecondition, "media-rule status cannot move backwards")
	}
	s.applications[application.HunterId] = proto.Clone(application).(*management.MediaRuleApplication)
	return &management.MediaRuleReceipt{Accepted: true}, nil
}

// A live subscription reserves its bounded status slot before sending a
// snapshot. Same-hunter reconnects share that reservation until the final stream
// exits, so an older stream cannot remove its replacement's application status.
func (s *Service) retainApplication(hunterID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeHunters[hunterID] == 0 && len(s.activeHunters) >= s.maxApplications {
		return status.Error(codes.ResourceExhausted, "media-rule application status capacity exceeded")
	}
	s.activeHunters[hunterID]++
	return nil
}

func (s *Service) releaseApplication(hunterID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeHunters[hunterID] > 1 {
		s.activeHunters[hunterID]--
		return
	}
	delete(s.activeHunters, hunterID)
	delete(s.applications, hunterID)
}

func (s *Service) Application(hunterID string) *management.MediaRuleApplication {
	s.mu.Lock()
	defer s.mu.Unlock()
	if application := s.applications[hunterID]; application != nil {
		return proto.Clone(application).(*management.MediaRuleApplication)
	}
	return nil
}

func ruleStatus(err error) error {
	switch {
	case errors.Is(err, mediarules.ErrCapacity):
		return status.Error(codes.ResourceExhausted, "media-rule configured capacity exceeded")
	case errors.Is(err, mediarules.ErrAuthority), errors.Is(err, mediarules.ErrScope):
		return status.Error(codes.PermissionDenied, "media-rule source is not authorized")
	case errors.Is(err, mediarules.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid media-rule message")
	default:
		return status.Error(codes.FailedPrecondition, "media-rule state requires reconciliation")
	}
}
