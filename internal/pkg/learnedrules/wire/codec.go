// Package wire carries versioned subject-neutral bindings. Authentication belongs
// to the connection owner; committed state and adapter validation belong to Store.
package wire

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	pb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"google.golang.org/protobuf/proto"
)

const Version uint32 = 1
const EvidenceVersion uint32 = 1
const EndpointSelectorVersion uint32 = 1

func EncodeSession(s learnedrules.Session) *pb.LearnedRuleSession {
	return &pb.LearnedRuleSession{ProcessorId: s.ProcessorID, Generation: s.Generation}
}
func DecodeSession(s *pb.LearnedRuleSession) (learnedrules.Session, error) {
	if s == nil || s.ProcessorId == "" || s.Generation == 0 || len(s.ProtoReflect().GetUnknown()) != 0 {
		return learnedrules.Session{}, learnedrules.ErrSession
	}
	return learnedrules.Session{ProcessorID: s.ProcessorId, Generation: s.Generation}, nil
}
func EncodeBinding(b learnedrules.Binding) *pb.LearnedBinding {
	w := &pb.LearnedBinding{Id: b.ID, Session: EncodeSession(b.Session), Revision: uint64(b.Revision), AdapterId: b.AdapterID, ContextVersion: b.ContextVersion, SubjectId: b.Subject.ID, SubjectIncarnation: b.Subject.Incarnation, AttributionContext: b.AttributionContext, EvidenceRefs: append([]string(nil), b.EvidenceRefs...), Context: append([]byte(nil), b.Context...), Proof: append([]byte(nil), b.Proof...), NotBeforeNs: b.NotBefore.UnixNano(), ExpiresAtNs: b.ExpiresAt.UnixNano()}
	for _, v := range b.Intents {
		w.Intents = append(w.Intents, &pb.LearnedIntent{Id: v.ID, Revision: v.Revision})
	}
	for _, v := range b.Scope {
		w.Scopes = append(w.Scopes, &pb.LearnedRuleScope{HunterId: v.HunterID, Domain: uint32(v.Domain)})
	}
	for _, v := range b.Selectors {
		s := &pb.LearnedSelector{Domain: uint32(v.Domain), Address: v.Address.String(), Port: uint32(v.Port), Protocol: uint32(v.Protocol), Direction: uint32(v.Direction)}
		if v.Qualifier.ID != "" {
			s.Qualifier = &pb.LearnedQualifier{Id: v.Qualifier.ID, Version: v.Qualifier.Version}
		}
		w.Selectors = append(w.Selectors, s)
	}
	return w
}
func DecodeBinding(w *pb.LearnedBinding) (learnedrules.Binding, error) {
	if w == nil || len(w.ProtoReflect().GetUnknown()) != 0 {
		return learnedrules.Binding{}, learnedrules.ErrInvalid
	}
	session, err := DecodeSession(w.Session)
	if err != nil {
		return learnedrules.Binding{}, err
	}
	b := learnedrules.Binding{ID: w.Id, Session: session, Revision: learnedrules.Revision(w.Revision), AdapterID: w.AdapterId, ContextVersion: w.ContextVersion, Subject: learnedrules.Subject{ID: w.SubjectId, Incarnation: w.SubjectIncarnation}, AttributionContext: w.AttributionContext, EvidenceRefs: append([]string(nil), w.EvidenceRefs...), Context: append([]byte(nil), w.Context...), Proof: append([]byte(nil), w.Proof...), NotBefore: time.Unix(0, w.NotBeforeNs), ExpiresAt: time.Unix(0, w.ExpiresAtNs)}
	for _, v := range w.Intents {
		if v == nil || len(v.ProtoReflect().GetUnknown()) != 0 {
			return learnedrules.Binding{}, learnedrules.ErrInvalid
		}
		b.Intents = append(b.Intents, learnedrules.IntentRef{ID: v.Id, Revision: v.Revision})
	}
	for _, v := range w.Scopes {
		if v == nil || len(v.ProtoReflect().GetUnknown()) != 0 {
			return learnedrules.Binding{}, learnedrules.ErrInvalid
		}
		b.Scope = append(b.Scope, learnedrules.Scope{HunterID: v.HunterId, Domain: learnedrules.DomainID(v.Domain)})
	}
	for _, v := range w.Selectors {
		if v == nil || len(v.ProtoReflect().GetUnknown()) != 0 || v.Port > 65535 || v.Protocol > 255 || v.Direction > uint32(learnedrules.Destination) {
			return learnedrules.Binding{}, learnedrules.ErrInvalid
		}
		address, err := netip.ParseAddr(v.Address)
		if err != nil || address.String() != v.Address {
			return learnedrules.Binding{}, fmt.Errorf("canonical learned endpoint: %w", learnedrules.ErrInvalid)
		}
		s := learnedrules.Selector{Domain: learnedrules.DomainID(v.Domain), Address: address, Port: uint16(v.Port), Protocol: learnedrules.Protocol(v.Protocol), Direction: learnedrules.Direction(v.Direction)}
		if v.Qualifier != nil {
			if len(v.Qualifier.ProtoReflect().GetUnknown()) != 0 {
				return learnedrules.Binding{}, learnedrules.ErrUnsupported
			}
			s.Qualifier = learnedrules.Qualifier{ID: v.Qualifier.Id, Version: v.Qualifier.Version}
			if s.Qualifier.ID == "" {
				return learnedrules.Binding{}, learnedrules.ErrInvalid
			}
		}
		if err := s.Validate(); err != nil {
			return learnedrules.Binding{}, err
		}
		b.Selectors = append(b.Selectors, s)
	}
	return b, nil
}

// Limits bound transport staging independently of committed store limits.
type Limits struct{ MaxMessageBytes, MaxSnapshotBytes, MaxRules int }

func (l Limits) validate() error {
	if l.MaxMessageBytes <= 0 || l.MaxSnapshotBytes < l.MaxMessageBytes || l.MaxRules <= 0 {
		return errors.New("learned wire limits must be positive and fit snapshot")
	}
	return nil
}

// SnapshotChunks preserves every immutable binding revision and proof byte.
func SnapshotChunks(session learnedrules.Session, revision learnedrules.Revision, bindings []learnedrules.Binding, limits Limits) ([]*pb.LearnedRuleUpdate, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if session.ProcessorID == "" || session.Generation == 0 || revision == 0 {
		return nil, learnedrules.ErrInvalid
	}
	if len(bindings) > limits.MaxRules {
		return nil, learnedrules.ErrCapacity
	}
	fresh := func() *pb.LearnedRuleUpdate {
		return &pb.LearnedRuleUpdate{ProtocolVersion: Version, Session: EncodeSession(session), Revision: uint64(revision)}
	}
	chunk := fresh()
	chunk.SnapshotBegin = true
	var chunks []*pb.LearnedRuleUpdate
	total := 0
	for _, binding := range bindings {
		encoded := EncodeBinding(binding)
		chunk.Bindings = append(chunk.Bindings, encoded)
		if proto.Size(chunk)+4 > limits.MaxMessageBytes {
			chunk.Bindings = chunk.Bindings[:len(chunk.Bindings)-1]
			if len(chunk.Bindings) == 0 {
				return nil, learnedrules.ErrCapacity
			}
			total += proto.Size(chunk)
			chunks = append(chunks, chunk)
			chunk = fresh()
			chunk.Bindings = append(chunk.Bindings, encoded)
			if proto.Size(chunk)+4 > limits.MaxMessageBytes {
				return nil, learnedrules.ErrCapacity
			}
		}
	}
	chunk.SnapshotEnd = true
	total += proto.Size(chunk)
	if total > limits.MaxSnapshotBytes || proto.Size(chunk) > limits.MaxMessageBytes {
		return nil, learnedrules.ErrCapacity
	}
	return append(chunks, chunk), nil
}

// Receiver is scoped to one authenticated stream and one advertised capability
// set. A new receiver invalidates stale callbacks without renewing old rules.
type Receiver struct {
	mu               sync.Mutex
	store            *learnedrules.Store
	issuer           string
	limits           Limits
	capabilities     []*pb.LearnedCapability
	control          learnedrules.Control
	session          learnedrules.Session
	started, staging bool
	revision         learnedrules.Revision
	pending          []learnedrules.Binding
	bytes            int
	subscriptionID   string
}

func NewReceiver(store *learnedrules.Store, issuer string, limits Limits, capabilities []*pb.LearnedCapability) (*Receiver, error) {
	if store == nil || issuer == "" {
		return nil, learnedrules.ErrAuthority
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := ValidateCapabilities(capabilities); err != nil {
		return nil, err
	}
	r := &Receiver{store: store, issuer: issuer, limits: limits, capabilities: cloneCapabilities(capabilities)}
	if known := store.Status().Session; known.Generation != 0 {
		var err error
		r.control, err = store.StartSession(issuer, known)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}
func (r *Receiver) SubscriptionID() string { r.mu.Lock(); defer r.mu.Unlock(); return r.subscriptionID }
func (r *Receiver) Apply(update *pb.LearnedRuleUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if update == nil || update.ProtocolVersion != Version || len(update.ProtoReflect().GetUnknown()) != 0 {
		return learnedrules.ErrUnsupported
	}
	if proto.Size(update) > r.limits.MaxMessageBytes || len(update.Bindings) > r.limits.MaxRules || len(update.RemovedIds) > r.limits.MaxRules {
		return learnedrules.ErrCapacity
	}
	session, err := DecodeSession(update.Session)
	if err != nil || session.ProcessorID != r.issuer {
		return learnedrules.ErrAuthority
	}
	if update.ResyncRequired {
		return learnedrules.ErrNotReady
	}
	if !r.started {
		if !update.SnapshotBegin {
			return learnedrules.ErrNotReady
		}
		if update.SubscriptionId == "" || !equalCapabilities(update.Capabilities, r.capabilities) {
			return learnedrules.ErrUnsupported
		}
		r.control, err = r.store.StartSession(r.issuer, session)
		if err != nil {
			return err
		}
		r.session, r.started, r.subscriptionID = session, true, update.SubscriptionId
	} else if session != r.session || update.SubscriptionId != r.subscriptionID {
		return learnedrules.ErrSession
	} else if len(update.Capabilities) > 0 && !equalCapabilities(update.Capabilities, r.capabilities) {
		return learnedrules.ErrUnsupported
	}
	revision := learnedrules.Revision(update.Revision)
	if revision == 0 {
		return learnedrules.ErrRevision
	}
	if update.SnapshotBegin {
		if r.staging {
			return learnedrules.ErrInvalid
		}
		r.staging, r.revision, r.pending, r.bytes = true, revision, nil, 0
	}
	if r.staging {
		if revision != r.revision || len(update.RemovedIds) > 0 {
			return learnedrules.ErrRevision
		}
		r.bytes += proto.Size(update)
		if r.bytes > r.limits.MaxSnapshotBytes || len(update.Bindings) > r.limits.MaxRules-len(r.pending) {
			return learnedrules.ErrCapacity
		}
	} else if update.SnapshotEnd {
		return learnedrules.ErrInvalid
	}
	decoded := make([]learnedrules.Binding, 0, len(update.Bindings))
	for _, w := range update.Bindings {
		b, err := DecodeBinding(w)
		if err != nil {
			return err
		}
		if !Supports(r.capabilities, b) {
			return learnedrules.ErrUnsupported
		}
		decoded = append(decoded, b)
	}
	if r.staging {
		r.pending = append(r.pending, decoded...)
		if !update.SnapshotEnd {
			return nil
		}
		err := r.store.ApplySnapshot(r.control, revision, r.pending)
		r.pending, r.bytes, r.staging = nil, 0, false
		return err
	}
	return r.store.ApplyDelta(r.control, revision, decoded, update.RemovedIds)
}
