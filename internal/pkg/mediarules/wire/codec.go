// Package wire translates bounded temporary media rules to the management
// protocol. Authentication belongs to the connection owner; packet selection
// remains with the shared mediarules store.
package wire

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"google.golang.org/protobuf/proto"
)

const Version = 1
const GrantVersion = 2

func EncodeSession(s mediarules.Session) *management.MediaRuleSession {
	return &management.MediaRuleSession{ProcessorId: s.ProcessorID, Generation: s.Generation}
}

func DecodeSession(s *management.MediaRuleSession) (mediarules.Session, error) {
	if s == nil || s.ProcessorId == "" || s.Generation == 0 {
		return mediarules.Session{}, mediarules.ErrSession
	}
	return mediarules.Session{ProcessorID: s.ProcessorId, Generation: s.Generation}, nil
}

func EncodeRule(r mediarules.Rule) *management.MediaRule {
	w := &management.MediaRule{Id: r.ID, Session: EncodeSession(r.Session), Revision: uint64(r.Revision),
		Call: &management.MediaRuleCall{RegistrySession: r.Call.Lifetime.Session, RegistryGeneration: r.Call.Lifetime.Generation,
			CallId: r.Call.CallID, FromTag: r.Call.FromTag, ToTag: r.Call.ToTag,
			SelectionRevision: r.Call.SelectionRevision, CapturePolicyRevision: r.Call.CapturePolicyRevision, FilterIds: append([]string(nil), r.Call.FilterIDs...)},
		NotBeforeNs: r.NotBefore.UnixNano(), ExpiresAtNs: r.ExpiresAt.UnixNano()}
	w.CaptureSignature = append([]byte(nil), r.CaptureSignature...)
	for _, ref := range r.Call.SelectionGrants {
		w.Call.SelectionGrants = append(w.Call.SelectionGrants, &management.CaptureSelectionRef{Id: ref.ID, Revision: ref.Revision})
	}
	for _, scope := range r.Scope {
		w.Scopes = append(w.Scopes, &management.MediaRuleScope{HunterId: scope.HunterID, Domain: uint32(scope.Domain)})
	}
	for _, endpoint := range r.Endpoints {
		w.Endpoints = append(w.Endpoints, &management.MediaRuleEndpoint{Domain: uint32(endpoint.Key.Domain),
			Address: endpoint.Key.Addr.String(), Port: uint32(endpoint.Key.Port), Kind: management.MediaRuleEndpointKind(endpoint.Kind)})
	}
	return w
}

// DecodeRule rejects malformed wire values before narrowing integer fields.
// The store separately validates authority, ownership, deadlines and aggregate
// resource accounting before publishing any rule.
func DecodeRule(w *management.MediaRule) (mediarules.Rule, error) {
	if w == nil || w.Call == nil {
		return mediarules.Rule{}, mediarules.ErrInvalid
	}
	session, err := DecodeSession(w.Session)
	if err != nil {
		return mediarules.Rule{}, err
	}
	r := mediarules.Rule{ID: w.Id, Session: session, Revision: mediarules.Revision(w.Revision),
		Call: mediarules.CallAssociation{Lifetime: callregistry.Lifetime{Session: w.Call.RegistrySession, Generation: w.Call.RegistryGeneration},
			CallID: w.Call.CallId, FromTag: w.Call.FromTag, ToTag: w.Call.ToTag,
			SelectionRevision: w.Call.SelectionRevision, CapturePolicyRevision: w.Call.CapturePolicyRevision, FilterIDs: append([]string(nil), w.Call.FilterIds...)},
		NotBefore: time.Unix(0, w.NotBeforeNs), ExpiresAt: time.Unix(0, w.ExpiresAtNs)}
	r.CaptureSignature = append([]byte(nil), w.CaptureSignature...)
	for _, ref := range w.Call.SelectionGrants {
		if ref == nil {
			return mediarules.Rule{}, mediarules.ErrInvalid
		}
		r.Call.SelectionGrants = append(r.Call.SelectionGrants, mediarules.SelectionRef{ID: ref.Id, Revision: ref.Revision})
	}
	for _, scope := range w.Scopes {
		if scope == nil {
			return mediarules.Rule{}, mediarules.ErrScope
		}
		r.Scope = append(r.Scope, mediarules.Scope{HunterID: scope.HunterId, Domain: mediaadmission.DomainID(scope.Domain)})
	}
	for _, endpoint := range w.Endpoints {
		if endpoint == nil || endpoint.Port == 0 || endpoint.Port > 65535 || endpoint.Kind < 0 || endpoint.Kind > management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_MUX {
			return mediarules.Rule{}, mediarules.ErrInvalid
		}
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return mediarules.Rule{}, fmt.Errorf("media-rule address: %w", mediarules.ErrInvalid)
		}
		key, err := mediaadmission.NewEndpoint(mediaadmission.DomainID(endpoint.Domain), address, uint16(endpoint.Port))
		if err != nil || key.Addr.String() != endpoint.Address {
			return mediarules.Rule{}, fmt.Errorf("media-rule canonical endpoint: %w", mediarules.ErrInvalid)
		}
		r.Endpoints = append(r.Endpoints, mediarules.Endpoint{Key: key, Kind: mediarules.MediaKind(endpoint.Kind)})
	}
	return r, nil
}

// Limits also bound staged snapshots, which have not yet reached Store's own
// resource accounting. The transport must enforce MaxMessageBytes on decoding.
type Limits struct {
	MaxMessageBytes  int
	MaxSnapshotBytes int
	MaxRules         int
}

func (l Limits) validate() error {
	if l.MaxMessageBytes <= 0 || l.MaxSnapshotBytes < l.MaxMessageBytes || l.MaxRules <= 0 {
		return errors.New("media-rule wire limits must be positive and fit a snapshot")
	}
	return nil
}

// SnapshotChunks never splits a rule. Callers send chunks serially and do not
// interleave deltas before snapshot_end. Each returned chunk owns its contents.
func SnapshotChunks(session mediarules.Session, revision mediarules.Revision, rules []mediarules.Rule, limits Limits) ([]*management.MediaRuleUpdate, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if session.ProcessorID == "" || session.Generation == 0 || revision == 0 || len(rules) > limits.MaxRules {
		return nil, mediarules.ErrInvalid
	}
	version := uint32(Version)
	for _, rule := range rules {
		if len(rule.Call.SelectionGrants) > 0 {
			version = GrantVersion
		}
	}
	newChunk := func() *management.MediaRuleUpdate {
		return &management.MediaRuleUpdate{ProtocolVersion: version, Session: EncodeSession(session), Revision: uint64(revision)}
	}
	chunk := newChunk()
	chunk.SnapshotBegin = true
	var chunks []*management.MediaRuleUpdate
	total := 0
	for _, rule := range rules {
		encoded := EncodeRule(rule)
		chunk.Rules = append(chunk.Rules, encoded)
		// Reserve both framing flags, even on a middle chunk.
		if proto.Size(chunk)+4 > limits.MaxMessageBytes {
			chunk.Rules = chunk.Rules[:len(chunk.Rules)-1]
			if len(chunk.Rules) == 0 {
				return nil, mediarules.ErrCapacity
			}
			total += proto.Size(chunk)
			chunks = append(chunks, chunk)
			chunk = newChunk()
			chunk.Rules = append(chunk.Rules, encoded)
			if proto.Size(chunk)+4 > limits.MaxMessageBytes {
				return nil, mediarules.ErrCapacity
			}
		}
	}
	chunk.SnapshotEnd = true
	total += proto.Size(chunk)
	if total > limits.MaxSnapshotBytes || proto.Size(chunk) > limits.MaxMessageBytes {
		return nil, mediarules.ErrCapacity
	}
	return append(chunks, chunk), nil
}

// Receiver is owned by one authenticated subscription. A new receiver invalidates
// old callbacks immediately when the store already knows a remote session.
// Closing a stream does not renew rules; installed rules retain their deadlines.
type Receiver struct {
	mu       sync.Mutex
	store    *mediarules.Store
	issuer   string
	limits   Limits
	control  mediarules.Control
	session  mediarules.Session
	started  bool
	staging  bool
	revision mediarules.Revision
	pending  []mediarules.Rule
	bytes    int
}

func NewReceiver(store *mediarules.Store, authenticatedIssuer string, limits Limits) (*Receiver, error) {
	if store == nil || authenticatedIssuer == "" {
		return nil, mediarules.ErrAuthority
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	r := &Receiver{store: store, issuer: authenticatedIssuer, limits: limits}
	if known := store.Status().Session; known.Generation != 0 {
		var err error
		r.control, err = store.StartSession(authenticatedIssuer, known)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Receiver) Apply(update *management.MediaRuleUpdate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if update == nil || (update.ProtocolVersion != Version && update.ProtocolVersion != GrantVersion) {
		return mediarules.ErrInvalid
	}
	if proto.Size(update) > r.limits.MaxMessageBytes || len(update.Rules) > r.limits.MaxRules || len(update.RemovedIds) > r.limits.MaxRules {
		return mediarules.ErrCapacity
	}
	for _, encoded := range update.Rules {
		if update.ProtocolVersion == Version && encoded != nil && (len(encoded.GetCall().GetSelectionGrants()) > 0 || len(encoded.CaptureSignature) > 0) {
			return mediarules.ErrInvalid
		}
	}
	session, err := DecodeSession(update.Session)
	if err != nil || session.ProcessorID != r.issuer {
		return mediarules.ErrAuthority
	}
	if update.ResyncRequired {
		return mediarules.ErrNotReady
	}
	if !r.started {
		if !update.SnapshotBegin {
			return mediarules.ErrNotReady
		}
		r.control, err = r.store.StartSession(r.issuer, session)
		if err != nil {
			return err
		}
		r.session, r.started = session, true
	} else if session != r.session {
		return mediarules.ErrSession
	}
	revision := mediarules.Revision(update.Revision)
	if revision == 0 {
		return mediarules.ErrRevision
	}
	if update.SnapshotBegin {
		if r.staging {
			return mediarules.ErrInvalid
		}
		r.staging, r.revision, r.pending, r.bytes = true, revision, nil, 0
	}
	if r.staging {
		if revision != r.revision || len(update.RemovedIds) != 0 {
			return mediarules.ErrRevision
		}
		r.bytes += proto.Size(update)
		if r.bytes > r.limits.MaxSnapshotBytes || len(update.Rules) > r.limits.MaxRules-len(r.pending) {
			return mediarules.ErrCapacity
		}
	} else if update.SnapshotEnd {
		return mediarules.ErrInvalid
	}
	decoded := make([]mediarules.Rule, 0, len(update.Rules))
	for _, encoded := range update.Rules {
		rule, err := DecodeRule(encoded)
		if err != nil {
			return err
		}
		decoded = append(decoded, rule)
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
