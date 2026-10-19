package learnedrules

import (
	"fmt"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"net/netip"
	"time"
)

var ErrInvalid = core.ErrInvalid
var ErrScope = core.ErrScope
var ErrSession = core.ErrSession

func EncodeSession(s Session) *management.MediaRuleSession {
	return &management.MediaRuleSession{ProcessorId: s.ProcessorID, Generation: s.Generation}
}

func DecodeSession(s *management.MediaRuleSession) (Session, error) {
	if s == nil || s.ProcessorId == "" || s.Generation == 0 {
		return Session{}, ErrSession
	}
	return Session{ProcessorID: s.ProcessorId, Generation: s.Generation}, nil
}

func EncodeLegacyRule(r Rule) *management.MediaRule {
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
func DecodeLegacyRule(w *management.MediaRule) (Rule, error) {
	if w == nil || w.Call == nil {
		return Rule{}, ErrInvalid
	}
	session, err := DecodeSession(w.Session)
	if err != nil {
		return Rule{}, err
	}
	r := Rule{ID: w.Id, Session: session, Revision: Revision(w.Revision),
		Call: CallAssociation{Lifetime: callregistry.Lifetime{Session: w.Call.RegistrySession, Generation: w.Call.RegistryGeneration},
			CallID: w.Call.CallId, FromTag: w.Call.FromTag, ToTag: w.Call.ToTag,
			SelectionRevision: w.Call.SelectionRevision, CapturePolicyRevision: w.Call.CapturePolicyRevision, FilterIDs: append([]string(nil), w.Call.FilterIds...)},
		NotBefore: time.Unix(0, w.NotBeforeNs), ExpiresAt: time.Unix(0, w.ExpiresAtNs)}
	r.CaptureSignature = append([]byte(nil), w.CaptureSignature...)
	for _, ref := range w.Call.SelectionGrants {
		if ref == nil {
			return Rule{}, ErrInvalid
		}
		r.Call.SelectionGrants = append(r.Call.SelectionGrants, SelectionRef{ID: ref.Id, Revision: ref.Revision})
	}
	for _, scope := range w.Scopes {
		if scope == nil {
			return Rule{}, ErrScope
		}
		r.Scope = append(r.Scope, Scope{HunterID: scope.HunterId, Domain: mediaadmission.DomainID(scope.Domain)})
	}
	for _, endpoint := range w.Endpoints {
		if endpoint == nil || endpoint.Port == 0 || endpoint.Port > 65535 || endpoint.Kind < 0 || endpoint.Kind > management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_MUX {
			return Rule{}, ErrInvalid
		}
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return Rule{}, fmt.Errorf("media-rule address: %w", ErrInvalid)
		}
		key, err := mediaadmission.NewEndpoint(mediaadmission.DomainID(endpoint.Domain), address, uint16(endpoint.Port))
		if err != nil || key.Addr.String() != endpoint.Address {
			return Rule{}, fmt.Errorf("media-rule canonical endpoint: %w", ErrInvalid)
		}
		r.Endpoints = append(r.Endpoints, Endpoint{Key: key, Kind: MediaKind(endpoint.Kind)})
	}
	return r, nil
}
