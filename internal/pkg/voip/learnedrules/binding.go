package learnedrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"google.golang.org/protobuf/proto"
)

var qualifiers = []core.Qualifier{{ID: "voip.rtp", Version: 1}, {ID: "voip.rtcp", Version: 1}, {ID: "voip.media", Version: 1}}

// ToBinding translates the complete immutable VoIP relationship. A protected
// binding retains the exact deterministic legacy signed artifact; its signature
// is never reinterpreted as a generic selector authorization.
func ToBinding(rule Rule) core.Binding {
	context, err := json.Marshal(rule.Call)
	if err != nil {
		return core.Binding{}
	} // The concrete context contains only JSON-safe fields.
	binding := core.Binding{ID: rule.ID, Session: rule.Session, Revision: rule.Revision,
		AdapterID: AdapterID, ContextVersion: ContextVersion,
		Subject:            core.Subject{ID: rule.Call.CallID, Incarnation: fmt.Sprintf("%d:%d", rule.Call.Lifetime.Session, rule.Call.Lifetime.Generation)},
		AttributionContext: AttributionContext, Context: context, NotBefore: rule.NotBefore, ExpiresAt: rule.ExpiresAt}
	for _, scope := range rule.Scope {
		binding.Scope = append(binding.Scope, core.Scope{HunterID: scope.HunterID, Domain: core.DomainID(scope.Domain)})
	}
	for _, endpoint := range rule.Endpoints {
		q := core.Qualifier{ID: "voip.invalid", Version: 1}
		if endpoint.Kind <= RTPAndRTCP {
			q = qualifiers[endpoint.Kind]
		}
		binding.Selectors = append(binding.Selectors, core.Selector{Domain: core.DomainID(endpoint.Key.Domain), Address: endpoint.Key.Addr, Port: endpoint.Key.Port, Protocol: core.UDP, Direction: core.Either, Qualifier: q})
	}
	if len(rule.Call.SelectionGrants) > 0 {
		for _, ref := range rule.Call.SelectionGrants {
			binding.Intents = append(binding.Intents, core.IntentRef{ID: ref.ID, Revision: ref.Revision})
		}
	} else {
		for _, id := range rule.Call.FilterIDs {
			binding.Intents = append(binding.Intents, core.IntentRef{ID: id, Revision: rule.Call.SelectionRevision})
		}
	}
	if len(rule.CaptureSignature) > 0 {
		binding.Proof, err = (proto.MarshalOptions{Deterministic: true}).Marshal(EncodeLegacyRule(rule))
		if err != nil {
			return core.Binding{}
		}
	}
	return binding
}

// FromBinding rejects noncanonical or broadened VoIP definitions, including any
// semantic difference from their retained protected artifact. Cryptographic
// authenticity and current task eligibility are separate publication/ingress
// checks owned by the configured authority.
func FromBinding(binding core.Binding) (Rule, error) {
	if binding.AdapterID != AdapterID || binding.ContextVersion != ContextVersion || binding.AttributionContext != AttributionContext || len(binding.EvidenceRefs) != 0 {
		return Rule{}, core.ErrInvalid
	}
	var call CallAssociation
	decoder := json.NewDecoder(bytes.NewReader(binding.Context))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&call); err != nil {
		return Rule{}, fmt.Errorf("VoIP context: %w", core.ErrInvalid)
	}
	canonical, err := json.Marshal(call)
	if err != nil {
		return Rule{}, core.ErrInvalid
	}
	if !bytes.Equal(canonical, binding.Context) {
		return Rule{}, core.ErrInvalid
	}
	rule := Rule{ID: binding.ID, Session: binding.Session, Revision: binding.Revision, Call: call, NotBefore: binding.NotBefore, ExpiresAt: binding.ExpiresAt}
	for _, scope := range binding.Scope {
		rule.Scope = append(rule.Scope, Scope{HunterID: scope.HunterID, Domain: mediaadmission.DomainID(scope.Domain)})
	}
	for _, selector := range binding.Selectors {
		if selector.Protocol != core.UDP || selector.Direction != core.Either {
			return Rule{}, core.ErrInvalid
		}
		kind := MediaKind(255)
		for i, q := range qualifiers {
			if selector.Qualifier == q {
				kind = MediaKind(i)
			}
		}
		if kind > RTPAndRTCP {
			return Rule{}, core.ErrInvalid
		}
		rule.Endpoints = append(rule.Endpoints, Endpoint{Key: mediaadmission.EndpointKey{Domain: mediaadmission.DomainID(selector.Domain), Addr: selector.Address, Port: selector.Port}, Kind: kind})
	}
	if len(binding.Proof) > 0 {
		encoded := EncodeLegacyRule(Rule{})
		if err := proto.Unmarshal(binding.Proof, encoded); err != nil {
			return Rule{}, core.ErrInvalid
		}
		original, err := DecodeLegacyRule(encoded)
		if err != nil {
			return Rule{}, err
		}
		rule.CaptureSignature = append([]byte(nil), original.CaptureSignature...)
		if !EqualRule(rule, original) {
			return Rule{}, core.ErrInvalid
		}
		// The original byte string is immutable evidence. Unknown protobuf fields
		// and alternate encodings cannot be silently dropped by canonical conversion.
		canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(EncodeLegacyRule(original))
		if err != nil || !bytes.Equal(canonical, binding.Proof) {
			return Rule{}, core.ErrInvalid
		}
	}
	expected := ToBinding(rule)
	if binding.Subject != expected.Subject || !slices.Equal(binding.Intents, expected.Intents) || !bytes.Equal(binding.Proof, expected.Proof) {
		return Rule{}, core.ErrInvalid
	}
	return rule, nil
}

// Adapter registers VoIP context and qualifier semantics. Optional maxReferences
// retains legacy per-rule limits for context fields not expanded into selectors.
func Adapter(maxReferences ...int) core.Adapter {
	maxRefs := 100000
	if len(maxReferences) > 0 {
		maxRefs = maxReferences[0]
	}
	return core.Adapter{ID: AdapterID, Version: ContextVersion, Qualifiers: append([]core.Qualifier(nil), qualifiers...),
		Validate: func(binding core.Binding) error {
			rule, err := FromBinding(binding)
			if err != nil {
				return err
			}
			if rule.Call.CallID == "" || rule.Call.Lifetime.Session == 0 || rule.Call.Lifetime.Generation == 0 || rule.Call.SelectionRevision == 0 {
				return core.ErrInvalid
			}
			if len(rule.Call.FilterIDs) > maxRefs || len(rule.Call.SelectionGrants) > maxRefs {
				return core.ErrCapacity
			}
			if len(rule.Call.SelectionGrants) > 0 {
				if len(rule.CaptureSignature) == 0 || len(rule.CaptureSignature) > 16384 || rule.Call.CapturePolicyRevision == 0 {
					return core.ErrInvalid
				}
				previous := ""
				for _, ref := range rule.Call.SelectionGrants {
					if ref.ID == "" || len(ref.ID) > 1024 || ref.ID <= previous || ref.Revision == 0 {
						return core.ErrInvalid
					}
					previous = ref.ID
				}
			} else if len(rule.CaptureSignature) > 0 {
				return core.ErrInvalid
			}
			seen := make(map[mediaadmission.EndpointKey]bool, len(rule.Endpoints))
			for _, endpoint := range rule.Endpoints {
				if endpoint.Key.Validate() != nil || endpoint.Kind > RTPAndRTCP || seen[endpoint.Key] {
					return core.ErrInvalid
				}
				seen[endpoint.Key] = true
			}
			return nil
		},
		Authorize: func(binding core.Binding) error { _, err := FromBinding(binding); return err },
		ValidateTransition: func(before, after core.Binding) error {
			old, err := FromBinding(before)
			if err != nil {
				return err
			}
			next, err := FromBinding(after)
			if err != nil {
				return err
			}
			if next.Call.SelectionRevision < old.Call.SelectionRevision {
				return core.ErrRevision
			}
			return nil
		},
		Qualify: func(_ core.Binding, selector core.Selector, packet core.Packet) bool {
			return Qualify(selector.Qualifier, packet)
		},
	}
}

// Qualify preserves the existing media-header candidate checks. Qualification
// does not establish call identity or grant output permission.
func Qualify(qualifier core.Qualifier, packet core.Packet) bool {
	payload := packet.Payload
	if packet.Protocol != core.UDP || len(payload) < 8 || payload[0]>>6 != 2 {
		return false
	}
	rtcp := payload[1] >= 192 && payload[1] <= 223
	if !rtcp && len(payload) < 12 {
		return false
	}
	if qualifier.Version != 1 {
		return false
	}
	return qualifier.ID == "voip.media" || rtcp && qualifier.ID == "voip.rtcp" || !rtcp && qualifier.ID == "voip.rtp"
}

func CloneRule(rule Rule) Rule {
	rule.CaptureSignature = append([]byte(nil), rule.CaptureSignature...)
	rule.Call.SelectionGrants = append([]SelectionRef(nil), rule.Call.SelectionGrants...)
	rule.Call.FilterIDs = append([]string(nil), rule.Call.FilterIDs...)
	rule.Scope = append([]Scope(nil), rule.Scope...)
	rule.Endpoints = append([]Endpoint(nil), rule.Endpoints...)
	return rule
}

func EqualRule(a, b Rule) bool {
	return a.ID == b.ID && a.Session == b.Session && a.Revision == b.Revision && a.Call.Lifetime == b.Call.Lifetime && a.Call.CallID == b.Call.CallID && a.Call.FromTag == b.Call.FromTag && a.Call.ToTag == b.Call.ToTag && a.Call.SelectionRevision == b.Call.SelectionRevision && a.Call.CapturePolicyRevision == b.Call.CapturePolicyRevision && slices.Equal(a.Call.FilterIDs, b.Call.FilterIDs) && slices.Equal(a.Call.SelectionGrants, b.Call.SelectionGrants) && slices.Equal(a.Scope, b.Scope) && slices.Equal(a.Endpoints, b.Endpoints) && slices.Equal(a.CaptureSignature, b.CaptureSignature) && a.NotBefore.Equal(b.NotBefore) && a.ExpiresAt.Equal(b.ExpiresAt)
}
