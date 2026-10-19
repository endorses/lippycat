package learnedrules

import (
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// ResolvePacket uses the common branch-qualified matcher, then applies VoIP's
// ownership intersection independently. Unqualified owners are still considered
// for ambiguity; an RTP/RTCP heuristic cannot silently select a different call.
func ResolvePacket(store *core.Store, packet core.Packet, maxCandidates int) Resolution {
	return resolvePacket(store, "", packet, maxCandidates)
}

// ResolvePacketForSource considers every authoritative owner eligible for the
// captured source/domain, including owners absent from supplied packet evidence.
// Other sources' independent local domain numberings do not create ambiguity.
func ResolvePacketForSource(store *core.Store, sourceID string, packet core.Packet, maxCandidates int) Resolution {
	if sourceID == "" {
		return Resolution{}
	}
	return resolvePacket(store, sourceID, packet, maxCandidates)
}

func resolvePacket(store *core.Store, sourceID string, packet core.Packet, maxCandidates int) Resolution {
	eligible := func(b core.Binding) bool {
		return store.InScope(b, packet.Domain) && (sourceID == "" || store.InScopeForSource(b, sourceID, packet.Domain))
	}
	var candidates core.Candidates
	if sourceID == "" {
		candidates = store.Match(packet, maxCandidates)
	} else {
		candidates = store.MatchForSource(sourceID, packet, maxCandidates)
	}
	if candidates.Overflow || len(candidates.Bindings) == 0 || packet.Protocol != core.UDP {
		return Resolution{}
	}
	var rules []Rule
	for _, b := range store.ActiveRules() {
		if b.AdapterID != AdapterID || b.ContextVersion != ContextVersion || !eligible(b) {
			continue
		}
		rule, err := FromBinding(b)
		if err != nil {
			return Resolution{}
		}
		rules = append(rules, rule)
	}
	left := mediaadmission.EndpointKey{Domain: mediaadmission.DomainID(packet.Domain), Addr: packet.Source.Address, Port: packet.Source.Port}
	right := mediaadmission.EndpointKey{Domain: mediaadmission.DomainID(packet.Domain), Addr: packet.Destination.Address, Port: packet.Destination.Port}
	resolved := Resolve(rules, left, right)
	if !resolved.Resolved || resolved.Rule == nil {
		return resolved
	}
	for _, b := range candidates.Bindings {
		if b.AdapterID != AdapterID || b.ContextVersion != ContextVersion || !eligible(b) {
			continue
		}
		rule, err := FromBinding(b)
		if err != nil {
			return Resolution{}
		}
		if rule.Call.CallID != resolved.Call.CallID || rule.Call.Lifetime != resolved.Call.Lifetime {
			continue
		}
		if len(resolved.Call.SelectionGrants) > 0 && rule.ID != resolved.Rule.ID {
			continue
		}
		return Resolution{Resolved: true, Rule: &rule, Call: rule.Call}
	}
	return Resolution{}
}
