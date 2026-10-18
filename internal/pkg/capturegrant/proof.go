// Package capturegrant validates processor-selected media against generic signed
// capture permissions. Signature verification belongs to the policy owner.
package capturegrant

import (
	"errors"
	"net/netip"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ErrAuthority = errors.New("capture selection is outside its signed grant or media rule")

// ValidateRule checks immutable capture facts. It deliberately uses capture time,
// not delivery time: the caller separately enforces live lease expiry or current
// task authorization when selecting that operation's acceptance boundary.
func ValidateRule(snapshot *management.PolicySnapshot, rule *management.MediaRule, source string, domain uint32, packet gopacket.Packet, capturedAt time.Time) error {
	if snapshot == nil || snapshot.ProtocolVersion != 2 || rule == nil || rule.Call == nil || rule.Session == nil || source == "" || packet == nil || capturedAt.IsZero() || rule.Call.CapturePolicyRevision != snapshot.Revision || len(rule.Call.SelectionGrants) == 0 || rule.Call.CallId == "" || rule.Call.RegistrySession == 0 || rule.Call.RegistryGeneration == 0 || rule.Call.SelectionRevision == 0 || rule.Session.ProcessorId == "" || rule.Session.Generation == 0 {
		return ErrAuthority
	}
	at := capturedAt.UnixNano()
	if at < snapshot.ValidFromNs || at >= snapshot.ValidUntilNs || at < rule.NotBeforeNs || at >= rule.ExpiresAtNs {
		return ErrAuthority
	}
	sourceAllowed := false
	for _, id := range snapshot.SourceIds {
		if id == source {
			sourceAllowed = true
			break
		}
	}
	if !sourceAllowed {
		return ErrAuthority
	}
	ruleScoped := false
	for _, scope := range rule.Scopes {
		if scope != nil && scope.HunterId == source && scope.Domain == domain {
			ruleScoped = true
			break
		}
	}
	if !ruleScoped {
		return ErrAuthority
	}
	grants := make(map[string]*management.CaptureSelectionGrant, len(snapshot.SelectionGrants))
	for _, grant := range snapshot.SelectionGrants {
		if grant == nil || grant.Id == "" || grants[grant.Id] != nil {
			return ErrAuthority
		}
		grants[grant.Id] = grant
	}
	seen := make(map[string]bool, len(rule.Call.SelectionGrants))
	for _, ref := range rule.Call.SelectionGrants {
		if ref == nil || seen[ref.Id] {
			return ErrAuthority
		}
		seen[ref.Id] = true
		grant := grants[ref.Id]
		if grant == nil || grant.Revision != ref.Revision || grant.Purpose != management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA || grant.ProcessorId != rule.Session.ProcessorId || at < grant.NotBeforeNs || at >= grant.ExpiresAtNs || rule.NotBeforeNs < grant.NotBeforeNs || rule.ExpiresAtNs > grant.ExpiresAtNs {
			return ErrAuthority
		}
		scoped := false
		for _, scope := range grant.Scopes {
			if scope != nil && scope.HunterId == source && scope.Domain == domain {
				scoped = true
				break
			}
		}
		if !scoped {
			return ErrAuthority
		}
	}
	if packet.NetworkLayer() == nil {
		return ErrAuthority
	}
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || len(udp.Payload) < 8 || udp.Payload[0]>>6 != 2 {
		return ErrAuthority
	}
	rtcp := udp.Payload[1] >= 192 && udp.Payload[1] <= 223
	if !rtcp && len(udp.Payload) < 12 {
		return ErrAuthority
	}
	src, e1 := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Src().String())
	dst, e2 := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Dst().String())
	if e1 != nil || e2 != nil {
		return ErrAuthority
	}
	matched := false
	for _, endpoint := range rule.Endpoints {
		if endpoint == nil || endpoint.Domain != domain {
			continue
		}
		addr, err := netip.ParseAddr(endpoint.Address)
		if err != nil {
			return ErrAuthority
		}
		if !(addr.Unmap() == src.Unmap() && endpoint.Port == uint32(udp.SrcPort)) && !(addr.Unmap() == dst.Unmap() && endpoint.Port == uint32(udp.DstPort)) {
			continue
		}
		if endpoint.Kind == management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_MUX || rtcp && endpoint.Kind == management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTCP || !rtcp && endpoint.Kind == management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTP {
			matched = true
		}
	}
	if !matched {
		return ErrAuthority
	}
	return nil
}
