//go:build (processor || tap || all) && li

package processor

import (
	"net"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capturegrant"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
)

// validateLICaptureSelectionProof authenticates the original exact media rule,
// including its call incarnation, endpoints, issuer, source and capture interval.
// Opaque IDs alone never authorize packets on the local-selection path.
func (p *Processor) validateLICaptureSelectionProof(snapshot *management.PolicySnapshot, packet *data.CapturedPacket, hunterID string) ([]string, error) {
	if packet == nil || snapshot == nil || p.liManager == nil {
		return nil, li.ErrCaptureAuthority
	}
	authority, err := li.DecodeHandoverAuthority(snapshot.CaptureAuthority)
	if err != nil {
		return nil, err
	}
	local := make(map[string]bool)
	for _, g := range authority.Grants {
		if g.LocalOnly {
			local[g.FilterID] = true
		}
	}
	for _, id := range packet.DirectMatchedFilterIds {
		if local[id] {
			return nil, li.ErrCaptureAuthority
		}
	}
	if len(packet.CaptureSelectionProof) == 0 {
		for _, id := range capturePacketFilterIDs(packet) {
			if local[id] {
				return nil, li.ErrCaptureAuthority
			}
		}
		return nil, nil
	}
	if len(packet.CaptureSelectionProof) > filterpolicy.MaxSnapshotBytes || !packet.ObservationDomainKnown || p.sharedPolicy == nil {
		return nil, li.ErrCaptureAuthority
	}
	rule := &management.MediaRule{}
	if err := proto.Unmarshal(packet.CaptureSelectionProof, rule); err != nil {
		return nil, li.ErrCaptureAuthority
	}
	if err := p.sharedPolicy.state.Verifier().VerifyMediaRule(rule); err != nil {
		return nil, li.ErrCaptureAuthority
	}
	capturedAt := time.Unix(0, packet.TimestampNs)
	decoded := gopacket.NewPacket(packet.Data, layers.LinkType(packet.LinkType), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if err := capturegrant.ValidateRule(snapshot, rule, hunterID, packet.ObservationDomain, decoded, capturedAt); err != nil {
		return nil, li.ErrCaptureAuthority
	}
	ids, err := p.liManager.ValidateCaptureSelectionAuthority(snapshot.CaptureAuthority, snapshot.Filters, snapshot.SelectionGrants, rule.GetCall().GetSelectionGrants(), hunterID, packet.ObservationDomain, capturedAt, time.Now(), p.config.LIHandover)
	if err != nil {
		return nil, err
	}
	proven := make(map[string]bool, len(ids))
	for _, id := range ids {
		proven[id] = true
	}
	for _, id := range capturePacketFilterIDs(packet) {
		if local[id] && !proven[id] {
			return nil, li.ErrCaptureAuthority
		}
	}
	return ids, nil
}

// liSelectionCaptureAuthority repeats raw proof checks at delivery while allowing
// old capture leases to expire. Current task revocation/generation remains live.
func (p *Processor) liSelectionCaptureAuthority(packet *types.PacketDisplay, direct, inherited []string, encoded, proof []byte) (*li.HandoverAuthority, error) {
	if packet == nil {
		return nil, li.ErrCaptureAuthority
	}
	if len(proof) == 0 {
		return p.liPacketCaptureAuthority(packet, direct, inherited, encoded)
	}
	snapshot, err := p.verifiedLICaptureSnapshot(encoded)
	if err != nil {
		return nil, err
	}
	raw := &data.CapturedPacket{Data: packet.RawData, LinkType: uint32(packet.LinkType), TimestampNs: packet.Timestamp.UnixNano(), ObservationDomain: packet.ObservationDomain, ObservationDomainKnown: packet.ObservationDomainKnown, DirectMatchedFilterIds: direct, InheritedMatchedFilterIds: inherited, CaptureSelectionProof: proof}
	ids, err := p.validateLICaptureSelectionProof(snapshot, raw, packet.NodeID)
	if err != nil {
		return nil, err
	}
	all := append(append(append([]string(nil), direct...), inherited...), ids...)
	if err := p.liManager.ValidateHandoverAuthority(snapshot.CaptureAuthority, snapshot.Filters, all, packet.NodeID, packet.Timestamp, time.Now(), p.config.LIHandover); err != nil {
		return nil, err
	}
	return li.DecodeHandoverAuthority(snapshot.CaptureAuthority)
}

// processLocalLIPacketWithAdmissionAndDedup is called only after the internal
// pipeline established SourceLiveCapture and MediaSourceTrusted. Hunter-supplied
// source fields never select this adapter. Local observation is independent of
// the media-only authority exported to hunters.
func (p *Processor) processLocalLIPacketWithAdmissionAndDedup(packet *types.PacketDisplay, direct, inherited []string, admission *CallAdmission, observation *packetdedup.Observation) {
	p.processLIPacketWithCaptureOrigin(packet, nil, nil, admission, observation, true)
}

func (p *Processor) localSIPSelection(packet *types.PacketDisplay) ([]string, *li.HandoverAuthority, bool) {
	if packet == nil || packet.VoIPData == nil || packet.VoIPData.IsRTP || p.filterManager == nil || p.liManager == nil || !packet.ObservationDomainKnown {
		return nil, nil, false
	}
	mapping, ok := p.mediaMapping(packet.NodeID, packet.Interface)
	if !ok || mapping.HunterDomain != mediaadmission.DomainID(packet.ObservationDomain) {
		return nil, nil, false
	}
	payload := packet.VoIPData.RawSIP
	if len(payload) == 0 {
		decoded := gopacket.NewPacket(packet.RawData, packet.LinkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		switch transport := decoded.TransportLayer().(type) {
		case *layers.UDP:
			payload = transport.Payload
		case *layers.TCP:
			payload = transport.Payload
		default:
			return nil, nil, false
		}
	}
	event, err := sip.Parse(payload, sip.OptionsForEndpoints(packet.Timestamp, net.JoinHostPort(packet.SrcIP, packet.SrcPort), net.JoinHostPort(packet.DstIP, packet.DstPort)))
	if err != nil || event.CallID == "" || event.CallID != packet.VoIPData.CallID {
		return nil, nil, false
	}
	ids, authority, err := p.liManager.SelectLocalSIP(event, packet.NodeID)
	if err != nil || len(ids) == 0 {
		return nil, nil, false
	}
	return ids, authority, true
}
