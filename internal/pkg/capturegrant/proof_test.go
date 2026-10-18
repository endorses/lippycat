package capturegrant

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCaptureGrantIntersection(t *testing.T) {
	at := time.Now()
	start, end := at.Add(-time.Second).UnixNano(), at.Add(time.Second).UnixNano()
	policy := &management.PolicySnapshot{ProtocolVersion: 2, Revision: 3, ValidFromNs: start, ValidUntilNs: end, SourceIds: []string{"capture-a"}, SelectionGrants: []*management.CaptureSelectionGrant{{Id: "opaque", Revision: 4, ProcessorId: "processor", Purpose: management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_MEDIA, NotBeforeNs: start, ExpiresAtNs: end, Scopes: []*management.CaptureSelectionScope{{HunterId: "capture-a", Domain: 0}}}}}
	rule := &management.MediaRule{Session: &management.MediaRuleSession{ProcessorId: "processor", Generation: 1}, NotBeforeNs: start, ExpiresAtNs: end, Call: &management.MediaRuleCall{CallId: "call", RegistrySession: 1, RegistryGeneration: 2, SelectionRevision: 1, CapturePolicyRevision: 3, SelectionGrants: []*management.CaptureSelectionRef{{Id: "opaque", Revision: 4}}}, Scopes: []*management.MediaRuleScope{{HunterId: "capture-a", Domain: 0}}, Endpoints: []*management.MediaRuleEndpoint{{Address: "192.0.2.1", Port: 4000, Domain: 0, Kind: management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTP}}}
	packet := grantPacket(t, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42})
	require.NoError(t, ValidateRule(policy, rule, "capture-a", 0, packet, at), "known domain zero is a valid scoped realm")
	for _, test := range []struct {
		name   string
		change func(*management.PolicySnapshot, *management.MediaRule)
	}{
		{"legacy policy", func(p *management.PolicySnapshot, r *management.MediaRule) { p.ProtocolVersion = 1 }},
		{"policy revision", func(p *management.PolicySnapshot, r *management.MediaRule) { p.Revision++ }},
		{"grant revision", func(p *management.PolicySnapshot, r *management.MediaRule) { p.SelectionGrants[0].Revision++ }},
		{"grant removed", func(p *management.PolicySnapshot, r *management.MediaRule) { p.SelectionGrants = nil }},
		{"source excluded", func(p *management.PolicySnapshot, r *management.MediaRule) { p.SourceIds = nil }},
		{"grant purpose", func(p *management.PolicySnapshot, r *management.MediaRule) {
			p.SelectionGrants[0].Purpose = management.CaptureSelectionPurpose_CAPTURE_SELECTION_PURPOSE_UNSPECIFIED
		}},
		{"different issuer", func(p *management.PolicySnapshot, r *management.MediaRule) { r.Session.ProcessorId = "other" }},
		{"different domain", func(p *management.PolicySnapshot, r *management.MediaRule) { p.SelectionGrants[0].Scopes[0].Domain = 1 }},
		{"missing rule scope", func(p *management.PolicySnapshot, r *management.MediaRule) { r.Scopes = nil }},
		{"expired capture", func(p *management.PolicySnapshot, r *management.MediaRule) { r.ExpiresAtNs = at.UnixNano() }},
		{"future capture", func(p *management.PolicySnapshot, r *management.MediaRule) {
			r.NotBeforeNs = at.Add(time.Nanosecond).UnixNano()
		}},
		{"rule exceeds grant", func(p *management.PolicySnapshot, r *management.MediaRule) { r.ExpiresAtNs++ }},
		{"duplicate reference", func(p *management.PolicySnapshot, r *management.MediaRule) {
			r.Call.SelectionGrants = append(r.Call.SelectionGrants, proto.Clone(r.Call.SelectionGrants[0]).(*management.CaptureSelectionRef))
		}},
		{"ambiguous grant definition", func(p *management.PolicySnapshot, r *management.MediaRule) {
			p.SelectionGrants = append(p.SelectionGrants, proto.Clone(p.SelectionGrants[0]).(*management.CaptureSelectionGrant))
		}},
		{"missing incarnation", func(p *management.PolicySnapshot, r *management.MediaRule) { r.Call.RegistryGeneration = 0 }},
		{"unrelated endpoint", func(p *management.PolicySnapshot, r *management.MediaRule) { r.Endpoints[0].Port++ }},
		{"wrong media kind", func(p *management.PolicySnapshot, r *management.MediaRule) {
			r.Endpoints[0].Kind = management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTCP
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, r := proto.Clone(policy).(*management.PolicySnapshot), proto.Clone(rule).(*management.MediaRule)
			test.change(p, r)
			require.ErrorIs(t, ValidateRule(p, r, "capture-a", 0, packet, at), ErrAuthority)
		})
	}
	for _, payload := range [][]byte{[]byte("INVITE sip:bob@example.invalid SIP/2.0\r\n"), []byte("unrelated UDP"), {0x80, 0}, {0x40, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42}} {
		require.ErrorIs(t, ValidateRule(policy, rule, "capture-a", 0, grantPacket(t, payload), at), ErrAuthority)
	}
	rtcp := proto.Clone(rule).(*management.MediaRule)
	rtcp.Endpoints[0].Kind = management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTCP
	require.NoError(t, ValidateRule(policy, rtcp, "capture-a", 0, grantPacket(t, []byte{0x80, 200, 0, 1, 0, 0, 0, 42}), at))
	// Delivery can validate original facts after the lease's wall deadline;
	// live capture owners independently enforce their current installed lease.
	old := at.Add(-time.Hour)
	shift := old.Sub(at).Nanoseconds()
	policy.ValidFromNs += shift
	policy.ValidUntilNs += shift
	policy.SelectionGrants[0].NotBeforeNs += shift
	policy.SelectionGrants[0].ExpiresAtNs += shift
	rule.NotBeforeNs += shift
	rule.ExpiresAtNs += shift
	require.NoError(t, ValidateRule(policy, rule, "capture-a", 0, packet, old))
	require.ErrorIs(t, ValidateRule(policy, rule, "capture-a", 0, packet, at), ErrAuthority)
}

func grantPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 4000, DstPort: 5000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}
