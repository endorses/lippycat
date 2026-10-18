//go:build (processor || tap || all) && li && linux

package processor

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLICentralSelectionRequiresSignedExactMediaProof(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	f.config.LITaskFilterDistributionScope = "local_only"
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	config, signer := policyfixture.Config(t)
	config.Owner = "li"
	config.StorageProtection = "encrypted"
	config.StorageKeys = securestore.KeyConfig{Active: storageKeyRef(t, "selection-policy", 27)}
	require.NoError(t, filterpolicy.Initialize(config))
	state, err := filterpolicy.Open(config)
	require.NoError(t, err)
	p.sharedPolicy = &processorPolicy{processor: p, config: config, state: state, signer: signer, ready: make(chan struct{})}
	p.config.LIHandover = li.HandoverConfig{Enabled: true, LeaseDuration: time.Minute, ClockUncertainty: 100 * time.Millisecond, SourceIDs: []string{"edge-a"}}
	p.config.MediaRules.Sources = []MediaSourceMapping{{HunterID: "edge-a", Interface: "eth-test", HunterDomain: 0, Domain: 0}}
	now := time.Now().Add(-time.Second)
	require.NoError(t, p.publishLIHandoverPolicy(now))
	signed := state.Latest()
	require.NotNil(t, signed)
	snapshot := signed.Snapshot
	require.Empty(t, snapshot.Filters)
	require.Len(t, snapshot.SelectionGrants, 1)
	grant := snapshot.SelectionGrants[0]
	rule := &management.MediaRule{Id: "selected-call", Session: &management.MediaRuleSession{ProcessorId: p.config.ProcessorID, Generation: 1}, Revision: 1, Call: &management.MediaRuleCall{RegistrySession: 1, RegistryGeneration: 1, CallId: "private-call", SelectionRevision: 1, CapturePolicyRevision: snapshot.Revision, SelectionGrants: []*management.CaptureSelectionRef{{Id: grant.Id, Revision: grant.Revision}}}, Scopes: []*management.MediaRuleScope{{HunterId: "edge-a", Domain: 0}}, Endpoints: []*management.MediaRuleEndpoint{{Domain: 0, Address: "192.0.2.1", Port: 18000, Kind: management.MediaRuleEndpointKind_MEDIA_RULE_ENDPOINT_RTP}}, NotBeforeNs: grant.NotBeforeNs, ExpiresAtNs: grant.ExpiresAtNs}
	rule, err = state.Verifier().SignMediaRule(signer, rule)
	require.NoError(t, err)
	proof, err := proto.Marshal(rule)
	require.NoError(t, err)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 18000, DstPort: 19000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	raw := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(raw, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload([]byte{0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1})))
	encoded, err := proto.Marshal(signed)
	require.NoError(t, err)
	packet := &data.CapturedPacket{Data: raw.Bytes(), LinkType: uint32(layers.LinkTypeRaw), TimestampNs: time.Now().UnixNano(), ObservationDomainKnown: true, InheritedMatchedFilterIds: []string{grant.Id}, CaptureSelectionProof: proof}
	batch := &data.PacketBatch{HunterId: "edge-a", SignedCapturePolicy: encoded, Packets: []*data.CapturedPacket{packet}}
	require.NoError(t, p.validateLICapturePolicy(batch))
	for _, tc := range []struct {
		name   string
		change func(*data.PacketBatch)
	}{
		{"bare-reference", func(b *data.PacketBatch) { b.Packets[0].CaptureSelectionProof = nil }},
		{"direct-reference", func(b *data.PacketBatch) { b.Packets[0].DirectMatchedFilterIds = []string{grant.Id} }},
		{"wrong-domain", func(b *data.PacketBatch) { b.Packets[0].ObservationDomain = 1 }},
		{"unknown-domain", func(b *data.PacketBatch) { b.Packets[0].ObservationDomainKnown = false }},
		{"wrong-source", func(b *data.PacketBatch) { b.HunterId = "edge-b" }},
		{"unsigned-rule", func(b *data.PacketBatch) {
			r := proto.Clone(rule).(*management.MediaRule)
			r.CaptureSignature = nil
			encodedRule, err := proto.Marshal(r)
			require.NoError(t, err)
			b.Packets[0].CaptureSelectionProof = encodedRule
		}},
		{"changed-call", func(b *data.PacketBatch) {
			r := proto.Clone(rule).(*management.MediaRule)
			r.Call.RegistryGeneration++
			encodedRule, err := proto.Marshal(r)
			require.NoError(t, err)
			b.Packets[0].CaptureSelectionProof = encodedRule
		}},
		{"unclaimed-signalling", func(b *data.PacketBatch) {
			b.Packets[0].InheritedMatchedFilterIds = nil
			b.Packets[0].CaptureSelectionProof = nil
			b.Packets[0].Data = []byte("INVITE sip:private@example.test SIP/2.0\r\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := proto.Clone(batch).(*data.PacketBatch)
			tc.change(bad)
			require.ErrorIs(t, p.validateLICapturePolicy(bad), li.ErrCaptureAuthority)
		})
	}
	// Trusted local observation selects SIP independently of the media-only
	// hunter grant. The same no-policy packet through the remote path is denied.
	task, err := p.liManager.GetTaskDetails(f.xid)
	require.NoError(t, err)
	sipPayload := []byte(fmt.Sprintf("INVITE %s SIP/2.0\r\nFrom: <sip:caller@example.test>;tag=from\r\nTo: <%s>\r\nCall-ID: local-selection-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", task.Targets[0].Value, task.Targets[0].Value))
	local := &types.PacketDisplay{NodeID: "edge-a", Interface: "eth-test", ObservationDomainKnown: true, ObservationDomain: 0, Timestamp: time.Now(), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "5060", DstPort: "5060", Protocol: "SIP", VoIPData: &types.VoIPMetadata{CallID: "local-selection-call", RawSIP: sipPayload}}
	count := 0
	p.liManager.SetPacketBatchProcessor(nil)
	p.liManager.SetPacketProcessor(func(*li.InterceptTask, *types.PacketDisplay) { count++ })
	p.processLocalLIPacketWithAdmissionAndDedup(local, []string{"forged"}, nil, nil, nil)
	require.Equal(t, 1, count)
	p.processLIPacketWithAdmissionAndDedup(local, []string{grant.Id}, nil, nil, nil)
	require.Equal(t, 1, count, "remote unsigned IDs do not inherit local observation permission")
	local.ObservationDomain = 1
	p.processLocalLIPacketWithAdmissionAndDedup(local, nil, nil, nil, nil)
	require.Equal(t, 1, count)
	targets := []li.TargetIdentity{{Type: li.TargetTypeSIPURI, Value: "sip:replacement@example.test"}}
	require.NoError(t, p.liManager.ModifyTask(f.xid, &li.TaskModification{Targets: &targets}))
	require.ErrorIs(t, p.validateLICapturePolicy(batch), li.ErrCaptureAuthority, "signed original rule cannot rebind to modified task")
}
