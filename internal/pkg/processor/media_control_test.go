//go:build processor || tap || all

package processor

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func mediaControlFixture(t *testing.T) *Processor {
	t.Helper()
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", ProcessorID: "processor.example.invalid", MediaRules: MediaRulesConfig{
		Settings: mediarules.Settings{Enabled: true},
		Sources:  []MediaSourceMapping{{HunterID: "hunter-a", Interface: "capture0", Domain: 7, HunterDomain: 1}, {HunterID: "hunter-b", Interface: "capture0", Domain: 7, HunterDomain: 2}, {HunterID: "hunter-c", Interface: "capture0", Domain: 7, HunterDomain: 2}, {HunterID: "isolated", Interface: "capture0", Domain: 8, HunterDomain: 2}},
	}})
	require.NoError(t, err)
	_, err = p.updateManagedFilter(&management.Filter{Id: "local-alice", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	return p
}

func centralMessage(start, toTag, branch string, cseq int, method, body string) []byte {
	to := "<sip:bob@example.invalid>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=%s\r\nFrom: <sip:alice@example.invalid>;tag=alice-tag\r\nTo: %s\r\nCall-ID: continuity@example.invalid\r\nCSeq: %d %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", start, branch, to, cseq, method, len(body), body))
}

func centralEnvelope(t *testing.T, node string, payload []byte, media bool) *pipeline.PacketEnvelope {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	if media {
		udp.SrcPort = 40000
		udp.DstPort = 50000
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, gopacket.Payload(payload)))
	return &pipeline.PacketEnvelope{Data: buffer.Bytes(), LinkType: layers.LinkTypeRaw, CaptureTime: time.Now(), CaptureLength: len(buffer.Bytes()), OriginalLength: len(buffer.Bytes()), Source: pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: node, InterfaceName: "capture0"}}
}

func centralObserve(p *Processor, envelope *pipeline.PacketEnvelope, trusted bool) {
	p.processBatch(&source.PacketBatch{SourceID: envelope.Source.NodeID, MediaSourceTrusted: trusted, Envelopes: []*pipeline.PacketEnvelope{envelope}, TimestampNs: time.Now().UnixNano()})
}

func TestMediaControlPublishesAcrossHuntersWithoutOutput(t *testing.T) {
	p := mediaControlFixture(t)
	require.True(t, p.needsPacketProcessing())
	require.False(t, p.needsPacketOutput())
	require.Empty(t, p.filterManager.GetForHunter("hunter-a"), "local-only filter stays central")
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-first", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	centralObserve(p, centralEnvelope(t, "hunter-a", invite, false), true)
	first := p.mediaControl.store.Snapshot()
	require.NotEmpty(t, first.Rules)
	lifetime := first.Rules[0].Call.Lifetime
	require.Equal(t, []string{"local-alice"}, first.Rules[0].Call.FilterIDs)
	require.Contains(t, first.Rules[0].Scope, mediarules.Scope{HunterID: "hunter-c", Domain: 2})
	require.NotContains(t, first.Rules[0].Scope, mediarules.Scope{HunterID: "isolated", Domain: 2})
	answer := centralMessage("SIP/2.0 200 OK", "bob-tag", "z9hG4bK-first", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.2\r\nm=audio 50000 RTP/AVP 0\r\n")
	centralObserve(p, centralEnvelope(t, "hunter-b", answer, false), true)
	for _, node := range []string{"hunter-b", "hunter-c"} {
		envelope := centralEnvelope(t, node, []byte{0x80, 0, 0, 10, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 2, 3}, true)
		captured := envelope.CaptureTime
		centralObserve(p, envelope, true)
		require.Equal(t, []string{"local-alice"}, envelope.InheritedMatchedFilterIDs)
		require.Equal(t, node, envelope.Source.NodeID)
		require.Equal(t, captured, envelope.CaptureTime)
		require.Equal(t, pipeline.SourceGRPC, envelope.Source.Kind)
		metadata := &data.PacketMetadata{}
		require.NoError(t, proto.Unmarshal(envelope.Metadata.Payload, metadata))
		require.Equal(t, "continuity@example.invalid", metadata.Sip.CallId)
	}
	require.Len(t, p.mediaControl.tracker.Snapshot(), 1)
	require.Equal(t, lifetime, p.mediaControl.tracker.Snapshot()[0].Info.Lifetime)
	bye := centralMessage("BYE sip:bob@example.invalid SIP/2.0", "wrong-tag", "z9hG4bK-bye", 2, "BYE", "")
	forged := centralEnvelope(t, "hunter-c", bye, false)
	centralObserve(p, forged, true)
	require.True(t, forged.CallLifecycleRejected, "a rejected dialog must not mutate legacy output lifecycle consumers")
	require.False(t, p.mediaControl.tracker.Snapshot()[0].Completing)
	bye = centralMessage("BYE sip:bob@example.invalid SIP/2.0", "bob-tag", "z9hG4bK-bye", 2, "BYE", "")
	centralObserve(p, centralEnvelope(t, "hunter-c", bye, false), true)
	require.True(t, p.mediaControl.tracker.Snapshot()[0].Completing)
	require.WithinDuration(t, time.Now().Add(p.config.MediaRules.TrailingGrace), p.mediaControl.store.Snapshot().Rules[0].ExpiresAt, time.Second)
	_, err := p.deleteManagedFilter("local-alice")
	require.NoError(t, err)
	require.Empty(t, p.mediaControl.store.Snapshot().Rules, "current policy removal retires selected rules immediately")
}

func TestMediaControlRejectsUntrustedUnknownAndHistoricalSelection(t *testing.T) {
	p := mediaControlFixture(t)
	invite := centralMessage("INVITE sip:bob@example.invalid SIP/2.0", "", "z9hG4bK-first", 1, "INVITE", "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 40000 RTP/AVP 0\r\n")
	centralObserve(p, centralEnvelope(t, "hunter-a", invite, false), false)
	centralObserve(p, centralEnvelope(t, "unknown", invite, false), true)
	wrongDomain := centralEnvelope(t, "hunter-a", invite, false)
	wrongDomain.Source.ObservationDomainKnown = true
	wrongDomain.Source.ObservationDomain = 2
	centralObserve(p, wrongDomain, true)
	old := centralEnvelope(t, "hunter-a", invite, false)
	old.CaptureTime = time.Now().Add(-2 * p.config.MediaRules.RuleTTL)
	centralObserve(p, old, true)
	replay := centralEnvelope(t, "hunter-a", invite, false)
	p.processBatch(&source.PacketBatch{SourceID: "hunter-a", MediaSourceTrusted: true, HistoricalReplay: true, Envelopes: []*pipeline.PacketEnvelope{replay}})
	require.Empty(t, p.mediaControl.store.Snapshot().Rules)
	require.Empty(t, p.mediaControl.tracker.Snapshot())
}

func TestMediaControlRetainsDirectIPButRejectsUnprovenIdentityForRTP(t *testing.T) {
	p := mediaControlFixture(t)
	_, err := p.updateManagedFilter(&management.Filter{Id: "direct-address", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.1", Enabled: true})
	require.NoError(t, err)
	envelope := centralEnvelope(t, "hunter-a", []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2}, true)
	envelope.MatchedFilterIDs = []string{"local-alice"}
	envelope.InheritedMatchedFilterIDs = []string{"local-alice"}
	centralObserve(p, envelope, true)
	require.Equal(t, []string{"direct-address"}, envelope.DirectMatchedFilterIDs)
	require.Equal(t, []string{"direct-address"}, envelope.MatchedFilterIDs)
	require.Empty(t, envelope.InheritedMatchedFilterIDs)
	require.Empty(t, p.mediaControl.tracker.Snapshot(), "a packet IP match alone does not invent a SIP call")
}
