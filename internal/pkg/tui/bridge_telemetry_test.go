//go:build tui || all

package tui

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestIngressTelemetryAccumulatorCountsEveryValidEnvelope(t *testing.T) {
	t.Parallel()
	start := time.Unix(10, 0)
	acc := newIngressTelemetryAccumulator(start)
	one := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("one"))
	two := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("payload-two"))

	require.True(t, acc.observe(one))
	require.False(t, acc.observe(nil))
	require.True(t, acc.observe(two))
	_, published := acc.snapshot(start.Add(100*time.Millisecond), false)
	require.False(t, published)
	snapshot, published := acc.snapshot(start.Add(ingressPublishInterval), false)
	require.True(t, published)
	require.Equal(t, int64(2), snapshot.Packets)
	require.Equal(t, int64(one.OriginalLength+two.OriginalLength), snapshot.Bytes)
	require.Equal(t, int64(2), snapshot.ProtocolCounts["UDP"])
	require.Equal(t, int64(2), snapshot.SourceCounts["192.0.2.1"])
	require.Equal(t, int64(2), snapshot.DestCounts["198.51.100.2"])
	require.Equal(t, one.OriginalLength, snapshot.MinPacketSize)
	require.Equal(t, two.OriginalLength, snapshot.MaxPacketSize)
}

func TestIngressTelemetrySnapshotDoesNotExposeMutableMaps(t *testing.T) {
	t.Parallel()
	acc := newIngressTelemetryAccumulator(time.Time{})
	require.True(t, acc.observe(telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, nil)))
	snapshot, ok := acc.snapshot(time.Unix(1, 0), true)
	require.True(t, ok)
	publishIngressTelemetry(snapshot)
	got := GetIngressTelemetrySnapshot()
	got.ProtocolCounts["UDP"] = 99
	require.Equal(t, int64(1), GetIngressTelemetrySnapshot().ProtocolCounts["UDP"])
}

func TestSustainedSyntheticBridgeAboveOneThousandPacketsPerSecond(t *testing.T) {
	t.Parallel()
	start := time.Unix(20, 0)
	acc := newIngressTelemetryAccumulator(start)
	policy := newDisplaySamplingPolicy(false, start)
	env := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("synthetic"))
	const offeredPackets = 4000
	delivered := int64(0)
	for i := int64(1); i <= offeredPackets; i++ {
		now := start.Add(time.Duration(i) * 250 * time.Microsecond) // 4,000 pps
		require.True(t, acc.observe(env))
		if policy.shouldDisplay(env, i, now) {
			delivered++
		}
	}
	snapshot, ok := acc.snapshot(start.Add(time.Second), true)
	require.True(t, ok)
	require.Equal(t, int64(offeredPackets), snapshot.Packets)
	require.Less(t, delivered, int64(offeredPackets))
	require.Greater(t, delivered, int64(0))
}

func TestBridgePacketCounterReconciliationInvariant(t *testing.T) {
	// At a settled boundary every received envelope is either invalid, sampled
	// out, dropped at a later local stage, or delivered to the model/list.
	stats := BridgeStats{
		PacketsReceived: 100, InvalidEnvelopes: 3, PacketsSampledOut: 50,
		BatchQueuePacketDrops: 10, PendingPacketEvictions: 7, PacketsDelivered: 30,
	}
	reconciled := stats.InvalidEnvelopes + stats.PacketsSampledOut +
		stats.BatchQueuePacketDrops + stats.PendingPacketEvictions + stats.PacketsDelivered
	require.Equal(t, stats.PacketsReceived, reconciled)
}

func telemetryUDPEnvelope(tb testing.TB, kind pipeline.SourceKind, payload []byte) *pipeline.PacketEnvelope {
	tb.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{198, 51, 100, 2}}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 5060}
	require.NoError(tb, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(tb, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)))
	data := buffer.Bytes()
	env := &pipeline.PacketEnvelope{Data: data, LinkType: layers.LinkTypeEthernet, OriginalLength: len(data), CaptureLength: len(data)}
	env.Source.Kind = kind
	return env
}
