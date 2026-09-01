//go:build tui || all

package tui

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
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
	ResetBridgeStats()
	ClearPendingPackets()
	t.Cleanup(ClearPendingPackets)
	SetVoIPModeEnabled(false)

	start := time.Unix(20, 0)
	current := start
	clock := func() time.Time {
		now := current
		current = current.Add(250 * time.Microsecond)
		return now
	}
	env := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("synthetic"))
	const offeredPackets = 4000
	envelopes := make(chan *pipeline.PacketEnvelope, offeredPackets+3)
	for range 3 {
		envelopes <- nil
	}
	for range offeredPackets {
		envelopes <- env
	}
	close(envelopes)

	bridge := newEnvelopeBridgePipeline(nil, NewPauseSignal(), nil, false, nil)
	bridge.now = clock
	bridge.run(envelopes)

	var details []components.PacketDisplay
	for {
		drained := DrainPendingPackets(false)
		if len(drained) == 0 {
			break
		}
		details = append(details, drained...)
	}
	theme := themes.Solarized()
	uiState := store.NewUIState(theme)
	uiState.Statistics = &components.Statistics{
		ProtocolCounts: components.NewBoundedCounter(1000),
		SourceCounts:   components.NewBoundedCounter(10000),
		DestCounts:     components.NewBoundedCounter(10000),
		MinPacketSize:  999999,
	}
	model := Model{
		statistics: uiState.Statistics, uiState: uiState,
		packetStore: store.NewPacketStore(offeredPackets), captureMode: components.CaptureModeLive,
	}
	model.processPendingPackets(details)

	stats := GetBridgeStats()
	require.Equal(t, int64(offeredPackets+3), stats.PacketsReceived)
	require.Equal(t, int64(3), stats.InvalidEnvelopes)
	require.Equal(t, int64(offeredPackets), GetIngressTelemetrySnapshot().Packets)
	require.Positive(t, stats.PacketsSampledOut)
	require.Positive(t, stats.PacketsDelivered)
	require.Less(t, stats.DisplayRetentionRatio, int64(1000))
	require.Equal(t, stats.PacketsReceived, stats.InvalidEnvelopes+stats.PacketsSampledOut+
		stats.BatchQueuePacketDrops+stats.PendingPacketEvictions+stats.PacketsDelivered)
}

func TestInvalidEnvelopesDoNotInflateSamplingIngressRate(t *testing.T) {
	t.Parallel()
	start := time.Unix(25, 0)
	acc := newIngressTelemetryAccumulator(start)
	policy := newDisplaySamplingPolicy(false, start)

	for range 10_000 {
		require.False(t, acc.observe(nil))
	}

	env := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("valid"))
	for i := 1; i <= 500; i++ {
		require.True(t, acc.observe(env))
		now := start.Add(time.Duration(i) * 2 * time.Millisecond)
		require.True(t, policy.shouldDisplay(env, acc.packets, now))
	}

	require.Equal(t, int64(500), acc.packets)
	require.Equal(t, 1.0, policy.ratio)
}

func TestEnvelopeBridgePreservesAcceptedBatchAcrossPause(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	t.Cleanup(ClearPendingPackets)
	SetVoIPModeEnabled(false)

	pause := NewPauseSignal()
	accepted := make(chan struct{})
	var once sync.Once
	bridge := newEnvelopeBridgePipeline(nil, pause, nil, false, nil)
	bridge.onBatchQueued = func() {
		once.Do(func() {
			pause.Pause()
			close(accepted)
		})
	}

	envelopes := make(chan *pipeline.PacketEnvelope, 50)
	env := telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("pause"))
	for range 50 {
		envelopes <- env
	}
	done := make(chan struct{})
	go func() {
		bridge.run(envelopes)
		close(done)
	}()

	<-accepted
	require.Eventually(t, func() bool { return pendingPackets.liveLen() == 50 }, time.Second, time.Millisecond)
	require.Equal(t, int64(50), GetBridgeStats().PacketsReceived)
	require.Zero(t, GetBridgeStats().BatchQueuePacketDrops)

	pause.Resume()
	close(envelopes)
	<-done
	require.Len(t, DrainPendingPackets(false), 50)
	require.Zero(t, GetBridgeStats().QueueDepth)
}

func TestEnvelopeBridgeQueueDepthReturnsToZeroAfterConsumerDrain(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	t.Cleanup(ClearPendingPackets)
	SetVoIPModeEnabled(false)

	envelopes := make(chan *pipeline.PacketEnvelope, 1)
	envelopes <- telemetryUDPEnvelope(t, pipeline.SourceLiveCapture, []byte("queue-depth"))
	close(envelopes)

	bridge := newEnvelopeBridgePipeline(nil, NewPauseSignal(), nil, false, nil)
	bridge.run(envelopes)

	require.Zero(t, GetBridgeStats().QueueDepth)
	require.Len(t, DrainPendingPackets(false), 1)
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
