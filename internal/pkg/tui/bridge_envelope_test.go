//go:build tui || all

package tui

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestNormalizeCaptureStreamPreservesEnvelopeProvenance(t *testing.T) {
	timestamp := time.Date(2026, time.August, 29, 12, 34, 56, 789, time.UTC)
	data := goldenUDPPacket(t, 53000, 53, []byte{0, 1, 2, 3})
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data) + 8,
	}

	input := make(chan capture.PacketInfo, 1)
	input <- capture.PacketInfo{Packet: packet, Interface: "replay-0", LinkType: layers.LinkTypeEthernet}
	close(input)

	envelopes := NormalizeCaptureStream(context.Background(), input, pipeline.SourcePCAPReplay)
	envelope := <-envelopes
	require.NotNil(t, envelope)
	require.Equal(t, pipeline.SourcePCAPReplay, envelope.Source.Kind)
	require.Equal(t, "replay-0", envelope.Source.InterfaceName)
	require.Equal(t, layers.LinkTypeEthernet, envelope.LinkType)
	require.Equal(t, timestamp, envelope.CaptureTime)
	require.Equal(t, len(data), envelope.CaptureLength)
	require.Equal(t, len(data)+8, envelope.OriginalLength)
	require.True(t, bytes.Equal(data, envelope.Data))
	_, ok := <-envelopes
	require.False(t, ok)
}

func TestBridgeStatsExposeReassemblyLossStages(t *testing.T) {
	ResetBridgeStats()
	atomic.StoreInt64(&bridgeStats.ReassemblyNormalDiscontinuities, 2)
	atomic.StoreInt64(&bridgeStats.ReassemblyNormalMissingBytes, 20)
	atomic.StoreInt64(&bridgeStats.ReassemblyExplicitFlushDiscontinuities, 3)
	atomic.StoreInt64(&bridgeStats.ReassemblyExplicitFlushMissingBytes, 30)

	stats := GetBridgeStats()
	require.Equal(t, int64(2), stats.ReassemblyNormalDiscontinuities)
	require.Equal(t, int64(20), stats.ReassemblyNormalMissingBytes)
	require.Equal(t, int64(3), stats.ReassemblyExplicitFlushDiscontinuities)
	require.Equal(t, int64(30), stats.ReassemblyExplicitFlushMissingBytes)
}

func TestNormalizeCaptureStreamBuffersShortBridgeStall(t *testing.T) {
	const packetCount = 64
	input := make(chan capture.PacketInfo)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	envelopes := NormalizeCaptureStream(ctx, input, pipeline.SourceLiveCapture)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < packetCount; i++ {
			packet := gopacket.NewPacket([]byte{byte(i)}, gopacket.LayerTypePayload, gopacket.Default)
			input <- capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeRaw}
		}
		close(input)
	}()

	select {
	case <-producerDone:
	case <-time.After(time.Second):
		t.Fatal("normalization did not absorb a short bridge stall")
	}

	for i := 0; i < packetCount; i++ {
		envelope := <-envelopes
		require.Equal(t, byte(i), envelope.Data[0])
	}
	_, ok := <-envelopes
	require.False(t, ok)
}

func TestEnvelopeBridgePublishesOrderedPacketsThroughLocalEventHandler(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	ResetTUIReady()
	SignalTUIReady()
	SetVoIPModeEnabled(false)

	base := time.Date(2026, time.August, 29, 13, 0, 0, 0, time.UTC)
	envelopes := make(chan *pipeline.PacketEnvelope, 3)
	for i := range 3 {
		data := goldenUDPPacket(t, layers.UDPPort(53000+i), 53, []byte{byte(i)})
		envelopes <- &pipeline.PacketEnvelope{
			Data:           data,
			LinkType:       layers.LinkTypeEthernet,
			CaptureTime:    base.Add(time.Duration(i) * time.Millisecond),
			CaptureLength:  len(data),
			OriginalLength: len(data),
			Source:         pipeline.SourceProvenance{Kind: pipeline.SourcePCAPReplay, InterfaceName: "ordered.pcap"},
		}
	}
	close(envelopes)

	StartEnvelopeBridge(envelopes, nil, NewPauseSignal(), nil, true, nil)
	got := pendingPackets.drainPackets(3)
	require.Len(t, got, 3)
	for i := range got {
		require.Equal(t, base.Add(time.Duration(i)*time.Millisecond), got[i].Timestamp)
		require.Equal(t, "ordered.pcap", got[i].Interface)
	}
	require.Zero(t, GetBridgeStats().PacketsDisplayed)

	// Compile-time and behavioral coverage for the shared local/remote boundary.
	var handler types.EventHandler = newLocalTUIEventHandler(nil, true)
	handler.OnPacketBatch([]types.PacketDisplay{{Timestamp: base.Add(4 * time.Millisecond)}})
	require.Len(t, pendingPackets.drainPackets(1), 1)
}
