package source

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

// Any packet inspection panics: demand-free capture must only update counters.
type untouchedDemandPacket struct{ gopacket.Packet }

func TestLocalPacketDemandSkipsInspectionAndResumesFiltering(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{BatchSize: 1})
	s.ctx = context.Background()
	var demanded atomic.Bool
	s.SetPacketDemand(demanded.Load)
	filter := &mockAppFilter{matchAll: true}
	s.SetApplicationFilter(filter)

	run := func(packet capture.PacketInfo) {
		input := make(chan capture.PacketInfo, 1)
		input <- packet
		close(input)
		s.batchingWorker(input)
	}
	run(capture.PacketInfo{Packet: &untouchedDemandPacket{}})
	require.Empty(t, s.batches)
	require.Zero(t, filter.calls)
	require.Equal(t, uint64(1), s.Stats().PacketsCaptured)
	require.Zero(t, s.Stats().PacketsForwarded)
	require.Zero(t, s.Stats().PacketsDropped)

	demanded.Store(true)
	run(buildTCPPacket(t, 1))
	require.Len(t, s.batches, 1)
	batch := <-s.batches
	require.Len(t, batch.Envelopes, 1)
	require.Equal(t, 1, filter.calls)
	require.Equal(t, uint64(2), s.Stats().PacketsCaptured)
	require.Equal(t, uint64(1), s.Stats().PacketsForwarded)

	// Resuming demand must still enforce the current application filter.
	filter.matchAll = false
	run(buildTCPPacket(t, 2))
	require.Empty(t, s.batches)
	require.Equal(t, 2, filter.calls)
	require.Equal(t, uint64(1), s.Stats().PacketsForwarded)

	demanded.Store(false)
	run(capture.PacketInfo{Packet: &untouchedDemandPacket{}})
	require.Empty(t, s.batches)
	require.Equal(t, 2, filter.calls)
	require.Equal(t, uint64(4), s.Stats().PacketsCaptured)
}

func TestLocalPacketDemandReleasesSkippedInjection(t *testing.T) {
	s := NewLocalSource(LocalSourceConfig{BatchSize: 1})
	s.SetPacketDemand(func() bool { return false })
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	injected := make(chan InjectedPacket, 1)
	s.SetTCPInjectionChannel(injected)
	var completions atomic.Int32
	injected <- InjectedPacket{
		PacketInfo:   capture.PacketInfo{Packet: &untouchedDemandPacket{}},
		AfterProcess: func() { completions.Add(1) },
	}
	input := make(chan capture.PacketInfo)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.batchingWorker(input)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("batching worker did not stop")
		}
		require.Equal(t, int32(1), completions.Load())
	})
	require.Eventually(t, func() bool { return completions.Load() == 1 }, time.Second, time.Millisecond)
	require.Empty(t, s.batches)
	require.Equal(t, uint64(1), s.Stats().PacketsCaptured)
	require.Zero(t, s.Stats().PacketsForwarded)
}
