//go:build tui || all

package tui

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func numberedPackets(first, count int) []components.PacketDisplay {
	packets := make([]components.PacketDisplay, count)
	for i := range packets {
		packets[i].Timestamp = time.Unix(0, int64(first+i))
	}
	return packets
}

func packetNumbers(packets []components.PacketDisplay) []int64 {
	result := make([]int64, len(packets))
	for i := range packets {
		result[i] = packets[i].Timestamp.UnixNano()
	}
	return result
}

func newTestPendingPacketBuffer(capacity int) *pendingPacketBuffer {
	return &pendingPacketBuffer{
		packets: make([]components.PacketDisplay, 0),
		live:    make([]components.PacketDisplay, capacity),
	}
}

func TestPendingPacketBufferLiveRingOrderingWraparoundAndEviction(t *testing.T) {
	ResetBridgeStats()
	pb := newTestPendingPacketBuffer(5)
	pb.addPackets(numberedPackets(0, 4), false)
	require.Equal(t, []int64{0, 1, 2}, packetNumbers(pb.drainPackets(3)))

	// This append wraps and evicts the oldest retained packet (3).
	pb.addPackets(numberedPackets(4, 5), false)
	require.Equal(t, 5, pb.liveLen())
	require.Equal(t, int64(1), GetBridgeStats().PendingPacketEvictions)
	require.Equal(t, []int64{4, 5}, packetNumbers(pb.drainPackets(2)))
	require.Equal(t, []int64{6, 7, 8}, packetNumbers(pb.drainPackets(10)))
	require.Zero(t, pb.liveLen())
}

func TestPendingPacketBufferLiveRingLargeAppendKeepsNewestCapacity(t *testing.T) {
	ResetBridgeStats()
	pb := newTestPendingPacketBuffer(4)
	pb.addPackets(numberedPackets(10, 10), false)

	require.Equal(t, 4, pb.liveLen())
	require.Equal(t, int64(6), GetBridgeStats().PendingPacketEvictions)
	require.Equal(t, []int64{16, 17, 18, 19}, packetNumbers(pb.drainPackets(10)))
}

func TestPendingPacketBufferOfflinePathIsLossless(t *testing.T) {
	pb := newTestPendingPacketBuffer(3)
	pb.addPackets(numberedPackets(0, 20), true)

	require.Zero(t, pb.liveLen())
	require.Len(t, pb.packets, 20)
	require.Equal(t, packetNumbers(numberedPackets(0, 20)), packetNumbers(pb.drainPackets(100)))
}

func TestDrainPendingPacketsAdaptsToLiveBacklog(t *testing.T) {
	ResetBridgeStats()
	ClearPendingPackets()
	t.Cleanup(ClearPendingPackets)

	pendingPackets.addPackets(numberedPackets(0, 40), false)
	require.Len(t, DrainPendingPackets(false), 40)

	pendingPackets.addPackets(numberedPackets(100, 1200), false)
	require.Len(t, DrainPendingPackets(false), 300)

	ClearPendingPackets()
	pendingPackets.addPackets(numberedPackets(0, 4000), false)
	require.Len(t, DrainPendingPackets(false), 500)
}

func TestClearPendingPacketsClearsBothStoragePaths(t *testing.T) {
	ClearPendingPackets()
	pendingPackets.addPackets(numberedPackets(0, 5), false)
	pendingPackets.addPackets(numberedPackets(5, 5), true)
	ClearPendingPackets()

	require.Nil(t, pendingPackets.drainPackets(10))
	require.Zero(t, pendingPackets.liveLen())
}

func BenchmarkPendingPacketBufferSaturatedLiveRing(b *testing.B) {
	pb := newTestPendingPacketBuffer(maxPendingLivePackets)
	batch := numberedPackets(0, 100)
	pb.addPackets(numberedPackets(0, maxPendingLivePackets), false)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = pb.drainPackets(len(batch))
		pb.addPackets(batch, false)
	}
}

// BenchmarkPendingPacketBufferLegacyFrontSlice records the Phase 1 baseline:
// every drain copied the entire retained backlog before the next append.
func BenchmarkPendingPacketBufferLegacyFrontSlice(b *testing.B) {
	queued := numberedPackets(0, maxPendingLivePackets)
	batch := numberedPackets(0, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		remaining := make([]components.PacketDisplay, len(queued)-len(batch))
		copy(remaining, queued[len(batch):])
		queued = append(remaining, batch...)
	}
}
