//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// TestBridgeOfflinePacketCounting tests that the bridge correctly counts all packets
// when processing offline PCAP files (simulating TUI mode).
func TestBridgeOfflinePacketCounting(t *testing.T) {
	files := writeOrderedBridgeFixtures(t)

	// Run test multiple times to check consistency
	for run := 0; run < 5; run++ {
		t.Run("run", func(t *testing.T) {
			// Reset bridge stats and TUI ready state
			ResetBridgeStats()
			ClearPendingPackets()
			ResetTUIReady()
			SignalTUIReady() // Mark TUI as ready so bridge doesn't block

			// Set up call tracker (simulates TUI offline mode)
			callTracker := NewCallTracker()

			// Open files and create devices
			var openFiles []*os.File
			var devices []pcaptypes.PcapInterface
			for _, path := range files {
				f, err := os.Open(path)
				if err != nil {
					t.Fatalf("Error opening %s: %v", path, err)
				}
				openFiles = append(openFiles, f)
				devices = append(devices, pcaptypes.CreateOfflineInterface(f))
			}
			defer func() {
				for _, f := range openFiles {
					require.NoError(t, f.Close())
				}
			}()

			// Create pause signal (simulates TUI)
			pauseSignal := NewPauseSignal()

			// Track packets added to pendingPackets
			var packetsInPending int64

			// Create processor that uses the bridge (like TUI does)
			processor := func(ch <-chan capture.PacketInfo) {
				// Run bridge (this is what TUI's startFileSnifferOrdered does)
				StartEnvelopeBridge(NormalizeCaptureStream(context.Background(), ch, pipeline.SourcePCAPReplay), nil, pauseSignal, callTracker, true, nil)

				// After bridge completes, count packets in pending buffer
				pendingPackets.mu.Lock()
				packetsInPending = int64(len(pendingPackets.packets))
				pendingPackets.mu.Unlock()
			}

			// Run offline ordered capture
			require.NoError(t, capture.RunOfflineOrderedContext(context.Background(), devices, "", processor))

			// Get bridge stats
			stats := GetBridgeStats()

			t.Logf("Run %d: PacketsReceived=%d, PacketsDisplayed=%d, BatchesSent=%d, BatchesDropped=%d, PacketsInPending=%d",
				run, stats.PacketsReceived, stats.PacketsDisplayed, stats.BatchesSent, stats.BatchesDropped, packetsInPending)

			// Verify all packets were processed
			const expectedPackets = 1077 // 1023 + 54
			if stats.PacketsReceived != expectedPackets {
				t.Errorf("Expected %d packets received, got %d", expectedPackets, stats.PacketsReceived)
			}
			if stats.PacketsDisplayed != 0 {
				t.Errorf("Expected no packets displayed before model delivery, got %d", stats.PacketsDisplayed)
			}
			if stats.BatchesDropped != 0 {
				t.Errorf("Expected 0 batches dropped, got %d", stats.BatchesDropped)
			}
			if packetsInPending != expectedPackets {
				t.Errorf("Expected %d packets in pending buffer, got %d", expectedPackets, packetsInPending)
			}
		})
	}
}

// TestBridgeOfflineConsistency repeats replay to check deterministic delivery.
func TestBridgeOfflineConsistency(t *testing.T) {
	files := writeOrderedBridgeFixtures(t)

	const numRuns = 10
	results := make([]int64, numRuns)

	for i := 0; i < numRuns; i++ {
		// Reset state before each run
		ResetBridgeStats()
		ClearPendingPackets()
		ResetTUIReady()
		SignalTUIReady() // Mark TUI as ready so bridge doesn't block

		// Set up call tracker
		callTracker := NewCallTracker()

		// Open files and create devices
		var openFiles []*os.File
		var devices []pcaptypes.PcapInterface
		for _, path := range files {
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("Error opening %s: %v", path, err)
			}
			openFiles = append(openFiles, f)
			devices = append(devices, pcaptypes.CreateOfflineInterface(f))
		}

		pauseSignal := NewPauseSignal()

		processor := func(ch <-chan capture.PacketInfo) {
			StartEnvelopeBridge(NormalizeCaptureStream(context.Background(), ch, pipeline.SourcePCAPReplay), nil, pauseSignal, callTracker, true, nil)
		}

		require.NoError(t, capture.RunOfflineOrderedContext(context.Background(), devices, "", processor))

		// Get results
		results[i] = atomic.LoadInt64(&bridgeStats.PacketsReceived)

		// Close files
		for _, f := range openFiles {
			require.NoError(t, f.Close())
		}
	}

	// Check all results are consistent
	t.Logf("Results from %d runs: %v", numRuns, results)

	first := results[0]
	for i, result := range results {
		if result != first {
			t.Errorf("Inconsistent results: run %d got %d, expected %d", i, result, first)
		}
	}

	// Verify we got the expected count
	const expectedPackets = 1077
	if first != expectedPackets {
		t.Errorf("Expected %d packets, got %d", expectedPackets, first)
	}
}

// Each file is monotonic and their timestamps interleave. These generated files
// keep delivery tests independent of private captures and timestamp regressions.
func writeOrderedBridgeFixtures(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	data := goldenUDPPacket(t, 32000, 32001, []byte("offline bridge fixture"))
	var paths []string
	for source, count := range []int{1023, 54} {
		path := filepath.Join(dir, fmt.Sprintf("source-%d.pcap", source))
		f, err := os.Create(path)
		require.NoError(t, err)
		writer := pcapgo.NewWriter(f)
		require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for sequence := 0; sequence < count; sequence++ {
			require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Unix(1700000000, int64(2*sequence+source)*1000000),
				CaptureLength: len(data), Length: len(data),
			}, data))
		}
		require.NoError(t, f.Close())
		paths = append(paths, path)
	}
	return paths
}
