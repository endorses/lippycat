//go:build tui || all

package tui

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/tcpassembly"
)

// TestBridgeOfflinePacketCounting tests that the bridge correctly counts all packets
// when processing offline PCAP files (simulating TUI mode).
func TestBridgeOfflinePacketCounting(t *testing.T) {
	files := []string{
		"/home/grischa/Downloads/pcaps/gk_72_rtp_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
		"/home/grischa/Downloads/pcaps/gk_72_sip_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
	}

	// Check files exist
	for _, path := range files {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("Test file not found: %s", path)
		}
	}

	// Run test multiple times to check consistency
	for run := 0; run < 5; run++ {
		t.Run("run", func(t *testing.T) {
			// Reset bridge stats and TUI ready state
			ResetBridgeStats()
			ClearPendingPackets()
			ClearCallTracker()
			ResetTUIReady()
			SignalTUIReady() // Mark TUI as ready so bridge doesn't block

			// Set up call tracker (simulates TUI offline mode)
			callTracker := NewCallTracker()
			SetCallTracker(callTracker)

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
					f.Close()
				}
			}()

			// Create pause signal (simulates TUI)
			pauseSignal := NewPauseSignal()

			// Track packets added to pendingPackets
			var packetsInPending int64

			// Create processor that uses the bridge (like TUI does)
			processor := func(ch <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
				// Run bridge (this is what TUI's startFileSnifferOrdered does)
				StartPacketBridge(ch, nil, pauseSignal) // nil program is ok, we don't use it

				// After bridge completes, count packets in pending buffer
				pendingPackets.mu.Lock()
				packetsInPending = int64(len(pendingPackets.packets))
				pendingPackets.mu.Unlock()
			}

			// Run offline ordered capture
			capture.RunOfflineOrdered(devices, "", processor, nil)

			// Allow time for consumer to finish
			time.Sleep(100 * time.Millisecond)

			// Get bridge stats
			stats := GetBridgeStats()

			t.Logf("Run %d: PacketsReceived=%d, PacketsDisplayed=%d, BatchesSent=%d, BatchesDropped=%d, PacketsInPending=%d",
				run, stats.PacketsReceived, stats.PacketsDisplayed, stats.BatchesSent, stats.BatchesDropped, packetsInPending)

			// Verify all packets were processed
			const expectedPackets = 1077 // 1023 + 54
			if stats.PacketsReceived != expectedPackets {
				t.Errorf("Expected %d packets received, got %d", expectedPackets, stats.PacketsReceived)
			}
			if stats.PacketsDisplayed != expectedPackets {
				t.Errorf("Expected %d packets displayed, got %d", expectedPackets, stats.PacketsDisplayed)
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

// TestBridgeOfflineConsistency runs the bridge multiple times in parallel
// to stress test for race conditions
func TestBridgeOfflineConsistency(t *testing.T) {
	files := []string{
		"/home/grischa/Downloads/pcaps/gk_72_rtp_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
		"/home/grischa/Downloads/pcaps/gk_72_sip_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap",
	}

	// Check files exist
	for _, path := range files {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("Test file not found: %s", path)
		}
	}

	const numRuns = 10
	results := make([]int64, numRuns)

	for i := 0; i < numRuns; i++ {
		// Reset state before each run
		ResetBridgeStats()
		ClearPendingPackets()
		ClearCallTracker()
		ResetTUIReady()
		SignalTUIReady() // Mark TUI as ready so bridge doesn't block

		// Set up call tracker
		callTracker := NewCallTracker()
		SetCallTracker(callTracker)

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

		processor := func(ch <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
			StartPacketBridge(ch, nil, pauseSignal)
		}

		capture.RunOfflineOrdered(devices, "", processor, nil)

		// Wait for everything to settle
		time.Sleep(50 * time.Millisecond)

		// Get results
		results[i] = atomic.LoadInt64(&bridgeStats.PacketsReceived)

		// Close files
		for _, f := range openFiles {
			f.Close()
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
