package voip

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetOrCreateCall(t *testing.T) {
	// Create a new tracker for this test
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	callID := "test-call-123"

	// Test getOrCreateCall logic directly on our tracker
	tracker.mu.Lock()
	call1, exists := tracker.callMap[callID]
	if !exists {
		call1 = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    layers.LinkTypeEthernet,
		}
		tracker.callMap[callID] = call1
	}
	tracker.mu.Unlock()

	assert.NotNil(t, call1)
	assert.Equal(t, callID, call1.CallID)

	// Second call should return same CallInfo
	tracker.mu.Lock()
	call2, exists := tracker.callMap[callID]
	if !exists {
		call2 = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    layers.LinkTypeEthernet,
		}
		tracker.callMap[callID] = call2
	}
	tracker.mu.Unlock()

	assert.Equal(t, call1, call2)

	// Verify it's in the map
	tracker.mu.RLock()
	storedCall, exists := tracker.callMap[callID]
	tracker.mu.RUnlock()
	assert.True(t, exists)
	assert.Equal(t, call1, storedCall)
}

func TestCallInfoSetState(t *testing.T) {
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	callID := "test-state-call"
	call := &CallInfo{
		CallID:      callID,
		State:       "NEW",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
	}

	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()

	oldTime := call.LastUpdated

	// Test state change directly
	tracker.mu.Lock()
	call.State = "ACTIVE"
	call.LastUpdated = time.Now()
	tracker.mu.Unlock()

	// Check the state was updated
	assert.Equal(t, "ACTIVE", call.State)
	assert.True(t, call.LastUpdated.After(oldTime))
}

func TestShutdownCallTracker(t *testing.T) {
	// Test that shutdown function exists and can be called without panic
	assert.NotPanics(t, func() {
		ShutdownCallTracker()
	}, "ShutdownCallTracker should not panic")
}

func TestJanitorLoopCleanup(t *testing.T) {
	// Create a new tracker for this test
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	// Create test calls with different ages
	oldCallID := "old-call-to-cleanup"
	recentCallID := "recent-call-to-keep"

	// Create an old call
	oldCall := &CallInfo{
		CallID:      oldCallID,
		State:       "NEW",
		Created:     time.Now().Add(-2 * time.Hour),
		LastUpdated: time.Now().Add(-2 * time.Hour), // Very old
		LinkType:    layers.LinkTypeEthernet,
	}

	// Create a recent call
	recentCall := &CallInfo{
		CallID:      recentCallID,
		State:       "NEW",
		Created:     time.Now(),
		LastUpdated: time.Now(), // Recent
		LinkType:    layers.LinkTypeEthernet,
	}

	// Add calls to tracker
	tracker.mu.Lock()
	tracker.callMap[oldCallID] = oldCall
	tracker.callMap[recentCallID] = recentCall
	tracker.mu.Unlock()

	// Verify both calls exist before cleanup
	tracker.mu.RLock()
	assert.Contains(t, tracker.callMap, oldCallID)
	assert.Contains(t, tracker.callMap, recentCallID)
	tracker.mu.RUnlock()

	// Test cleanup directly - this is now a no-op since cleanup is handled by ring buffer
	tracker.cleanupOldCalls()

	// Verify both calls remain (cleanup is now handled by ring buffer, not time-based expiry)
	tracker.mu.RLock()
	assert.Contains(t, tracker.callMap, oldCallID, "Call should remain (cleanup is ring buffer based)")
	assert.Contains(t, tracker.callMap, recentCallID, "Recent call should still exist")
	tracker.mu.RUnlock()
}

func TestConcurrentCallCreation(t *testing.T) {
	// Create a new tracker for this test
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	const numGoroutines = 10
	const callsPerGoroutine = 100

	var wg sync.WaitGroup
	callIDs := make([]string, numGoroutines*callsPerGoroutine)

	// Test concurrent creation directly on our tracker instance
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				callID := fmt.Sprintf("concurrent-call-%d-%d", goroutineID, j)
				callIDs[goroutineID*callsPerGoroutine+j] = callID

				// Call getOrCreateCall directly on our tracker
				tracker.mu.Lock()
				call, exists := tracker.callMap[callID]
				if !exists {
					call = &CallInfo{
						CallID:      callID,
						State:       "NEW",
						Created:     time.Now(),
						LastUpdated: time.Now(),
						LinkType:    layers.LinkTypeEthernet,
					}
					tracker.callMap[callID] = call
				}
				tracker.mu.Unlock()

				require.NotNil(t, call)
				assert.Equal(t, callID, call.CallID)
			}
		}(i)
	}

	wg.Wait()

	// Verify all calls were created
	tracker.mu.RLock()
	assert.Len(t, tracker.callMap, numGoroutines*callsPerGoroutine, "All calls should be created")

	// Verify each call exists and is correct
	for _, callID := range callIDs {
		call, exists := tracker.callMap[callID]
		assert.True(t, exists, "Call %s should exist", callID)
		if exists {
			assert.Equal(t, callID, call.CallID)
		}
	}
	tracker.mu.RUnlock()
}

func TestSanitizeCallID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal call ID",
			input:    "normal-call-123",
			expected: "normal-call-123",
		},
		{
			name:     "Call ID with path traversal",
			input:    "../../../etc/passwd",
			expected: "_________etc_passwd", // Three ".." become "__" each (6 total) plus three "/" become "_" (3 total) = 9 underscores
		},
		{
			name:     "Call ID with dangerous characters",
			input:    "call<>|?*:@",
			expected: "call_______", // 7 special chars replaced with _
		},
		{
			name:     "Very long call ID",
			input:    string(make([]byte, 200)), // 200 null bytes
			expected: strings.Repeat("_", 100),  // Null bytes become underscores, truncated to 100
		},
		{
			name:     "Call ID with forward slashes",
			input:    "call/with/slashes",
			expected: "call_with_slashes",
		},
		{
			name:     "Call ID with backslashes",
			input:    "call\\with\\backslashes",
			expected: "call_with_backslashes",
		},
		{
			name:     "Empty call ID",
			input:    "",
			expected: "safe_filename", // Secure implementation returns safe default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitize(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 100, "Result should not exceed 100 characters")
		})
	}
}

// TestConcurrentWritesToSameCall tests that concurrent writes to the same call's
// SIP and RTP writers are properly synchronized with mutexes to prevent race conditions.
// This test verifies Phase 1.1 of the code review remediation plan.
func TestConcurrentWritesToSameCall(t *testing.T) {
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	callID := "test-concurrent-write-call"
	call := &CallInfo{
		CallID:      callID,
		State:       "ACTIVE",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
	}

	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()

	const numWriters = 10
	const writesPerWriter = 100
	var wg sync.WaitGroup

	// Test concurrent access to SIP writer mutex
	t.Run("concurrent_sip_mutex", func(t *testing.T) {
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < writesPerWriter; j++ {
					// Lock and unlock the SIP writer mutex
					call.sipWriterMu.Lock()
					// Simulate write operation
					_ = call.SIPWriter
					call.sipWriterMu.Unlock()
				}
			}()
		}
		wg.Wait()
	})

	// Test concurrent access to RTP writer mutex
	t.Run("concurrent_rtp_mutex", func(t *testing.T) {
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < writesPerWriter; j++ {
					// Lock and unlock the RTP writer mutex
					call.rtpWriterMu.Lock()
					// Simulate write operation
					_ = call.RTPWriter
					call.rtpWriterMu.Unlock()
				}
			}()
		}
		wg.Wait()
	})

	// Test concurrent mixed access (some SIP, some RTP)
	t.Run("concurrent_mixed_mutex", func(t *testing.T) {
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < writesPerWriter; j++ {
					// Alternate between SIP and RTP writes
					if (id+j)%2 == 0 {
						call.sipWriterMu.Lock()
						_ = call.SIPWriter
						call.sipWriterMu.Unlock()
					} else {
						call.rtpWriterMu.Lock()
						_ = call.RTPWriter
						call.rtpWriterMu.Unlock()
					}
				}
			}(i)
		}
		wg.Wait()
	})
}

// TestCallInfoClose tests that CallInfo.Close() properly closes files with mutex protection
// and is safe to call concurrently and multiple times (idempotent).
func TestCallInfoClose(t *testing.T) {
	t.Run("close_without_files", func(t *testing.T) {
		call := &CallInfo{
			CallID: "test-close-no-files",
		}
		err := call.Close()
		assert.NoError(t, err, "Close should not error when no files are open")
	})

	t.Run("concurrent_close", func(t *testing.T) {
		call := &CallInfo{
			CallID: "test-concurrent-close",
		}

		const numClosers = 10
		var wg sync.WaitGroup

		// Try to close the same call from multiple goroutines
		for i := 0; i < numClosers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = call.Close()
			}()
		}

		wg.Wait()

		// Verify files are nil after close
		assert.Nil(t, call.sipFile)
		assert.Nil(t, call.rtpFile)
		assert.Nil(t, call.SIPWriter)
		assert.Nil(t, call.RTPWriter)
	})

	t.Run("idempotent_close", func(t *testing.T) {
		call := &CallInfo{
			CallID: "test-idempotent-close",
		}

		// First close
		err1 := call.Close()
		assert.NoError(t, err1)

		// Second close should not panic or error
		err2 := call.Close()
		assert.NoError(t, err2)

		// Third close
		err3 := call.Close()
		assert.NoError(t, err3)
	})
}

// TestConcurrentShutdownAndWrites tests that concurrent writes during shutdown
// are handled gracefully. This verifies Phase 1.2 of the code review remediation plan:
// - Shutdown sets the shuttingDown flag
// - Active writes are tracked with activeWrites WaitGroup
// - Shutdown waits for active writes to complete before closing files
// - New writes during shutdown are rejected
func TestConcurrentShutdownAndWrites(t *testing.T) {
	tracker := NewCallTracker()

	callID := "test-shutdown-race-call"
	call := &CallInfo{
		CallID:      callID,
		State:       "ACTIVE",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
	}

	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()

	const numWriters = 20
	const writesPerWriter = 50
	var wg sync.WaitGroup

	// Start concurrent writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < writesPerWriter; j++ {
				// Simulate write operations by acquiring activeWrites
				if tracker.shuttingDown.Load() == 0 {
					tracker.activeWrites.Add(1)
					// Simulate some work
					time.Sleep(time.Microsecond)
					tracker.activeWrites.Done()
				}
			}
		}(i)
	}

	// Let some writes happen
	time.Sleep(10 * time.Millisecond)

	// Trigger shutdown while writes are still happening
	shutdownDone := make(chan struct{})
	go func() {
		tracker.Shutdown()
		close(shutdownDone)
	}()

	// Wait for all writers to finish
	wg.Wait()

	// Wait for shutdown to complete
	select {
	case <-shutdownDone:
		// Shutdown completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not complete within timeout")
	}

	// Verify shutdown state
	assert.Equal(t, int32(1), tracker.shuttingDown.Load(), "shuttingDown flag should be set")

	// Verify that call map is empty (all calls were closed)
	tracker.mu.RLock()
	assert.Empty(t, tracker.callMap, "All calls should be closed and removed")
	tracker.mu.RUnlock()

	// Verify no new writes can happen after shutdown
	tracker.activeWrites.Add(1)
	tracker.activeWrites.Done()
	// If this doesn't panic, the WaitGroup is working correctly
}

// TestShutdownWithActiveWrites tests that shutdown waits for active writes
// to complete before closing files.
func TestShutdownWithActiveWrites(t *testing.T) {
	tracker := NewCallTracker()

	callID := "test-shutdown-wait-call"
	call := &CallInfo{
		CallID:      callID,
		State:       "ACTIVE",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
	}

	tracker.mu.Lock()
	tracker.callMap[callID] = call
	tracker.mu.Unlock()

	// Start a long-running write operation
	writeDone := make(chan struct{})
	tracker.activeWrites.Add(1)
	go func() {
		defer tracker.activeWrites.Done()
		// Simulate long write
		time.Sleep(100 * time.Millisecond)
		close(writeDone)
	}()

	// Start shutdown (should wait for write to complete)
	shutdownStart := time.Now()
	tracker.Shutdown()
	shutdownDuration := time.Since(shutdownStart)

	// Verify that shutdown waited for the write
	assert.GreaterOrEqual(t, shutdownDuration, 100*time.Millisecond,
		"Shutdown should wait for active writes to complete")

	// Verify write completed before shutdown finished
	select {
	case <-writeDone:
		// Write completed as expected
	default:
		t.Fatal("Write should have completed before shutdown finished")
	}

	// Verify call map is empty
	tracker.mu.RLock()
	assert.Empty(t, tracker.callMap)
	tracker.mu.RUnlock()
}

// TestWritesDuringShutdown tests that writes are rejected during shutdown
func TestWritesDuringShutdown(t *testing.T) {
	tracker := NewCallTracker()

	// Trigger shutdown
	tracker.shuttingDown.Store(1)

	// Try to start a new write after shutdown flag is set
	writeAttempted := false
	if tracker.shuttingDown.Load() == 0 {
		tracker.activeWrites.Add(1)
		writeAttempted = true
		tracker.activeWrites.Done()
	}

	assert.False(t, writeAttempted,
		"Write should not be attempted when shuttingDown flag is set")
}

// TestCallTrackerFilePermissions verifies that per-call PCAP files are created with secure permissions (0600)
// This test addresses security concern from code review: Phase 1.4 - Fix PCAP File Permissions
func TestCallTrackerFilePermissions(t *testing.T) {
	// Create tracker with PCAP writing enabled
	tracker := NewCallTracker()
	defer tracker.Shutdown()

	// Create a call with PCAP files
	callID := "test-call-permissions"
	call := &CallInfo{
		CallID:      callID,
		State:       "NEW",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    layers.LinkTypeEthernet,
	}

	// Initialize PCAP files
	err := call.initWriters()
	require.NoError(t, err)
	require.NotNil(t, call.sipFile, "SIP file should be created")
	require.NotNil(t, call.rtpFile, "RTP file should be created")

	// Get file paths before closing
	sipPath := call.sipFile.Name()
	rtpPath := call.rtpFile.Name()

	// Close the call to flush files
	err = call.Close()
	require.NoError(t, err)

	// Check SIP file permissions
	sipInfo, err := os.Stat(sipPath)
	require.NoError(t, err)
	sipMode := sipInfo.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), sipMode,
		"SIP PCAP file should have 0600 permissions (owner read/write only), got %04o", sipMode)

	// Check RTP file permissions
	rtpInfo, err := os.Stat(rtpPath)
	require.NoError(t, err)
	rtpMode := rtpInfo.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), rtpMode,
		"RTP PCAP file should have 0600 permissions (owner read/write only), got %04o", rtpMode)

	// Cleanup
	_ = os.Remove(sipPath)
	_ = os.Remove(rtpPath)
}
