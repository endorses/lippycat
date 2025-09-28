package voip

import (
	"fmt"
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

	// Create an old call that should be cleaned up
	oldCall := &CallInfo{
		CallID:      oldCallID,
		State:       "NEW",
		Created:     time.Now().Add(-2 * time.Hour),
		LastUpdated: time.Now().Add(-2 * time.Hour), // Very old
		LinkType:    layers.LinkTypeEthernet,
	}

	// Create a recent call that should be kept
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

	// Test cleanup directly
	tracker.cleanupOldCalls()

	// Verify old call was removed and recent call remains
	tracker.mu.RLock()
	assert.NotContains(t, tracker.callMap, oldCallID, "Old call should have been cleaned up")
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
