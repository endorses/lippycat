package voip

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockFreeCallTracker_BasicOperations(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	callID := "test-lockfree-basic"
	linkType := layers.LinkTypeEthernet

	// Test GetOrCreateCall
	call1 := tracker.GetOrCreateCall(callID, linkType)
	require.NotNil(t, call1)
	assert.Equal(t, callID, call1.CallID)
	assert.Equal(t, "NEW", call1.State)

	// Test GetCall
	call2, err := tracker.GetCall(callID)
	require.NoError(t, err)
	assert.Equal(t, call1, call2)

	// Test SetCallState
	tracker.SetCallState(callID, "RINGING")
	call3, err := tracker.GetCall(callID)
	require.NoError(t, err)
	assert.Equal(t, "RINGING", call3.State)

	// Test statistics
	stats := tracker.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(1), stats.ActiveCalls)
}

func TestLockFreeCallTracker_PortMapping(t *testing.T) {
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	callID := "test-lockfree-port"
	port := "8000"

	// Test AddPortMapping
	tracker.AddPortMapping(port, callID)

	// Test GetCallIDByPort
	retrievedCallID, found := tracker.GetCallIDByPort(port)
	assert.True(t, found)
	assert.Equal(t, callID, retrievedCallID)

	// Test RemovePortMapping
	tracker.RemovePortMapping(port)
	_, found = tracker.GetCallIDByPort(port)
	assert.False(t, found)
}

func TestLockFreeCallTracker_ConcurrentAccess(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	numGoroutines := 100
	operationsPerGoroutine := 100
	var wg sync.WaitGroup
	var successCount atomic.Int64

	// Concurrent read/write operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				callID := "concurrent-call-" + string(rune(goroutineID*1000+j))

				// Create call
				call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
				if call != nil {
					successCount.Add(1)

					// Update state
					tracker.SetCallState(callID, "ACTIVE")

					// Add port mapping
					port := string(rune(8000 + goroutineID*100 + j))
					tracker.AddPortMapping(port, callID)

					// Read back
					_, err := tracker.GetCall(callID)
					if err == nil {
						successCount.Add(1)
					}

					// Check port mapping
					if _, found := tracker.GetCallIDByPort(port); found {
						successCount.Add(1)
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify statistics
	stats := tracker.GetStats()
	assert.Greater(t, stats.TotalCalls, int64(0))
	assert.Greater(t, successCount.Load(), int64(0))
}

func TestLockFreeCallTracker_RaceConditions(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	callID := "race-condition-call"
	numGoroutines := 50
	var wg sync.WaitGroup

	// Multiple goroutines trying to create the same call
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
			if call != nil {
				tracker.SetCallState(callID, "CREATED")
			}
		}()
	}

	wg.Wait()

	// Should only have one call created
	stats := tracker.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(1), stats.ActiveCalls)

	// Verify call exists and has consistent state
	call, err := tracker.GetCall(callID)
	require.NoError(t, err)
	assert.Equal(t, callID, call.CallID)
}

func TestLockFreeCallTracker_CleanupExpiredCalls(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	// Create some calls
	call1 := tracker.GetOrCreateCall("call-1", layers.LinkTypeEthernet)
	call2 := tracker.GetOrCreateCall("call-2", layers.LinkTypeEthernet)
	require.NotNil(t, call1)
	require.NotNil(t, call2)

	// Manually set old timestamp for call1
	oldTime := time.Now().Add(-2 * time.Hour)
	call1.LastUpdated = oldTime

	// Run cleanup
	cleaned := tracker.CleanupExpiredCalls()
	assert.Greater(t, cleaned, 0)

	// call1 should be removed, call2 should remain
	_, err1 := tracker.GetCall("call-1")
	assert.Error(t, err1)

	_, err2 := tracker.GetCall("call-2")
	assert.NoError(t, err2)
}

func TestHybridCallTracker_ModeSwitching(t *testing.T) {
	ResetConfigOnce()
	hybrid := NewHybridCallTracker()
	defer hybrid.Shutdown()

	callID := "hybrid-test-call"
	linkType := layers.LinkTypeEthernet

	// Start in traditional mode
	hybrid.DisableLockFree()
	assert.False(t, hybrid.IsLockFreeEnabled())

	// Create call in traditional mode
	call1 := hybrid.GetOrCreateCall(callID, linkType)
	require.NotNil(t, call1)

	// Switch to lock-free mode
	hybrid.EnableLockFree()
	assert.True(t, hybrid.IsLockFreeEnabled())

	// Operations should work in lock-free mode
	call2, err := hybrid.GetCall(callID)
	require.NoError(t, err)
	assert.Equal(t, callID, call2.CallID)

	// Test port mapping in lock-free mode
	port := "9000"
	hybrid.AddPortMapping(port, callID)
	retrievedCallID, found := hybrid.GetCallIDByPort(port)
	assert.True(t, found)
	assert.Equal(t, callID, retrievedCallID)

	// Switch back to traditional mode
	hybrid.DisableLockFree()
	assert.False(t, hybrid.IsLockFreeEnabled())
}

func TestLockFreeMetrics(t *testing.T) {
	// Reset metrics
	globalLockFreeMetrics = LockFreeMetrics{}

	// Test metric operations
	globalLockFreeMetrics.IncrementReads()
	globalLockFreeMetrics.IncrementWrites()
	globalLockFreeMetrics.IncrementLookupMisses()
	globalLockFreeMetrics.IncrementCreations()
	globalLockFreeMetrics.IncrementCleanups()

	// Test average lookup time
	globalLockFreeMetrics.UpdateAverageLookupTime(1000)
	globalLockFreeMetrics.UpdateAverageLookupTime(2000)

	metrics := globalLockFreeMetrics.GetMetrics()
	assert.Equal(t, int64(1), metrics["reads"])
	assert.Equal(t, int64(1), metrics["writes"])
	assert.Equal(t, int64(1), metrics["lookup_misses"])
	assert.Equal(t, int64(1), metrics["creations"])
	assert.Equal(t, int64(1), metrics["cleanups"])
	assert.Greater(t, metrics["avg_lookup_time"], int64(0))
}

func TestLockFreeCallTracker_ErrorCases(t *testing.T) {
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	// Test getting non-existent call
	_, err := tracker.GetCall("non-existent-call")
	assert.Error(t, err)

	// Test setting state for non-existent call (should not panic)
	tracker.SetCallState("non-existent-call", "SOME_STATE")

	// Test port mapping operations with empty values
	tracker.AddPortMapping("", "")
	_, found := tracker.GetCallIDByPort("")
	assert.True(t, found) // Empty string is a valid key

	tracker.RemovePortMapping("")
	_, found = tracker.GetCallIDByPort("")
	assert.False(t, found)
}

func TestLockFreeOptimizedFunctions(t *testing.T) {
	ResetConfigOnce()

	// Test with lock-free mode disabled
	DisableLockFreeMode()
	assert.False(t, IsLockFreeModeEnabled())

	callID := "optimized-test-call"
	call1 := GetOrCreateCallLockFree(callID, layers.LinkTypeEthernet)
	require.NotNil(t, call1)

	call2, err := GetCallLockFree(callID)
	require.NoError(t, err)
	assert.Equal(t, call1.CallID, call2.CallID)

	// Test with lock-free mode enabled
	EnableLockFreeMode()
	assert.True(t, IsLockFreeModeEnabled())

	callID2 := "optimized-test-call-2"
	call3 := GetOrCreateCallLockFree(callID2, layers.LinkTypeEthernet)
	require.NotNil(t, call3)

	call4, err := GetCallLockFree(callID2)
	require.NoError(t, err)
	assert.Equal(t, call3.CallID, call4.CallID)

	// Test port mapping
	port := "9001"
	AddPortMappingLockFree(port, callID2)

	// Would need to create a test packet to test GetCallIDForPacketLockFree
	// This is more complex and would require packet creation utilities
}

func TestLockFreeCallTracker_StateUpdates(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	callID := "state-update-test"
	call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	require.NotNil(t, call)

	// Test multiple state updates
	states := []string{"RINGING", "ANSWERED", "ACTIVE", "TERMINATED"}
	for _, state := range states {
		tracker.SetCallState(callID, state)

		// Verify state was updated
		updatedCall, err := tracker.GetCall(callID)
		require.NoError(t, err)
		assert.Equal(t, state, updatedCall.State)
	}
}

func TestLockFreeCallTracker_MemoryUsage(t *testing.T) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	// Create many calls to test memory usage
	numCalls := 1000
	for i := 0; i < numCalls; i++ {
		callID := "memory-test-call-" + string(rune(i))
		call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
		require.NotNil(t, call)

		// Add port mapping
		port := string(rune(10000 + i))
		tracker.AddPortMapping(port, callID)
	}

	// Verify all calls exist
	stats := tracker.GetStats()
	assert.Equal(t, int64(numCalls), stats.TotalCalls)
	assert.Equal(t, int64(numCalls), stats.ActiveCalls)

	// Test cleanup
	cleaned := tracker.CleanupExpiredCalls()
	// Since calls are new, none should be cleaned
	assert.Equal(t, 0, cleaned)
}

// Benchmark tests for performance comparison

func BenchmarkLockFreeCallTracker_GetOrCreateCall(b *testing.B) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "bench-call-" + string(rune(i%1000))
		tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}
}

func BenchmarkLockFreeCallTracker_GetCall(b *testing.B) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	// Pre-populate with calls
	for i := 0; i < 1000; i++ {
		callID := "bench-call-" + string(rune(i))
		tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "bench-call-" + string(rune(i%1000))
		tracker.GetCall(callID)
	}
}

func BenchmarkLockFreeCallTracker_PortMapping(b *testing.B) {
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		port := string(rune(8000 + i%1000))
		callID := "bench-call-" + string(rune(i%1000))
		tracker.AddPortMapping(port, callID)
	}
}

func BenchmarkLockFreeCallTracker_ConcurrentOperations(b *testing.B) {
	ResetConfigOnce()
	tracker := NewLockFreeCallTracker()
	defer tracker.Shutdown()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			callID := "concurrent-bench-call-" + string(rune(i%100))
			tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
			tracker.SetCallState(callID, "ACTIVE")
			tracker.GetCall(callID)
			i++
		}
	})
}

func BenchmarkTraditionalCallTracker_GetOrCreateCall(b *testing.B) {
	ResetConfigOnce()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "traditional-bench-call-" + string(rune(i%1000))
		GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}
}

func BenchmarkHybridCallTracker_LockFreeMode(b *testing.B) {
	ResetConfigOnce()
	hybrid := NewHybridCallTracker()
	defer hybrid.Shutdown()
	hybrid.EnableLockFree()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "hybrid-lockfree-bench-call-" + string(rune(i%1000))
		hybrid.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}
}

func BenchmarkHybridCallTracker_TraditionalMode(b *testing.B) {
	ResetConfigOnce()
	hybrid := NewHybridCallTracker()
	defer hybrid.Shutdown()
	hybrid.DisableLockFree()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "hybrid-traditional-bench-call-" + string(rune(i%1000))
		hybrid.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}
}