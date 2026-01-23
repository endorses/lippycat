//go:build tui || all

package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeCall(id string, startTime time.Time) components.Call {
	return components.Call{
		CallID:    id,
		From:      "alice@example.com",
		To:        "bob@example.com",
		StartTime: startTime,
		State:     components.CallStateActive,
	}
}

func TestCallStore_AddOrUpdateCall(t *testing.T) {
	store := NewCallStore(100)

	call := makeCall("call-1", time.Now())
	store.AddOrUpdateCall(call)

	assert.Equal(t, 1, store.GetCallCount())
	assert.Equal(t, 1, store.GetTotalCalls())

	retrieved, exists := store.GetCall("call-1")
	require.True(t, exists)
	assert.Equal(t, "call-1", retrieved.CallID)
}

func TestCallStore_AddOrUpdateCalls_Batch(t *testing.T) {
	store := NewCallStore(100)

	calls := make([]components.Call, 50)
	baseTime := time.Now()
	for i := 0; i < 50; i++ {
		calls[i] = makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Second))
	}

	store.AddOrUpdateCalls(calls)

	assert.Equal(t, 50, store.GetCallCount())
	assert.Equal(t, 50, store.GetTotalCalls())
}

func TestCallStore_LRUEviction(t *testing.T) {
	store := NewCallStore(3) // Small capacity

	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-1", baseTime))
	store.AddOrUpdateCall(makeCall("call-2", baseTime.Add(1*time.Second)))
	store.AddOrUpdateCall(makeCall("call-3", baseTime.Add(2*time.Second)))

	assert.Equal(t, 3, store.GetCallCount())

	// Add 4th call - should evict call-1 (oldest in LRU)
	store.AddOrUpdateCall(makeCall("call-4", baseTime.Add(3*time.Second)))

	assert.Equal(t, 3, store.GetCallCount())

	_, exists := store.GetCall("call-1")
	assert.False(t, exists, "call-1 should have been evicted")

	_, exists = store.GetCall("call-4")
	assert.True(t, exists, "call-4 should exist")
}

func TestCallStore_FilteredIndex_Consistency(t *testing.T) {
	store := NewCallStore(100)

	// Add a filter that matches calls with "alice" in From
	store.AddFilter(filters.NewTextFilter("alice", nil))

	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-1", baseTime))
	store.AddOrUpdateCall(makeCall("call-2", baseTime.Add(1*time.Second)))

	// Both calls have "alice" in From, so both should be in filtered list
	filtered := store.GetFilteredCalls()
	assert.Len(t, filtered, 2)

	// Verify index is consistent
	store.mu.RLock()
	for i, call := range store.filteredCalls {
		idx, exists := store.filteredIndex[call.CallID]
		assert.True(t, exists, "call %s should be in index", call.CallID)
		assert.Equal(t, i, idx, "index should match position for call %s", call.CallID)
	}
	store.mu.RUnlock()
}

func TestCallStore_FilteredIndex_RemovalConsistency(t *testing.T) {
	store := NewCallStore(5)

	baseTime := time.Now()
	for i := 0; i < 5; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Second)))
	}

	assert.Equal(t, 5, store.GetFilteredCallCount())

	// Add 6th call - should evict call-0
	store.AddOrUpdateCall(makeCall("call-5", baseTime.Add(5*time.Second)))

	// Verify index is still consistent after eviction
	store.mu.RLock()
	assert.NotContains(t, store.filteredIndex, "call-0", "evicted call should not be in index")
	for i, call := range store.filteredCalls {
		idx, exists := store.filteredIndex[call.CallID]
		assert.True(t, exists, "call %s should be in index", call.CallID)
		assert.Equal(t, i, idx, "index should match position for call %s", call.CallID)
	}
	store.mu.RUnlock()
}

func TestCallStore_FilteredIndex_SwapRemoval(t *testing.T) {
	store := NewCallStore(100)

	// Add filter first so calls are filtered as they come in
	store.AddFilter(filters.NewTextFilter("alice", nil))

	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-A", baseTime))
	store.AddOrUpdateCall(makeCall("call-B", baseTime.Add(1*time.Second)))
	store.AddOrUpdateCall(makeCall("call-C", baseTime.Add(2*time.Second)))

	// All 3 calls should match
	assert.Equal(t, 3, store.GetFilteredCallCount())

	// Update call-B to no longer match the filter
	callB := makeCall("call-B", baseTime.Add(1*time.Second))
	callB.From = "nobody@example.com" // Change From to not match "alice"
	store.AddOrUpdateCall(callB)

	// After update, call-B should be removed via swap-with-last
	assert.Equal(t, 2, store.GetFilteredCallCount())

	store.mu.RLock()
	_, hasB := store.filteredIndex["call-B"]
	store.mu.RUnlock()
	assert.False(t, hasB, "call-B should not be in filtered index after update")

	// Verify remaining index is consistent
	store.mu.RLock()
	for i, call := range store.filteredCalls {
		idx := store.filteredIndex[call.CallID]
		assert.Equal(t, i, idx, "index should match position")
	}
	store.mu.RUnlock()
}

func TestCallStore_Clear_ResetsIndex(t *testing.T) {
	store := NewCallStore(100)

	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-1", baseTime))

	assert.Equal(t, 1, store.GetFilteredCallCount())

	store.Clear()

	assert.Equal(t, 0, store.GetCallCount())
	assert.Equal(t, 0, store.GetFilteredCallCount())

	store.mu.RLock()
	assert.Empty(t, store.filteredIndex)
	store.mu.RUnlock()
}

func TestCallStore_GetCallsInOrder_Caching(t *testing.T) {
	store := NewCallStore(100)

	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-1", baseTime))
	store.AddOrUpdateCall(makeCall("call-2", baseTime.Add(1*time.Second)))
	store.AddOrUpdateCall(makeCall("call-3", baseTime.Add(2*time.Second)))

	// First call builds cache
	calls1 := store.GetCallsInOrder()
	assert.Len(t, calls1, 3)

	// Verify order (sorted by StartTime)
	assert.Equal(t, "call-1", calls1[0].CallID)
	assert.Equal(t, "call-2", calls1[1].CallID)
	assert.Equal(t, "call-3", calls1[2].CallID)

	// Second call should use cache (no mutation between calls)
	store.mu.Lock()
	store.callsDirty = false // Force cache to be used
	cachedLen := len(store.cachedCalls)
	store.mu.Unlock()

	calls2 := store.GetCallsInOrder()
	assert.Len(t, calls2, 3)
	assert.Equal(t, cachedLen, 3)

	// Mutation should invalidate cache
	store.AddOrUpdateCall(makeCall("call-4", baseTime.Add(3*time.Second)))

	store.mu.Lock()
	isDirty := store.callsDirty
	store.mu.Unlock()
	assert.True(t, isDirty, "cache should be dirty after mutation")

	// GetCallsInOrder should rebuild cache
	calls3 := store.GetCallsInOrder()
	assert.Len(t, calls3, 4)

	store.mu.Lock()
	isDirty = store.callsDirty
	store.mu.Unlock()
	assert.False(t, isDirty, "cache should not be dirty after GetCallsInOrder")
}

func TestCallStore_ConcurrentAccess(t *testing.T) {
	store := NewCallStore(1000)
	done := make(chan struct{})

	// Writer goroutine
	go func() {
		baseTime := time.Now()
		for i := 0; i < 1000; i++ {
			store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
		}
		close(done)
	}()

	// Reader goroutines
	for j := 0; j < 4; j++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					store.GetFilteredCalls()
					store.GetCallCount()
				}
			}
		}()
	}

	<-done

	assert.Equal(t, 1000, store.GetCallCount())
}

func TestCallStore_GetFilteredCalls_Sorting(t *testing.T) {
	store := NewCallStore(100)

	// Add calls out of order (newer calls added first)
	baseTime := time.Now()
	store.AddOrUpdateCall(makeCall("call-3", baseTime.Add(3*time.Second))) // Added first but latest
	store.AddOrUpdateCall(makeCall("call-1", baseTime.Add(1*time.Second))) // Earliest
	store.AddOrUpdateCall(makeCall("call-2", baseTime.Add(2*time.Second))) // Middle

	// GetFilteredCalls should return sorted by StartTime
	calls := store.GetFilteredCalls()
	require.Len(t, calls, 3)

	assert.Equal(t, "call-1", calls[0].CallID, "first call should be earliest")
	assert.Equal(t, "call-2", calls[1].CallID, "second call should be middle")
	assert.Equal(t, "call-3", calls[2].CallID, "third call should be latest")

	// Add another call out of order (earlier than all existing)
	store.AddOrUpdateCall(makeCall("call-0", baseTime))

	// Should still be sorted
	calls = store.GetFilteredCalls()
	require.Len(t, calls, 4)

	assert.Equal(t, "call-0", calls[0].CallID, "call-0 should be first after re-sort")
	assert.Equal(t, "call-1", calls[1].CallID)
	assert.Equal(t, "call-2", calls[2].CallID)
	assert.Equal(t, "call-3", calls[3].CallID)
}

func TestCallStore_GetFilteredCalls_SortingWithFilter(t *testing.T) {
	store := NewCallStore(100)

	// Add a filter that only matches calls with "alice" in any field
	// Note: "alice" should not appear in calls we want to filter out
	filter := filters.NewTextFilter("alice", []string{"all"})
	store.AddFilter(filter)

	baseTime := time.Now()
	// Add some calls that match and some that don't, in mixed order
	store.AddOrUpdateCall(components.Call{
		CallID:    "call-3",
		From:      "alice@example.com",
		To:        "bob@example.com",
		StartTime: baseTime.Add(3 * time.Second),
		State:     components.CallStateActive,
	})
	store.AddOrUpdateCall(components.Call{
		CallID:    "call-1",
		From:      "alice@example.com",
		To:        "bob@example.com",
		StartTime: baseTime.Add(1 * time.Second),
		State:     components.CallStateActive,
	})
	store.AddOrUpdateCall(components.Call{
		CallID:    "call-skip",
		From:      "charlie@example.com", // Doesn't match filter (no "alice" anywhere)
		To:        "dave@example.com",
		StartTime: baseTime.Add(2 * time.Second),
		State:     components.CallStateActive,
	})
	store.AddOrUpdateCall(components.Call{
		CallID:    "call-2",
		From:      "alice@example.com",
		To:        "bob@example.com",
		StartTime: baseTime.Add(2 * time.Second),
		State:     components.CallStateActive,
	})

	// GetFilteredCalls should return only matching calls, sorted
	calls := store.GetFilteredCalls()
	require.Len(t, calls, 3, "should have 3 matching calls")

	assert.Equal(t, "call-1", calls[0].CallID, "first call should be earliest matching")
	assert.Equal(t, "call-2", calls[1].CallID, "second call should be middle")
	assert.Equal(t, "call-3", calls[2].CallID, "third call should be latest")
}

// Benchmarks

func BenchmarkCallStore_AddOrUpdateCall(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	// Pre-populate
	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Update existing call
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i%5000), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}
}

func BenchmarkCallStore_AddOrUpdateCalls_Batch(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	// Pre-populate
	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	// Create batch of 100 calls
	batch := make([]components.Call, 100)
	for i := 0; i < 100; i++ {
		batch[i] = makeCall(fmt.Sprintf("call-%d", i), baseTime)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.AddOrUpdateCalls(batch)
	}
}

func BenchmarkCallStore_FilteredRemoval(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	// Pre-populate with filter active
	store.AddFilter(filters.NewTextFilter("alice", nil))

	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Trigger eviction by adding new call (will remove from filtered via index)
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("new-call-%d", i), baseTime.Add(time.Duration(i)*time.Hour)))
	}
}

func BenchmarkCallStore_GetFilteredCalls(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.GetFilteredCalls()
	}
}

func BenchmarkCallStore_GetCallsInOrder_Cached(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	// First call builds cache
	_ = store.GetCallsInOrder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Subsequent calls use cache (no mutations between calls)
		_ = store.GetCallsInOrder()
	}
}

func BenchmarkCallStore_GetCallsInOrder_Uncached(b *testing.B) {
	store := NewCallStore(5000)
	baseTime := time.Now()

	for i := 0; i < 5000; i++ {
		store.AddOrUpdateCall(makeCall(fmt.Sprintf("call-%d", i), baseTime.Add(time.Duration(i)*time.Millisecond)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force cache invalidation before each call
		store.mu.Lock()
		store.callsDirty = true
		store.mu.Unlock()

		_ = store.GetCallsInOrder()
	}
}
