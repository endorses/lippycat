//go:build tui || all

package components

import (
	"container/heap"
	"sort"
)

// BoundedCounter maintains counts for a limited number of keys
// When capacity is reached, it evicts the key with the lowest count
// Note: int64 counts ensure consistent behavior across 32-bit and 64-bit platforms
// and prevent overflow for long-running capture sessions.
type BoundedCounter struct {
	counts   map[string]int64
	capacity int

	// Cached TopN results to avoid O(n log n) sort on every call
	cachedTopN []KeyCount
	cacheN     int  // The N value for which cache was computed
	cacheValid bool // Whether cachedTopN is valid
}

// NewBoundedCounter creates a new bounded counter with the specified capacity
func NewBoundedCounter(capacity int) *BoundedCounter {
	return &BoundedCounter{
		counts:   make(map[string]int64, capacity),
		capacity: capacity,
	}
}

// Increment increases the count for the given key
// If capacity is reached, new keys are ignored (O(1) instead of O(n) eviction)
func (bc *BoundedCounter) Increment(key string) {
	// If key already exists, just increment
	if _, exists := bc.counts[key]; exists {
		bc.counts[key]++
		bc.cacheValid = false // Invalidate cache on count change
		return
	}

	// If we haven't reached capacity, add new key
	if len(bc.counts) < bc.capacity {
		bc.counts[key] = 1
		bc.cacheValid = false // Invalidate cache on new key
		return
	}

	// Capacity reached - ignore new keys to avoid O(n) eviction scan
	// For high-traffic capture, we already have the most common keys tracked
}

// Get returns the count for a key (0 if not present)
func (bc *BoundedCounter) Get(key string) int64 {
	return bc.counts[key]
}

// GetAll returns all counts as a map
func (bc *BoundedCounter) GetAll() map[string]int64 {
	// Return a copy to prevent external modification
	result := make(map[string]int64, len(bc.counts))
	for k, v := range bc.counts {
		result[k] = v
	}
	return result
}

// Len returns the number of tracked keys
func (bc *BoundedCounter) Len() int {
	return len(bc.counts)
}

// Clear removes all counts
func (bc *BoundedCounter) Clear() {
	bc.counts = make(map[string]int64, bc.capacity)
	bc.cachedTopN = nil
	bc.cacheN = 0
	bc.cacheValid = false
}

// GetTopN returns the top N keys by count, sorted descending.
// Results are cached and reused if n <= cachedN and cache is valid.
func (bc *BoundedCounter) GetTopN(n int) []KeyCount {
	// Return cached result if valid and sufficient
	if bc.cacheValid && n <= bc.cacheN && len(bc.cachedTopN) >= n {
		return bc.cachedTopN[:n]
	}

	// Use heap-based selection for O(n log k) instead of O(n log n) full sort
	// when n is small relative to total keys
	if n < len(bc.counts)/4 && n > 0 {
		result := bc.getTopNHeap(n)
		// Cache the result
		bc.cachedTopN = result
		bc.cacheN = n
		bc.cacheValid = true
		return result
	}

	// Fall back to full sort when n is large relative to total
	items := make([]KeyCount, 0, len(bc.counts))
	for k, v := range bc.counts {
		items = append(items, KeyCount{Key: k, Count: v})
	}

	// Sort by count descending
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	// Cache the sorted result
	bc.cachedTopN = items
	bc.cacheN = len(items)
	bc.cacheValid = true

	// Return top N
	if n < len(items) {
		return items[:n]
	}
	return items
}

// keyCountHeap is a min-heap of KeyCount for top-N selection
type keyCountHeap []KeyCount

func (h keyCountHeap) Len() int           { return len(h) }
func (h keyCountHeap) Less(i, j int) bool { return h[i].Count < h[j].Count } // Min-heap
func (h keyCountHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *keyCountHeap) Push(x any) {
	*h = append(*h, x.(KeyCount))
}

func (h *keyCountHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// getTopNHeap uses a min-heap to find top N in O(n log k) time
func (bc *BoundedCounter) getTopNHeap(n int) []KeyCount {
	if n <= 0 || len(bc.counts) == 0 {
		return nil
	}

	h := make(keyCountHeap, 0, n+1)
	heap.Init(&h)

	for k, v := range bc.counts {
		if h.Len() < n {
			heap.Push(&h, KeyCount{Key: k, Count: v})
		} else if v > h[0].Count {
			// Replace minimum if this count is larger
			h[0] = KeyCount{Key: k, Count: v}
			heap.Fix(&h, 0)
		}
	}

	// Extract items in descending order
	result := make([]KeyCount, h.Len())
	for i := len(result) - 1; i >= 0; i-- {
		result[i] = heap.Pop(&h).(KeyCount)
	}

	return result
}

// KeyCount represents a key-count pair for sorting
type KeyCount struct {
	Key   string
	Count int64
}
