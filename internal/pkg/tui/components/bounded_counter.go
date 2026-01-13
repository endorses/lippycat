//go:build tui || all

package components

import "sort"

// BoundedCounter maintains counts for a limited number of keys
// When capacity is reached, it evicts the key with the lowest count
// Note: int64 counts ensure consistent behavior across 32-bit and 64-bit platforms
// and prevent overflow for long-running capture sessions.
type BoundedCounter struct {
	counts   map[string]int64
	capacity int
}

// NewBoundedCounter creates a new bounded counter with the specified capacity
func NewBoundedCounter(capacity int) *BoundedCounter {
	return &BoundedCounter{
		counts:   make(map[string]int64, capacity),
		capacity: capacity,
	}
}

// Increment increases the count for the given key
// If capacity is reached, evicts the key with the lowest count
func (bc *BoundedCounter) Increment(key string) {
	// If key already exists, just increment
	if _, exists := bc.counts[key]; exists {
		bc.counts[key]++
		return
	}

	// If we haven't reached capacity, add new key
	if len(bc.counts) < bc.capacity {
		bc.counts[key] = 1
		return
	}

	// Capacity reached - find and evict the key with lowest count
	minKey := ""
	var minCount int64 = 1<<63 - 1 // max int64
	for k, count := range bc.counts {
		if count < minCount {
			minCount = count
			minKey = k
		}
	}

	// Only add new key if it would have higher count than evicted key
	// (start new keys at count 1)
	if minKey != "" {
		delete(bc.counts, minKey)
		bc.counts[key] = 1
	}
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
}

// GetTopN returns the top N keys by count, sorted descending
func (bc *BoundedCounter) GetTopN(n int) []KeyCount {
	// Convert to slice for sorting
	items := make([]KeyCount, 0, len(bc.counts))
	for k, v := range bc.counts {
		items = append(items, KeyCount{Key: k, Count: v})
	}

	// Sort by count descending
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})

	// Return top N
	if n < len(items) {
		return items[:n]
	}
	return items
}

// KeyCount represents a key-count pair for sorting
type KeyCount struct {
	Key   string
	Count int64
}
