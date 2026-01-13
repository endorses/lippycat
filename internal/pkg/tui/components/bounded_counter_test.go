//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoundedCounter_BasicIncrement(t *testing.T) {
	bc := NewBoundedCounter(10)

	bc.Increment("foo")
	bc.Increment("foo")
	bc.Increment("bar")

	assert.Equal(t, int64(2), bc.Get("foo"))
	assert.Equal(t, int64(1), bc.Get("bar"))
	assert.Equal(t, int64(0), bc.Get("nonexistent"))
	assert.Equal(t, 2, bc.Len())
}

func TestBoundedCounter_CapacityLimit(t *testing.T) {
	bc := NewBoundedCounter(3)

	// Add 3 items - should all fit
	bc.Increment("a")
	bc.Increment("b")
	bc.Increment("c")

	assert.Equal(t, 3, bc.Len())

	// Add 4th item - should evict lowest count ("a", "b", or "c")
	bc.Increment("d")

	assert.Equal(t, 3, bc.Len(), "should maintain capacity limit")
	assert.Equal(t, int64(1), bc.Get("d"), "new item should be added")
}

func TestBoundedCounter_EvictsLowestCount(t *testing.T) {
	bc := NewBoundedCounter(3)

	// Add items with different counts
	bc.Increment("high")
	bc.Increment("high")
	bc.Increment("high")
	bc.Increment("medium")
	bc.Increment("medium")
	bc.Increment("low")

	assert.Equal(t, 3, bc.Len())

	// Add new item - should evict "low" (count=1)
	bc.Increment("new")

	assert.Equal(t, int64(0), bc.Get("low"), "lowest count item should be evicted")
	assert.Equal(t, int64(3), bc.Get("high"))
	assert.Equal(t, int64(2), bc.Get("medium"))
	assert.Equal(t, int64(1), bc.Get("new"))
}

func TestBoundedCounter_IncrementExistingDoesNotEvict(t *testing.T) {
	bc := NewBoundedCounter(3)

	bc.Increment("a")
	bc.Increment("b")
	bc.Increment("c")

	// Increment existing key when at capacity
	bc.Increment("a")
	bc.Increment("a")

	assert.Equal(t, 3, bc.Len())
	assert.Equal(t, int64(3), bc.Get("a"))
	assert.Equal(t, int64(1), bc.Get("b"))
	assert.Equal(t, int64(1), bc.Get("c"))
}

func TestBoundedCounter_GetAll(t *testing.T) {
	bc := NewBoundedCounter(10)

	bc.Increment("foo")
	bc.Increment("foo")
	bc.Increment("bar")

	all := bc.GetAll()

	assert.Equal(t, int64(2), all["foo"])
	assert.Equal(t, int64(1), all["bar"])
	assert.Equal(t, 2, len(all))

	// Verify it's a copy - modifying result doesn't affect counter
	all["foo"] = 100
	assert.Equal(t, int64(2), bc.Get("foo"))
}

func TestBoundedCounter_GetTopN(t *testing.T) {
	bc := NewBoundedCounter(100)

	// Add items with known counts
	for i := 0; i < 10; i++ {
		bc.Increment("high")
	}
	for i := 0; i < 5; i++ {
		bc.Increment("medium")
	}
	bc.Increment("low")

	// Get top 2
	top2 := bc.GetTopN(2)

	assert.Len(t, top2, 2)
	assert.Equal(t, "high", top2[0].Key)
	assert.Equal(t, int64(10), top2[0].Count)
	assert.Equal(t, "medium", top2[1].Key)
	assert.Equal(t, int64(5), top2[1].Count)

	// Get top 10 (more than available) - should return all 3
	top10 := bc.GetTopN(10)
	assert.Len(t, top10, 3)
}

func TestBoundedCounter_GetTopN_Empty(t *testing.T) {
	bc := NewBoundedCounter(10)

	top5 := bc.GetTopN(5)

	assert.Len(t, top5, 0)
}

func TestBoundedCounter_Clear(t *testing.T) {
	bc := NewBoundedCounter(10)

	bc.Increment("foo")
	bc.Increment("bar")
	assert.Equal(t, 2, bc.Len())

	bc.Clear()

	assert.Equal(t, 0, bc.Len())
	assert.Equal(t, int64(0), bc.Get("foo"))
	assert.Equal(t, int64(0), bc.Get("bar"))
}

func TestBoundedCounter_MaintainsTopItems(t *testing.T) {
	// Simulate realistic usage - tracking top IPs
	bc := NewBoundedCounter(100)

	// Add 150 unique IPs with varying frequencies
	// Top IPs have high counts
	for i := 0; i < 20; i++ {
		for j := 0; j < 100-i*5; j++ {
			bc.Increment(string(rune('A' + i)))
		}
	}

	// Add 130 more unique IPs with low counts
	for i := 0; i < 130; i++ {
		bc.Increment(string(rune('a' + i)))
	}

	// Verify we're at capacity
	assert.Equal(t, 100, bc.Len())

	// Verify top items are preserved
	topItems := bc.GetTopN(10)
	assert.Equal(t, "A", topItems[0].Key)
	assert.Equal(t, int64(100), topItems[0].Count)
	assert.Equal(t, "B", topItems[1].Key)
	assert.Equal(t, int64(95), topItems[1].Count)
}

func TestBoundedCounter_ZeroCapacity(t *testing.T) {
	// Edge case: zero capacity counter
	bc := NewBoundedCounter(0)

	bc.Increment("foo")

	// Should not store anything
	assert.Equal(t, 0, bc.Len())
	assert.Equal(t, int64(0), bc.Get("foo"))
}

func TestBoundedCounter_SingleCapacity(t *testing.T) {
	bc := NewBoundedCounter(1)

	bc.Increment("first")
	assert.Equal(t, 1, bc.Len())
	assert.Equal(t, int64(1), bc.Get("first"))

	// Add second item - should replace first
	bc.Increment("second")
	assert.Equal(t, 1, bc.Len())
	assert.Equal(t, int64(0), bc.Get("first"))
	assert.Equal(t, int64(1), bc.Get("second"))
}
