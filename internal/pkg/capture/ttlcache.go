package capture

import (
	"sync"
	"time"
)

// ttlEntry holds a value with its insertion timestamp.
type ttlEntry[V any] struct {
	value     V
	timestamp time.Time
}

// ttlCache is a simple TTL-based cache with periodic eviction.
// It is safe for concurrent use.
type ttlCache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]ttlEntry[V]
	ttl     time.Duration
}

// newTTLCache creates a cache where entries expire after the given TTL.
func newTTLCache[K comparable, V any](ttl time.Duration) *ttlCache[K, V] {
	return &ttlCache[K, V]{
		entries: make(map[K]ttlEntry[V]),
		ttl:     ttl,
	}
}

// Store adds or updates an entry.
func (c *ttlCache[K, V]) Store(key K, value V) {
	c.mu.Lock()
	c.entries[key] = ttlEntry[V]{value: value, timestamp: time.Now()}
	c.mu.Unlock()
}

// Load retrieves an entry if it exists and is not expired.
func (c *ttlCache[K, V]) Load(key K) (V, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		var zero V
		return zero, false
	}
	if time.Since(entry.timestamp) > c.ttl {
		var zero V
		return zero, false
	}
	return entry.value, true
}

// Sweep removes all entries older than the TTL and returns the count removed.
func (c *ttlCache[K, V]) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	removed := 0
	for k, e := range c.entries {
		if now.Sub(e.timestamp) > c.ttl {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// Len returns the number of entries (including potentially expired ones).
func (c *ttlCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
