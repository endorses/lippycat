package detector

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// cacheEntry holds a detection result with expiration
type cacheEntry struct {
	result    *signatures.DetectionResult
	expiresAt time.Time
}

// DetectionCache provides caching for detection results
type DetectionCache struct {
	entries map[string]*cacheEntry
	ttl     time.Duration
	mu      sync.RWMutex
	done    chan struct{}
}

// NewDetectionCache creates a new detection cache
func NewDetectionCache(ttl time.Duration) *DetectionCache {
	cache := &DetectionCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached detection result
func (c *DetectionCache) Get(flowID string) *signatures.DetectionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[flowID]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	return entry.result
}

// Set stores a detection result in cache
func (c *DetectionCache) Set(flowID string, result *signatures.DetectionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[flowID] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes an entry from cache
func (c *DetectionCache) Delete(flowID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, flowID)
}

// Clear removes all entries from cache
func (c *DetectionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
}

// Size returns the number of cached entries
func (c *DetectionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// cleanup periodically removes expired entries
func (c *DetectionCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for flowID, entry := range c.entries {
				if now.After(entry.expiresAt) {
					delete(c.entries, flowID)
				}
			}
			c.mu.Unlock()
		case <-c.done:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (c *DetectionCache) Close() {
	select {
	case <-c.done:
		// Already closed
		return
	default:
		close(c.done)
	}
}
