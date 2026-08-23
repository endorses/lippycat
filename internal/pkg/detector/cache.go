package detector

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/viper"
)

// cacheEntry holds a detection result with expiration
type cacheEntry struct {
	result    *signatures.DetectionResult
	expiresAt time.Time
}

// DetectionCache provides caching for detection results
type DetectionCache struct {
	entries    map[string]*cacheEntry
	ttl        time.Duration
	maxEntries int
	capWarned  bool
	mu         sync.RWMutex
	done       chan struct{}
}

// NewDetectionCache creates a new detection cache
func NewDetectionCache(ttl time.Duration) *DetectionCache {
	return NewDetectionCacheWithMaxEntries(ttl, viper.GetInt("detector.max_cache_entries"))
}

// NewDetectionCacheWithMaxEntries creates a new detection cache with a hard
// entry cap. A maxEntries value of zero or less disables cap-based eviction.
func NewDetectionCacheWithMaxEntries(ttl time.Duration, maxEntries int) *DetectionCache {
	cache := &DetectionCache{
		entries:    make(map[string]*cacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		done:       make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Get retrieves a cached detection result
func (c *DetectionCache) Get(flowID string) *signatures.DetectionResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[flowID]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, flowID)
		return nil
	}

	return entry.result
}

// Set stores a detection result in cache
func (c *DetectionCache) Set(flowID string, result *signatures.DetectionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[flowID]; !exists {
		c.evictOldestLocked()
	}
	c.entries[flowID] = &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *DetectionCache) evictOldestLocked() {
	if c.maxEntries <= 0 || len(c.entries) < c.maxEntries {
		return
	}

	var oldestFlowID string
	var oldestExpiresAt time.Time
	for flowID, entry := range c.entries {
		if oldestFlowID == "" || entry.expiresAt.Before(oldestExpiresAt) {
			oldestFlowID = flowID
			oldestExpiresAt = entry.expiresAt
		}
	}
	if oldestFlowID == "" {
		return
	}

	delete(c.entries, oldestFlowID)
	if !c.capWarned {
		logger.Warn("Detector cache cap reached, evicting oldest entry",
			"max_entries", c.maxEntries)
		c.capWarned = true
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
