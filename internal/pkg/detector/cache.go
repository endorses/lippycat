package detector

import (
	"container/heap"
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

type cacheEvictionCandidate struct {
	flowID    string
	expiresAt time.Time
}

// cacheEvictionHeap is a max-heap whose root is the latest-expiring candidate
// among the earliest expirations selected so far.
type cacheEvictionHeap []cacheEvictionCandidate

func (h cacheEvictionHeap) Len() int { return len(h) }
func (h cacheEvictionHeap) Less(i, j int) bool {
	if h[i].expiresAt.Equal(h[j].expiresAt) {
		return h[i].flowID > h[j].flowID
	}
	return h[i].expiresAt.After(h[j].expiresAt)
}
func (h cacheEvictionHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *cacheEvictionHeap) Push(value any) {
	*h = append(*h, value.(cacheEvictionCandidate))
}
func (h *cacheEvictionHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = cacheEvictionCandidate{}
	*h = old[:last]
	return value
}

const cacheCapWarningInterval = time.Minute

// DetectionCache provides caching for detection results
type DetectionCache struct {
	entries        map[string]*cacheEntry
	ttl            time.Duration
	maxEntries     int
	lastCapWarning time.Time
	// evictionScratch is owned by DetectionCache and may only be accessed while
	// mu is write-locked. evictOldestLocked clears it before releasing the lock
	// so removed flow IDs are not retained between pressure episodes.
	evictionScratch []cacheEvictionCandidate
	mu              sync.RWMutex
	done            chan struct{}
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

	now := time.Now()
	if _, exists := c.entries[flowID]; !exists {
		c.evictOldestLocked(now)
	}
	c.entries[flowID] = &cacheEntry{
		result:    result,
		expiresAt: now.Add(c.ttl),
	}
}

func (c *DetectionCache) evictOldestLocked(now time.Time) {
	if c.maxEntries <= 0 || len(c.entries) < c.maxEntries {
		return
	}

	batchSize := c.maxEntries / 10
	if batchSize < 1 {
		batchSize = 1
	}
	// If callers lower the configured cap or otherwise hand us an already
	// oversized map, remove enough entries for the pending insertion too.
	if required := len(c.entries) - c.maxEntries + 1; batchSize < required {
		batchSize = required
	}
	if batchSize > len(c.entries) {
		batchSize = len(c.entries)
	}

	c.evictionScratch = c.evictionScratch[:0]
	for flowID, entry := range c.entries {
		candidate := cacheEvictionCandidate{
			flowID:    flowID,
			expiresAt: entry.expiresAt,
		}
		if len(c.evictionScratch) < batchSize {
			c.evictionScratch = append(c.evictionScratch, candidate)
			if len(c.evictionScratch) == batchSize {
				heap.Init((*cacheEvictionHeap)(&c.evictionScratch))
			}
			continue
		}
		latest := c.evictionScratch[0]
		if candidate.expiresAt.Before(latest.expiresAt) ||
			(candidate.expiresAt.Equal(latest.expiresAt) && candidate.flowID < latest.flowID) {
			c.evictionScratch[0] = candidate
			heap.Fix((*cacheEvictionHeap)(&c.evictionScratch), 0)
		}
	}

	for i := range c.evictionScratch {
		delete(c.entries, c.evictionScratch[i].flowID)
	}
	if c.capWarningDueLocked(now) {
		logger.Warn("Detector cache cap reached, evicting oldest entry batch",
			"max_entries", c.maxEntries,
			"evicted", len(c.evictionScratch))
	}
	clear(c.evictionScratch[:cap(c.evictionScratch)])
	c.evictionScratch = c.evictionScratch[:0]
}

// capWarningDueLocked allows an immediate initial warning and then at most one
// warning per interval while capacity pressure continues. c.mu must be locked.
func (c *DetectionCache) capWarningDueLocked(now time.Time) bool {
	if !c.lastCapWarning.IsZero() && now.Sub(c.lastCapWarning) < cacheCapWarningInterval {
		return false
	}
	c.lastCapWarning = now
	return true
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
