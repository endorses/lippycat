package detector

import (
	"container/heap"
	"sync"
	"sync/atomic"
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

const (
	cacheCapWarningInterval = time.Minute
	cacheCleanupInterval    = 100 * time.Millisecond
	cacheCleanupBatchSize   = 1024
)

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
	// cleanupKeys and cleanupKeyIndex provide a stable, incrementally scanned
	// schedule. They are kept in sync with entries while mu is write-locked so a
	// cleanup tick never needs to scan the complete cache under one lock hold.
	cleanupKeys            []string
	cleanupKeyIndex        map[string]int
	cleanupCursor          int
	mu                     sync.RWMutex
	done                   chan struct{}
	closeOnce              sync.Once
	cleanupWG              sync.WaitGroup
	totalEvictions         atomic.Uint64
	expiredRemovals        atomic.Uint64
	pressureEpisodes       atomic.Uint64
	lastEvictionDurationNs atomic.Uint64
	lastEvictionBatchSize  atomic.Uint64
}

// NewDetectionCache creates a new detection cache
func NewDetectionCache(ttl time.Duration) *DetectionCache {
	return NewDetectionCacheWithMaxEntries(ttl, viper.GetInt("detector.max_cache_entries"))
}

// NewDetectionCacheWithMaxEntries creates a new detection cache with a hard
// entry cap. A maxEntries value of zero or less disables cap-based eviction.
func NewDetectionCacheWithMaxEntries(ttl time.Duration, maxEntries int) *DetectionCache {
	cache := &DetectionCache{
		entries:         make(map[string]*cacheEntry),
		cleanupKeyIndex: make(map[string]int),
		ttl:             ttl,
		maxEntries:      maxEntries,
		done:            make(chan struct{}),
	}

	// Start cleanup goroutine
	cache.cleanupWG.Add(1)
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
		c.removeLocked(flowID)
		c.expiredRemovals.Add(1)
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
		c.addCleanupKeyLocked(flowID)
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
	started := time.Now()
	c.pressureEpisodes.Add(1)

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
		c.removeLocked(c.evictionScratch[i].flowID)
	}
	evicted := len(c.evictionScratch)
	c.totalEvictions.Add(uint64(evicted))
	if c.capWarningDueLocked(now) {
		logger.Warn("Detector cache cap reached, evicting oldest entry batch",
			"max_entries", c.maxEntries,
			"evicted", len(c.evictionScratch))
	}
	clear(c.evictionScratch[:cap(c.evictionScratch)])
	c.evictionScratch = c.evictionScratch[:0]
	c.lastEvictionBatchSize.Store(uint64(evicted))
	c.lastEvictionDurationNs.Store(uint64(time.Since(started).Nanoseconds()))
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

	c.removeLocked(flowID)
}

// Clear removes all entries from cache
func (c *DetectionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
	c.cleanupKeys = nil
	c.cleanupKeyIndex = make(map[string]int)
	c.cleanupCursor = 0
}

// Size returns the number of cached entries
func (c *DetectionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// cleanup periodically removes expired entries
func (c *DetectionCache) cleanup() {
	defer c.cleanupWG.Done()
	ticker := time.NewTicker(cacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.cleanupExpiredBatchLocked(time.Now(), cacheCleanupBatchSize)
			c.mu.Unlock()
		case <-c.done:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (c *DetectionCache) Close() {
	c.closeOnce.Do(func() { close(c.done) })
	c.cleanupWG.Wait()
}

// cleanupExpiredBatchLocked examines at most limit scheduled entries. Keeping
// the unit of work fixed bounds an individual cleanup lock hold independently
// of cache cardinality. c.mu must be write-locked.
func (c *DetectionCache) cleanupExpiredBatchLocked(now time.Time, limit int) int {
	if limit <= 0 || len(c.cleanupKeys) == 0 {
		return 0
	}

	removed := 0
	for inspected := 0; inspected < limit && len(c.cleanupKeys) > 0; inspected++ {
		if c.cleanupCursor >= len(c.cleanupKeys) {
			c.cleanupCursor = 0
		}
		flowID := c.cleanupKeys[c.cleanupCursor]
		entry, exists := c.entries[flowID]
		if !exists || now.After(entry.expiresAt) {
			c.removeLocked(flowID)
			if exists {
				removed++
			}
			continue
		}
		c.cleanupCursor++
	}
	c.expiredRemovals.Add(uint64(removed))
	return removed
}

func (c *DetectionCache) addCleanupKeyLocked(flowID string) {
	if _, exists := c.cleanupKeyIndex[flowID]; exists {
		return
	}
	c.cleanupKeyIndex[flowID] = len(c.cleanupKeys)
	c.cleanupKeys = append(c.cleanupKeys, flowID)
}

// removeLocked removes an entry and its cleanup schedule in constant time.
// c.mu must be write-locked.
func (c *DetectionCache) removeLocked(flowID string) {
	delete(c.entries, flowID)
	index, scheduled := c.cleanupKeyIndex[flowID]
	if !scheduled {
		return
	}

	last := len(c.cleanupKeys) - 1
	lastFlowID := c.cleanupKeys[last]
	c.cleanupKeys[index] = lastFlowID
	c.cleanupKeyIndex[lastFlowID] = index
	c.cleanupKeys[last] = ""
	c.cleanupKeys = c.cleanupKeys[:last]
	delete(c.cleanupKeyIndex, flowID)

	if len(c.cleanupKeys) == 0 {
		c.cleanupCursor = 0
		return
	}
	if index < c.cleanupCursor {
		c.cleanupCursor--
	}
	if c.cleanupCursor >= len(c.cleanupKeys) {
		c.cleanupCursor = 0
	}
}
