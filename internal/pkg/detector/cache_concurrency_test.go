package detector

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func TestDetectionCacheConcurrentLifecycleOperations(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(5*time.Millisecond, 32)
	t.Cleanup(cache.Close)

	result := &signatures.DetectionResult{
		Protocol:      "test",
		ShouldCache:   true,
		CacheStrategy: signatures.CacheFlow,
	}

	const workers = 8
	const iterations = 250
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				key := fmt.Sprintf("flow-%d", (worker+iteration)%64)
				cache.Set(key, result)
				_ = cache.Get(key)
				if iteration%7 == 0 {
					cache.Delete(key)
				}
				if iteration%61 == 0 {
					cache.Clear()
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	require.LessOrEqual(t, cache.Size(), 32)
}

func TestDetectionCacheCloseIsConcurrentAndIdempotent(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(time.Hour, 16)

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cache.Close()
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-cache.done:
	case <-time.After(time.Second):
		t.Fatal("cache cleanup did not observe Close")
	}
}

func TestDetectionCacheIncrementalCleanupIsBoundedAndConsistent(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(time.Hour, 0)
	t.Cleanup(cache.Close)
	result := &signatures.DetectionResult{Protocol: "test"}

	const entryCount = 25
	for i := 0; i < entryCount; i++ {
		cache.Set(fmt.Sprintf("flow-%02d", i), result)
	}

	cache.mu.Lock()
	for _, entry := range cache.entries {
		entry.expiresAt = time.Time{}
	}
	removed := cache.cleanupExpiredBatchLocked(time.Now(), 7)
	require.Equal(t, 7, removed)
	require.Len(t, cache.entries, entryCount-7)
	require.Len(t, cache.cleanupKeys, entryCount-7)
	require.Len(t, cache.cleanupKeyIndex, entryCount-7)
	for index, flowID := range cache.cleanupKeys {
		require.Equal(t, index, cache.cleanupKeyIndex[flowID])
		require.Contains(t, cache.entries, flowID)
	}
	cache.mu.Unlock()

	for cache.Size() > 0 {
		cache.mu.Lock()
		cache.cleanupExpiredBatchLocked(time.Now(), 7)
		cache.mu.Unlock()
	}
	require.Empty(t, cache.cleanupKeys)
	require.Empty(t, cache.cleanupKeyIndex)
}

func TestDetectionCacheCleanupScheduleTracksAllRemovalPaths(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(time.Hour, 3)
	t.Cleanup(cache.Close)
	result := &signatures.DetectionResult{Protocol: "test"}

	cache.Set("lazy-expiry", result)
	cache.Set("delete", result)
	cache.Set("evict", result)

	cache.mu.Lock()
	cache.entries["lazy-expiry"].expiresAt = time.Time{}
	cache.mu.Unlock()
	require.Nil(t, cache.Get("lazy-expiry"))
	cache.Delete("delete")

	cache.Set("one", result)
	cache.Set("two", result)
	cache.Set("three", result) // Exercises capacity eviction.

	cache.mu.RLock()
	require.Len(t, cache.cleanupKeys, len(cache.entries))
	require.Len(t, cache.cleanupKeyIndex, len(cache.entries))
	for index, flowID := range cache.cleanupKeys {
		require.Equal(t, index, cache.cleanupKeyIndex[flowID])
		require.Contains(t, cache.entries, flowID)
	}
	cache.mu.RUnlock()

	cache.Clear()
	cache.mu.RLock()
	require.Empty(t, cache.entries)
	require.Empty(t, cache.cleanupKeys)
	require.Empty(t, cache.cleanupKeyIndex)
	require.Zero(t, cache.cleanupCursor)
	cache.mu.RUnlock()
}
