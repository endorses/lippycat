package detector

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectionCacheBatchEviction(t *testing.T) {
	const capacity = 20
	cache := NewDetectionCacheWithMaxEntries(time.Hour, capacity)
	t.Cleanup(cache.Close)
	result := &signatures.DetectionResult{Protocol: "TEST"}
	base := time.Now()

	for i := range capacity {
		flowID := fmt.Sprintf("flow-%02d", i)
		cache.Set(flowID, result)
		cache.entries[flowID].expiresAt = base.Add(time.Duration(i) * time.Minute)
	}

	cache.Set("newest", result)

	require.Equal(t, capacity-2+1, cache.Size())
	assert.Nil(t, cache.Get("flow-00"))
	assert.Nil(t, cache.Get("flow-01"))
	assert.NotNil(t, cache.Get("flow-02"))
	assert.NotNil(t, cache.Get("newest"))
	assert.Empty(t, cache.evictionScratch)
	for _, candidate := range cache.evictionScratch[:cap(cache.evictionScratch)] {
		assert.Empty(t, candidate.flowID, "scratch storage must not retain removed flow IDs")
		assert.True(t, candidate.expiresAt.IsZero(), "scratch storage must not retain expiration values")
	}
}

func TestDetectionCacheCapWarningRateLimit(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(time.Hour, 10)
	t.Cleanup(cache.Close)
	initial := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)

	cache.mu.Lock()
	assert.True(t, cache.capWarningDueLocked(initial), "initial pressure must be observable")
	assert.False(t, cache.capWarningDueLocked(initial.Add(cacheCapWarningInterval-time.Nanosecond)))
	assert.True(t, cache.capWarningDueLocked(initial.Add(cacheCapWarningInterval)))
	cache.mu.Unlock()
}

func TestDetectionCacheBatchEvictionMaintainsHardCap(t *testing.T) {
	for _, capacity := range []int{1, 2, 5, 9, 20, 100} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			cache := NewDetectionCacheWithMaxEntries(time.Hour, capacity)
			t.Cleanup(cache.Close)
			original := &signatures.DetectionResult{Protocol: "ORIGINAL"}
			updated := &signatures.DetectionResult{Protocol: "UPDATED"}
			base := time.Now()

			for i := 0; i < capacity; i++ {
				flowID := fmt.Sprintf("flow-%03d", i)
				cache.Set(flowID, original)
				cache.mu.Lock()
				cache.entries[flowID].expiresAt = base.Add(time.Duration(i) * time.Second)
				cache.mu.Unlock()
				require.LessOrEqual(t, cache.Size(), capacity)
			}

			// Updating an existing key at the cap must not cause pressure eviction.
			newestID := fmt.Sprintf("flow-%03d", capacity-1)
			cache.Set(newestID, updated)
			require.Equal(t, capacity, cache.Size())
			assert.Same(t, updated, cache.Get(newestID))

			cache.Set("pending", original)
			batchSize := capacity / 10
			if batchSize < 1 {
				batchSize = 1
			}
			wantSize := capacity - batchSize + 1
			assert.Equal(t, wantSize, cache.Size(), "eviction must leave the configured hysteresis")
			assert.NotNil(t, cache.Get("pending"))
			for i := 0; i < batchSize; i++ {
				assert.Nil(t, cache.Get(fmt.Sprintf("flow-%03d", i)), "oldest cache entry %d was retained", i)
			}
			if batchSize < capacity {
				assert.NotNil(t, cache.Get(fmt.Sprintf("flow-%03d", batchSize)))
			}

			for i := 1; i < batchSize; i++ {
				cache.Set(fmt.Sprintf("pending-%03d", i), original)
				require.LessOrEqual(t, cache.Size(), capacity)
			}
			assert.Equal(t, capacity, cache.Size())
		})
	}
}

func TestDetectionCacheDisabledCapDoesNotEvict(t *testing.T) {
	result := &signatures.DetectionResult{Protocol: "TEST"}
	for _, capacity := range []int{0, -1} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			cache := NewDetectionCacheWithMaxEntries(time.Hour, capacity)
			t.Cleanup(cache.Close)

			for i := 0; i < 25; i++ {
				cache.Set(fmt.Sprintf("flow-%03d", i), result)
			}
			assert.Equal(t, 25, cache.Size())
		})
	}
}

func TestDetectionCacheUpdateAtCapDoesNotEvict(t *testing.T) {
	cache := NewDetectionCacheWithMaxEntries(time.Hour, 10)
	t.Cleanup(cache.Close)
	result := &signatures.DetectionResult{Protocol: "TEST"}

	for i := range 10 {
		cache.Set(fmt.Sprintf("flow-%d", i), result)
	}
	cache.Set("flow-0", result)

	assert.Equal(t, 10, cache.Size())
}

func TestDetectionCacheBatchEvictionRecoversFromOversizedMap(t *testing.T) {
	const capacity = 10
	cache := NewDetectionCacheWithMaxEntries(time.Hour, capacity)
	t.Cleanup(cache.Close)
	result := &signatures.DetectionResult{Protocol: "TEST"}

	cache.mu.Lock()
	for i := 0; i < capacity+4; i++ {
		cache.entries[fmt.Sprintf("flow-%d", i)] = &cacheEntry{
			result:    result,
			expiresAt: time.Now().Add(time.Duration(i) * time.Minute),
		}
	}
	cache.mu.Unlock()

	cache.Set("pending", result)

	assert.Equal(t, capacity, cache.Size())
	assert.NotNil(t, cache.Get("pending"))
}
