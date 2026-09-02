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
	for _, capacity := range []int{1, 2, 9, 10, 100} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			cache := NewDetectionCacheWithMaxEntries(time.Hour, capacity)
			t.Cleanup(cache.Close)
			result := &signatures.DetectionResult{Protocol: "TEST"}

			for i := 0; i < capacity*3; i++ {
				cache.Set(fmt.Sprintf("flow-%d", i), result)
				require.LessOrEqual(t, cache.Size(), capacity)
			}
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
