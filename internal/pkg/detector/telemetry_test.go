package detector

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func TestDetectorTelemetryPressureSnapshotsAreCumulative(t *testing.T) {
	d := &Detector{
		cache: NewDetectionCacheWithMaxEntries(time.Hour, 2),
		flows: NewFlowTrackerWithMaxEntries(time.Hour, 2),
	}
	t.Cleanup(d.cache.Close)
	t.Cleanup(d.flows.Close)

	result := &signatures.DetectionResult{Protocol: "test"}
	for _, id := range []string{"one", "two", "three", "four"} {
		d.cache.Set(id, result)
		d.flows.GetOrCreate(id)
	}

	got := d.Telemetry()
	require.Equal(t, uint64(2), got.FlowEntries)
	require.Equal(t, uint64(2), got.CacheEntries)
	require.Equal(t, uint64(2), got.FlowEvictions)
	require.Equal(t, uint64(2), got.CacheEvictions)
	require.Equal(t, uint64(2), got.FlowPressureEpisodes)
	require.Equal(t, uint64(2), got.CachePressureEpisodes)
	require.Equal(t, uint64(1), got.FlowLastEvictionBatchSize)
	require.Equal(t, uint64(1), got.CacheLastEvictionBatchSize)
	require.NotZero(t, got.FlowLastEvictionDurationNs)
	require.NotZero(t, got.CacheLastEvictionDurationNs)

	// Reading telemetry is non-destructive: heartbeats carry snapshots rather
	// than deltas and receivers must not add repeated reports.
	require.Equal(t, got, d.Telemetry())
}

func TestDetectorTelemetryExpiredRemovalSources(t *testing.T) {
	d := &Detector{
		cache: NewDetectionCacheWithMaxEntries(time.Hour, 0),
		flows: NewFlowTrackerWithMaxEntries(-time.Second, 0),
	}
	t.Cleanup(d.cache.Close)
	t.Cleanup(d.flows.Close)

	now := time.Now()
	d.cache.Set("read-expired", &signatures.DetectionResult{})
	d.cache.entries["read-expired"].expiresAt = now.Add(-time.Second)
	require.Nil(t, d.cache.Get("read-expired"))
	d.cache.Set("sweep-expired", &signatures.DetectionResult{})
	d.cache.entries["sweep-expired"].expiresAt = now.Add(-time.Second)
	d.cache.mu.Lock()
	d.cache.cleanupExpiredBatchLocked(now, 10)
	d.cache.mu.Unlock()

	d.flows.GetOrCreate("expired-flow")
	d.flows.cleanupExpired(now, 10)

	got := d.Telemetry()
	require.Equal(t, uint64(2), got.CacheExpiredRemovals)
	require.Equal(t, uint64(1), got.FlowExpiredRemovals)
	require.Zero(t, got.FlowEntries)
	require.Zero(t, got.CacheEntries)
	require.Zero(t, got.FlowEvictions)
	require.Zero(t, got.CacheEvictions)
}

func TestClearDoesNotResetDetectorTelemetryCounters(t *testing.T) {
	d := &Detector{
		cache: NewDetectionCacheWithMaxEntries(time.Hour, 1),
		flows: NewFlowTrackerWithMaxEntries(time.Hour, 1),
	}
	t.Cleanup(d.cache.Close)
	t.Cleanup(d.flows.Close)

	d.cache.Set("one", &signatures.DetectionResult{})
	d.cache.Set("two", &signatures.DetectionResult{})
	d.flows.GetOrCreate("one")
	d.flows.GetOrCreate("two")
	d.cache.Clear()
	d.flows.Clear()

	got := d.Telemetry()
	require.Zero(t, got.FlowEntries)
	require.Zero(t, got.CacheEntries)
	require.Equal(t, uint64(1), got.FlowEvictions)
	require.Equal(t, uint64(1), got.CacheEvictions)
	require.Equal(t, uint64(1), got.FlowPressureEpisodes)
	require.Equal(t, uint64(1), got.CachePressureEpisodes)
}
