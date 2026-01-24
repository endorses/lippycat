//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRateTracker(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		rt := NewRateTracker(0, 0)
		assert.Equal(t, 300, rt.maxSamples)
		assert.Equal(t, time.Second, rt.interval)
	})

	t.Run("custom values", func(t *testing.T) {
		rt := NewRateTracker(100, 500*time.Millisecond)
		assert.Equal(t, 100, rt.maxSamples)
		assert.Equal(t, 500*time.Millisecond, rt.interval)
	})
}

func TestDefaultRateTracker(t *testing.T) {
	rt := DefaultRateTracker()
	require.NotNil(t, rt)
	assert.Equal(t, 300, rt.maxSamples)
	assert.Equal(t, time.Second, rt.interval)
}

func TestRateTracker_Record(t *testing.T) {
	t.Run("first sample sets baseline only", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)
		rt.Record(100, 1000)

		// First sample should not be counted
		assert.Equal(t, 0, rt.SampleCount())
		assert.True(t, rt.started)
	})

	t.Run("second sample creates first rate", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)

		rt.Record(100, 1000)
		time.Sleep(10 * time.Millisecond) // Small delay to ensure elapsed > 0
		rt.Record(200, 2000)

		assert.Equal(t, 1, rt.SampleCount())
	})

	t.Run("ring buffer wraps correctly", func(t *testing.T) {
		rt := NewRateTracker(3, time.Second)

		// Record more samples than capacity
		rt.Record(0, 0)
		for i := 1; i <= 5; i++ {
			time.Sleep(1 * time.Millisecond)
			rt.Record(int64(i*100), int64(i*1000))
		}

		// Should only keep last 3 samples
		assert.Equal(t, 3, rt.SampleCount())
	})
}

func TestRateTracker_GetStats(t *testing.T) {
	t.Run("empty tracker returns zeros", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)
		stats := rt.GetStats()

		assert.Equal(t, float64(0), stats.CurrentPacketsPerSec)
		assert.Equal(t, float64(0), stats.CurrentBytesPerSec)
		assert.Equal(t, float64(0), stats.AvgPacketsPerSec)
		assert.Equal(t, float64(0), stats.AvgBytesPerSec)
		assert.Equal(t, float64(0), stats.PeakPacketsPerSec)
		assert.Equal(t, float64(0), stats.PeakBytesPerSec)
	})

	t.Run("calculates rates correctly", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)

		// Simulate 1 second intervals with known deltas
		rt.lastPackets = 0
		rt.lastBytes = 0
		rt.lastTime = time.Now().Add(-time.Second)
		rt.started = true

		// Record 100 packets and 1000 bytes in 1 second
		rt.Record(100, 1000)

		stats := rt.GetStats()

		// Should be approximately 100 pkt/s and 1000 B/s
		assert.InDelta(t, 100.0, stats.CurrentPacketsPerSec, 10.0)
		assert.InDelta(t, 1000.0, stats.CurrentBytesPerSec, 100.0)
	})

	t.Run("tracks peak correctly", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)

		// Manually set up for consistent testing
		rt.started = true
		rt.lastPackets = 0
		rt.lastBytes = 0
		rt.lastTime = time.Now().Add(-time.Second)

		// High rate
		rt.Record(1000, 10000)

		// Low rate
		rt.lastTime = time.Now().Add(-time.Second)
		rt.Record(1100, 11000)

		stats := rt.GetStats()

		// Peak should be from the first high-rate sample
		assert.InDelta(t, 1000.0, stats.PeakPacketsPerSec, 100.0)
	})
}

func TestRateTracker_GetRatesForWindow(t *testing.T) {
	t.Run("empty tracker returns nil", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)
		rates := rt.GetRatesForWindow(TimeWindow1Min, 10)
		assert.Nil(t, rates)
	})

	t.Run("returns correct number of points", func(t *testing.T) {
		rt := NewRateTracker(60, time.Second) // 1 minute capacity

		// Add baseline
		rt.Record(0, 0)

		// Add 30 samples
		for i := 1; i <= 30; i++ {
			rt.lastTime = time.Now().Add(-time.Second)
			rt.Record(int64(i*100), int64(i*1000))
		}

		// Request 10 points
		rates := rt.GetRatesForWindow(TimeWindow1Min, 10)
		assert.NotNil(t, rates)
		assert.LessOrEqual(t, len(rates), 30) // Won't exceed sample count
	})

	t.Run("zero maxPoints returns nil", func(t *testing.T) {
		rt := NewRateTracker(10, time.Second)
		rt.Record(0, 0)
		rt.lastTime = time.Now().Add(-time.Second)
		rt.Record(100, 1000)

		rates := rt.GetRatesForWindow(TimeWindow1Min, 0)
		assert.Nil(t, rates)
	})
}

func TestRateTracker_SampleCount(t *testing.T) {
	rt := NewRateTracker(5, time.Second)

	assert.Equal(t, 0, rt.SampleCount())

	rt.Record(0, 0)
	assert.Equal(t, 0, rt.SampleCount()) // First sample is baseline only

	rt.lastTime = time.Now().Add(-time.Second)
	rt.Record(100, 1000)
	assert.Equal(t, 1, rt.SampleCount())
}

func TestRateTracker_Reset(t *testing.T) {
	rt := NewRateTracker(10, time.Second)

	// Add some samples
	rt.Record(0, 0)
	rt.lastTime = time.Now().Add(-time.Second)
	rt.Record(100, 1000)
	rt.lastTime = time.Now().Add(-time.Second)
	rt.Record(200, 2000)

	assert.Greater(t, rt.SampleCount(), 0)
	assert.True(t, rt.started)

	// Reset
	rt.Reset()

	assert.Equal(t, 0, rt.SampleCount())
	assert.False(t, rt.started)
	assert.Equal(t, int64(0), rt.lastPackets)
	assert.Equal(t, int64(0), rt.lastBytes)
	assert.Equal(t, float64(0), rt.peakPacketsPerSec)
	assert.Equal(t, float64(0), rt.peakBytesPerSec)
}
