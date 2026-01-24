//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCPUTracker(t *testing.T) {
	t.Run("default capacity", func(t *testing.T) {
		ct := NewCPUTracker(0)
		assert.Equal(t, 60, ct.maxSamples)
		assert.Equal(t, 0, ct.count)
	})

	t.Run("custom capacity", func(t *testing.T) {
		ct := NewCPUTracker(100)
		assert.Equal(t, 100, ct.maxSamples)
	})

	t.Run("negative capacity uses default", func(t *testing.T) {
		ct := NewCPUTracker(-1)
		assert.Equal(t, 60, ct.maxSamples)
	})
}

func TestDefaultCPUTracker(t *testing.T) {
	ct := DefaultCPUTracker()
	require.NotNil(t, ct)
	assert.Equal(t, 60, ct.maxSamples)
}

func TestCPUTracker_Record(t *testing.T) {
	t.Run("records valid samples", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(25.0)
		ct.Record(50.0)
		ct.Record(75.0)

		assert.Equal(t, 3, ct.SampleCount())
	})

	t.Run("skips negative values", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(25.0)
		ct.Record(-1) // Should be skipped
		ct.Record(50.0)

		assert.Equal(t, 2, ct.SampleCount())
	})

	t.Run("ring buffer wraps around", func(t *testing.T) {
		ct := NewCPUTracker(3)

		ct.Record(10.0)
		ct.Record(20.0)
		ct.Record(30.0)
		ct.Record(40.0) // Overwrites first sample

		assert.Equal(t, 3, ct.SampleCount())

		// GetSamples should return oldest to newest: 20, 30, 40
		samples := ct.GetSamples(10)
		require.Len(t, samples, 3)
		assert.Equal(t, 20.0, samples[0])
		assert.Equal(t, 30.0, samples[1])
		assert.Equal(t, 40.0, samples[2])
	})
}

func TestCPUTracker_GetCurrent(t *testing.T) {
	t.Run("returns -1 when empty", func(t *testing.T) {
		ct := NewCPUTracker(10)
		assert.Equal(t, -1.0, ct.GetCurrent())
	})

	t.Run("returns most recent sample", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(25.0)
		ct.Record(50.0)
		ct.Record(75.0)

		assert.Equal(t, 75.0, ct.GetCurrent())
	})
}

func TestCPUTracker_GetPeak(t *testing.T) {
	t.Run("returns 0 when empty", func(t *testing.T) {
		ct := NewCPUTracker(10)
		assert.Equal(t, 0.0, ct.GetPeak())
	})

	t.Run("tracks peak value", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(25.0)
		ct.Record(75.0)
		ct.Record(50.0)

		assert.Equal(t, 75.0, ct.GetPeak())
	})
}

func TestCPUTracker_GetAverage(t *testing.T) {
	t.Run("returns 0 when empty", func(t *testing.T) {
		ct := NewCPUTracker(10)
		assert.Equal(t, 0.0, ct.GetAverage())
	})

	t.Run("calculates correct average", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(10.0)
		ct.Record(20.0)
		ct.Record(30.0)

		assert.Equal(t, 20.0, ct.GetAverage())
	})
}

func TestCPUTracker_GetSamples(t *testing.T) {
	t.Run("returns nil when empty", func(t *testing.T) {
		ct := NewCPUTracker(10)
		assert.Nil(t, ct.GetSamples(10))
	})

	t.Run("returns nil with zero maxPoints", func(t *testing.T) {
		ct := NewCPUTracker(10)
		ct.Record(50.0)
		assert.Nil(t, ct.GetSamples(0))
	})

	t.Run("returns all samples when fewer than maxPoints", func(t *testing.T) {
		ct := NewCPUTracker(10)

		ct.Record(10.0)
		ct.Record(20.0)
		ct.Record(30.0)

		samples := ct.GetSamples(10)
		require.Len(t, samples, 3)
		assert.Equal(t, []float64{10.0, 20.0, 30.0}, samples)
	})

	t.Run("downsamples when more samples than maxPoints", func(t *testing.T) {
		ct := NewCPUTracker(10)

		// Record 6 samples
		ct.Record(10.0)
		ct.Record(20.0)
		ct.Record(30.0)
		ct.Record(40.0)
		ct.Record(50.0)
		ct.Record(60.0)

		// Request only 3 points (groups of 2 averaged)
		samples := ct.GetSamples(3)
		require.Len(t, samples, 3)
		assert.Equal(t, 15.0, samples[0]) // avg(10, 20)
		assert.Equal(t, 35.0, samples[1]) // avg(30, 40)
		assert.Equal(t, 55.0, samples[2]) // avg(50, 60)
	})
}

func TestCPUTracker_Reset(t *testing.T) {
	ct := NewCPUTracker(10)

	ct.Record(50.0)
	ct.Record(75.0)

	assert.Equal(t, 2, ct.SampleCount())
	assert.Equal(t, 75.0, ct.GetPeak())

	ct.Reset()

	assert.Equal(t, 0, ct.SampleCount())
	assert.Equal(t, 0.0, ct.GetPeak())
	assert.Equal(t, -1.0, ct.GetCurrent())
}
