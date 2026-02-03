//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewActiveCallTracker(t *testing.T) {
	t.Run("default capacity", func(t *testing.T) {
		act := NewActiveCallTracker(0)
		assert.Equal(t, 300, act.maxSamples)
		assert.Equal(t, 0, act.count)
	})

	t.Run("custom capacity", func(t *testing.T) {
		act := NewActiveCallTracker(100)
		assert.Equal(t, 100, act.maxSamples)
	})

	t.Run("negative capacity uses default", func(t *testing.T) {
		act := NewActiveCallTracker(-1)
		assert.Equal(t, 300, act.maxSamples)
	})
}

func TestDefaultActiveCallTracker(t *testing.T) {
	act := DefaultActiveCallTracker()
	require.NotNil(t, act)
	assert.Equal(t, 300, act.maxSamples)
}

func TestActiveCallTracker_Record(t *testing.T) {
	t.Run("records samples", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(5)
		act.Record(10)
		act.Record(15)

		assert.Equal(t, 3, act.SampleCount())
	})

	t.Run("ring buffer wraps around", func(t *testing.T) {
		act := NewActiveCallTracker(3)

		act.Record(10)
		act.Record(20)
		act.Record(30)
		act.Record(40) // Overwrites first sample

		assert.Equal(t, 3, act.SampleCount())

		// GetSamples should return oldest to newest: 20, 30, 40
		samples := act.GetSamples(10)
		require.Len(t, samples, 3)
		assert.Equal(t, 20.0, samples[0])
		assert.Equal(t, 30.0, samples[1])
		assert.Equal(t, 40.0, samples[2])
	})
}

func TestActiveCallTracker_GetCurrent(t *testing.T) {
	t.Run("returns 0 when empty", func(t *testing.T) {
		act := NewActiveCallTracker(10)
		assert.Equal(t, 0, act.GetCurrent())
	})

	t.Run("returns most recent sample", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(5)
		act.Record(10)
		act.Record(15)

		assert.Equal(t, 15, act.GetCurrent())
	})
}

func TestActiveCallTracker_GetPeak(t *testing.T) {
	t.Run("returns 0 when empty", func(t *testing.T) {
		act := NewActiveCallTracker(10)
		assert.Equal(t, 0, act.GetPeak())
	})

	t.Run("tracks peak value", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(5)
		act.Record(20)
		act.Record(10)

		assert.Equal(t, 20, act.GetPeak())
	})
}

func TestActiveCallTracker_GetAverage(t *testing.T) {
	t.Run("returns 0 when empty", func(t *testing.T) {
		act := NewActiveCallTracker(10)
		assert.Equal(t, 0.0, act.GetAverage())
	})

	t.Run("calculates correct average", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(10)
		act.Record(20)
		act.Record(30)

		assert.Equal(t, 20.0, act.GetAverage())
	})

	t.Run("handles non-integer average", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(1)
		act.Record(2)
		act.Record(3)
		act.Record(4)

		assert.Equal(t, 2.5, act.GetAverage())
	})
}

func TestActiveCallTracker_GetSamples(t *testing.T) {
	t.Run("returns nil when empty", func(t *testing.T) {
		act := NewActiveCallTracker(10)
		assert.Nil(t, act.GetSamples(10))
	})

	t.Run("returns nil with zero maxPoints", func(t *testing.T) {
		act := NewActiveCallTracker(10)
		act.Record(5)
		assert.Nil(t, act.GetSamples(0))
	})

	t.Run("returns all samples when fewer than maxPoints", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(10)
		act.Record(20)
		act.Record(30)

		samples := act.GetSamples(10)
		require.Len(t, samples, 3)
		assert.Equal(t, []float64{10.0, 20.0, 30.0}, samples)
	})

	t.Run("downsamples when more samples than maxPoints", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		// Record 6 samples
		act.Record(10)
		act.Record(20)
		act.Record(30)
		act.Record(40)
		act.Record(50)
		act.Record(60)

		// Request only 3 points (groups of 2 averaged)
		samples := act.GetSamples(3)
		require.Len(t, samples, 3)
		assert.Equal(t, 15.0, samples[0]) // avg(10, 20)
		assert.Equal(t, 35.0, samples[1]) // avg(30, 40)
		assert.Equal(t, 55.0, samples[2]) // avg(50, 60)
	})
}

func TestActiveCallTracker_Reset(t *testing.T) {
	act := NewActiveCallTracker(10)

	act.Record(5)
	act.Record(15)

	assert.Equal(t, 2, act.SampleCount())
	assert.Equal(t, 15, act.GetPeak())

	act.Reset()

	assert.Equal(t, 0, act.SampleCount())
	assert.Equal(t, 0, act.GetPeak())
	assert.Equal(t, 0, act.GetCurrent())
	assert.Equal(t, 0.0, act.GetAverage())
}

func TestActiveCallTracker_Resize(t *testing.T) {
	t.Run("grow capacity preserves samples", func(t *testing.T) {
		act := NewActiveCallTracker(5)

		act.Record(10)
		act.Record(20)
		act.Record(30)

		act.Resize(10)

		assert.Equal(t, 3, act.SampleCount())
		samples := act.GetSamples(10)
		require.Len(t, samples, 3)
		assert.Equal(t, []float64{10.0, 20.0, 30.0}, samples)
	})

	t.Run("shrink capacity keeps recent samples", func(t *testing.T) {
		act := NewActiveCallTracker(10)

		act.Record(10)
		act.Record(20)
		act.Record(30)
		act.Record(40)
		act.Record(50)

		act.Resize(3)

		assert.Equal(t, 3, act.SampleCount())
		samples := act.GetSamples(10)
		require.Len(t, samples, 3)
		// Should keep most recent: 30, 40, 50
		assert.Equal(t, []float64{30.0, 40.0, 50.0}, samples)
	})
}
