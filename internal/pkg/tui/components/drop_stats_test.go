//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDropStats(t *testing.T) {
	ds := NewDropStats()
	require.NotNil(t, ds)

	// All counters should start at zero
	summary := ds.GetSummary()
	assert.Equal(t, int64(0), summary.TotalDrops)
	assert.Equal(t, float64(0), summary.TotalDropRate)
}

func TestDropStats_SetKernelStats(t *testing.T) {
	ds := NewDropStats()
	ds.SetKernelStats(10000, 100)

	summary := ds.GetSummary()
	assert.Equal(t, int64(100), summary.KernelDrops)
	assert.InDelta(t, 1.0, summary.KernelDropRate, 0.01) // 100/10000 = 1%
}

func TestDropStats_BufferDrops(t *testing.T) {
	ds := NewDropStats()
	ds.SetTotalPackets(1000)

	ds.AddBufferDrops(10)
	ds.AddBufferDrops(5)

	summary := ds.GetSummary()
	assert.Equal(t, int64(15), summary.BufferDrops)
	assert.InDelta(t, 1.5, summary.BufferDropRate, 0.01) // 15/1000 = 1.5%

	// Test SetBufferDrops overwrites
	ds.SetBufferDrops(20)
	summary = ds.GetSummary()
	assert.Equal(t, int64(20), summary.BufferDrops)
}

func TestDropStats_QueueDrops(t *testing.T) {
	ds := NewDropStats()
	ds.SetTotalPackets(1000)

	ds.AddQueueDrops(5)
	summary := ds.GetSummary()
	assert.Equal(t, int64(5), summary.QueueDrops)

	ds.SetQueueDrops(10)
	summary = ds.GetSummary()
	assert.Equal(t, int64(10), summary.QueueDrops)
}

func TestDropStats_FilterDrops(t *testing.T) {
	ds := NewDropStats()
	ds.SetFilterDrops(500)

	summary := ds.GetSummary()
	assert.Equal(t, int64(500), summary.FilterDrops)

	// Filter drops should NOT be included in TotalDrops
	assert.Equal(t, int64(0), summary.TotalDrops)
}

func TestDropStats_HunterDrops(t *testing.T) {
	ds := NewDropStats()
	ds.SetTotalPackets(10000)

	ds.SetHunterDrops(50)
	summary := ds.GetSummary()
	assert.Equal(t, int64(50), summary.HunterDrops)

	ds.AddHunterDrops(25)
	summary = ds.GetSummary()
	assert.Equal(t, int64(75), summary.HunterDrops)
	assert.InDelta(t, 0.75, summary.HunterDropRate, 0.01) // 75/10000 = 0.75%
}

func TestDropStats_NetworkDrops(t *testing.T) {
	ds := NewDropStats()
	ds.SetTotalPackets(5000)

	ds.SetNetworkDrops(25)
	summary := ds.GetSummary()
	assert.Equal(t, int64(25), summary.NetworkDrops)
	assert.InDelta(t, 0.5, summary.NetworkDropRate, 0.01) // 25/5000 = 0.5%
}

func TestDropStats_GetSummary(t *testing.T) {
	t.Run("aggregates all drops", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetTotalPackets(10000)

		ds.SetKernelStats(10000, 100)
		ds.SetBufferDrops(50)
		ds.SetQueueDrops(25)
		ds.SetHunterDrops(10)
		ds.SetNetworkDrops(15)
		ds.SetFilterDrops(1000) // Should not be in total

		summary := ds.GetSummary()

		// Total = kernel + buffer + queue + hunter + network (NOT filter)
		expectedTotal := int64(100 + 50 + 25 + 10 + 15)
		assert.Equal(t, expectedTotal, summary.TotalDrops)
		assert.InDelta(t, 2.0, summary.TotalDropRate, 0.01) // 200/10000 = 2%
	})

	t.Run("uses kernel received as fallback base", func(t *testing.T) {
		ds := NewDropStats()
		// No TotalPackets set, but kernel stats set
		ds.SetKernelStats(5000, 50)

		summary := ds.GetSummary()
		// Should use kernel received (5000) as base
		assert.InDelta(t, 1.0, summary.KernelDropRate, 0.01) // 50/5000 = 1%
	})

	t.Run("zero base returns zero rates", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetBufferDrops(100)

		summary := ds.GetSummary()
		assert.Equal(t, int64(100), summary.BufferDrops)
		assert.Equal(t, float64(0), summary.BufferDropRate) // No base to calculate rate
	})
}

func TestDropStats_HasDrops(t *testing.T) {
	t.Run("no drops returns false", func(t *testing.T) {
		ds := NewDropStats()
		assert.False(t, ds.HasDrops())
	})

	t.Run("kernel drops returns true", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetKernelStats(1000, 1)
		assert.True(t, ds.HasDrops())
	})

	t.Run("buffer drops returns true", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetBufferDrops(1)
		assert.True(t, ds.HasDrops())
	})

	t.Run("queue drops returns true", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetQueueDrops(1)
		assert.True(t, ds.HasDrops())
	})

	t.Run("hunter drops returns true", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetHunterDrops(1)
		assert.True(t, ds.HasDrops())
	})

	t.Run("network drops returns true", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetNetworkDrops(1)
		assert.True(t, ds.HasDrops())
	})

	t.Run("filter drops does NOT count as drops", func(t *testing.T) {
		ds := NewDropStats()
		ds.SetFilterDrops(1000)
		assert.False(t, ds.HasDrops()) // Filter drops are intentional
	})
}

func TestDropStats_Reset(t *testing.T) {
	ds := NewDropStats()
	ds.SetKernelStats(1000, 50)
	ds.SetBufferDrops(25)
	ds.SetQueueDrops(10)
	ds.SetFilterDrops(100)
	ds.SetHunterDrops(5)
	ds.SetNetworkDrops(5)
	ds.SetTotalPackets(10000)

	ds.Reset()

	summary := ds.GetSummary()
	assert.Equal(t, int64(0), summary.KernelDrops)
	assert.Equal(t, int64(0), summary.BufferDrops)
	assert.Equal(t, int64(0), summary.QueueDrops)
	assert.Equal(t, int64(0), summary.FilterDrops)
	assert.Equal(t, int64(0), summary.HunterDrops)
	assert.Equal(t, int64(0), summary.NetworkDrops)
	assert.Equal(t, int64(0), summary.TotalDrops)
	assert.False(t, ds.HasDrops())
}

func TestDropStats_UpdateFromBridgeStats(t *testing.T) {
	t.Run("nil bridge stats does nothing", func(t *testing.T) {
		ds := NewDropStats()
		ds.UpdateFromBridgeStats(nil)
		assert.Equal(t, int64(0), ds.GetSummary().BufferDrops)
	})

	t.Run("updates from bridge stats", func(t *testing.T) {
		ds := NewDropStats()
		bs := &BridgeStatistics{
			PacketsReceived: 10000,
			BatchesDropped:  5,
		}

		ds.UpdateFromBridgeStats(bs)

		summary := ds.GetSummary()
		// 5 batches * 100 packets/batch = 500 estimated drops
		assert.Equal(t, int64(500), summary.BufferDrops)
	})
}
