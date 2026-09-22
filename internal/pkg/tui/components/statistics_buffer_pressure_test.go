//go:build tui || all

package components

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDistributedStatsKeepSIPDemotionsOutOfLoss(t *testing.T) {
	view := NewStatisticsView()
	view.UpdateDistributedStats([]HunterInfo{{
		ID: "synthetic-hunter", PacketsCaptured: 100, PacketsDropped: 6,
		CaptureBufferRegularDrops: 2, CaptureBufferSIPDrops: 1, BatchChannelDrops: 3,
		CaptureBufferSIPDemotions: 9,
		CaptureBufferRegularLen:   4, CaptureBufferRegularCapacity: 14,
		CaptureBufferSIPLen: 5, CaptureBufferSIPCapacity: 15,
		CaptureBufferOutputLen: 6, CaptureBufferOutputCapacity: 16,
	}}, nil)

	stats := view.GetDistributedStats()
	require.Equal(t, uint64(6), stats.TotalPacketsDropped)
	require.Equal(t, uint64(9), stats.TotalSIPDemotions)
	require.Len(t, stats.HunterContributions, 1)
	contribution := stats.HunterContributions[0]
	require.Equal(t, uint64(9), contribution.CaptureBufferSIPDemotions)
	require.Equal(t, uint64(4), contribution.CaptureBufferRegularLen)
	require.Equal(t, uint64(14), contribution.CaptureBufferRegularCapacity)
	require.Equal(t, uint64(5), contribution.CaptureBufferSIPLen)
	require.Equal(t, uint64(15), contribution.CaptureBufferSIPCapacity)
	require.Equal(t, uint64(6), contribution.CaptureBufferOutputLen)
	require.Equal(t, uint64(16), contribution.CaptureBufferOutputCapacity)
}
