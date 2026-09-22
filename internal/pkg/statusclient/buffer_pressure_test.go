package statusclient

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestHunterToJSONIncludesCaptureBufferPressure(t *testing.T) {
	got := hunterToJSON(&management.ConnectedHunter{Stats: &management.HunterStats{
		PacketsDropped: 6, CaptureBufferRegularDrops: 2, CaptureBufferSipDrops: 1, BatchChannelDrops: 3,
		CaptureBufferSipDemotions: 5,
		CaptureBufferRegularLen:   6, CaptureBufferRegularCapacity: 16,
		CaptureBufferSipLen: 7, CaptureBufferSipCapacity: 17,
		CaptureBufferOutputLen: 8, CaptureBufferOutputCapacity: 18,
	}})

	require.Equal(t, uint64(6), got.Stats.PacketsDropped)
	require.Equal(t, uint64(5), got.Stats.CaptureBufferSIPDemotions)
	require.Equal(t, uint64(6), got.Stats.CaptureBufferRegularLen)
	require.Equal(t, uint64(16), got.Stats.CaptureBufferRegularCapacity)
	require.Equal(t, uint64(7), got.Stats.CaptureBufferSIPLen)
	require.Equal(t, uint64(17), got.Stats.CaptureBufferSIPCapacity)
	require.Equal(t, uint64(8), got.Stats.CaptureBufferOutputLen)
	require.Equal(t, uint64(18), got.Stats.CaptureBufferOutputCapacity)
	require.Equal(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSIPDrops+got.Stats.BatchChannelDrops)
}
