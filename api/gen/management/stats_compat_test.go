package management

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestHunterStatsNamedLossCountersWireRoundTrip(t *testing.T) {
	want := &HunterHeartbeat{
		HunterId: "hunter-test",
		Stats: &HunterStats{
			PacketsDropped:            9,
			CaptureBufferRegularDrops: 4,
			CaptureBufferSipDrops:     2,
			BatchChannelDrops:         3,
			CaptureBufferSipDemotions: 5,
			CaptureBufferRegularLen:   6, CaptureBufferRegularCapacity: 16,
			CaptureBufferSipLen: 7, CaptureBufferSipCapacity: 17,
			CaptureBufferOutputLen: 8, CaptureBufferOutputCapacity: 18,
		},
	}

	payload, err := proto.Marshal(want)
	require.NoError(t, err)

	var got HunterHeartbeat
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.True(t, proto.Equal(want, &got))
	require.Equal(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops)
	require.NotEqual(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops+got.Stats.CaptureBufferSipDemotions)
}

func TestHunterStatsLegacyPayloadDefaultsPriorityPressureToZero(t *testing.T) {
	legacyPayload, err := proto.Marshal(&HunterHeartbeat{Stats: &HunterStats{
		PacketsDropped: 3, CaptureBufferRegularDrops: 1, CaptureBufferSipDrops: 1, BatchChannelDrops: 1,
	}})
	require.NoError(t, err)

	var got HunterHeartbeat
	require.NoError(t, proto.Unmarshal(legacyPayload, &got))
	require.Zero(t, got.Stats.CaptureBufferSipDemotions)
	require.Zero(t, got.Stats.CaptureBufferRegularLen)
	require.Zero(t, got.Stats.CaptureBufferRegularCapacity)
	require.Zero(t, got.Stats.CaptureBufferSipLen)
	require.Zero(t, got.Stats.CaptureBufferSipCapacity)
	require.Zero(t, got.Stats.CaptureBufferOutputLen)
	require.Zero(t, got.Stats.CaptureBufferOutputCapacity)
}
