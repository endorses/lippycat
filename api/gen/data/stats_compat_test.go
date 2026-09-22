package data

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBatchStatsPriorityPressureWireRoundTrip(t *testing.T) {
	want := &PacketBatch{Stats: &BatchStats{
		Dropped: 6, CaptureBufferRegularDrops: 2, CaptureBufferSipDrops: 1, BatchChannelDrops: 3,
		CaptureBufferSipDemotions: 5,
		CaptureBufferRegularLen:   6, CaptureBufferRegularCapacity: 16,
		CaptureBufferSipLen: 7, CaptureBufferSipCapacity: 17,
		CaptureBufferOutputLen: 8, CaptureBufferOutputCapacity: 18,
	}}
	payload, err := proto.Marshal(want)
	require.NoError(t, err)

	var got PacketBatch
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.True(t, proto.Equal(want, &got))
	require.Equal(t, got.Stats.Dropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops)
}

func TestBatchStatsLegacyPayloadDefaultsPriorityPressureToZero(t *testing.T) {
	payload, err := proto.Marshal(&PacketBatch{Stats: &BatchStats{Dropped: 1, CaptureBufferRegularDrops: 1}})
	require.NoError(t, err)

	var got PacketBatch
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.Zero(t, got.Stats.CaptureBufferSipDemotions)
	require.Zero(t, got.Stats.CaptureBufferRegularLen)
	require.Zero(t, got.Stats.CaptureBufferRegularCapacity)
	require.Zero(t, got.Stats.CaptureBufferSipLen)
	require.Zero(t, got.Stats.CaptureBufferSipCapacity)
	require.Zero(t, got.Stats.CaptureBufferOutputLen)
	require.Zero(t, got.Stats.CaptureBufferOutputCapacity)
}
