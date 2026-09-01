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
		},
	}

	payload, err := proto.Marshal(want)
	require.NoError(t, err)

	var got HunterHeartbeat
	require.NoError(t, proto.Unmarshal(payload, &got))
	require.True(t, proto.Equal(want, &got))
	require.Equal(t, got.Stats.PacketsDropped,
		got.Stats.CaptureBufferRegularDrops+got.Stats.CaptureBufferSipDrops+got.Stats.BatchChannelDrops)
}
