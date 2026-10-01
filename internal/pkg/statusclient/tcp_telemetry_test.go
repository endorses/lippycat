package statusclient

import (
	"google.golang.org/protobuf/proto"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHunterToJSONIncludesTCPStreamTelemetry(t *testing.T) {
	original := &management.ConnectedHunter{
		Stats: &management.HunterStats{
			TcpEstablishedIdleRetentions: 7,
			TcpPreRearmDiscardedChunks:   11,
			TcpRearmRejectedChunks:       13,
			TcpRearmKeepaliveChunks:      17,
			TcpOrphanControls:            19,
			TcpAcceptRejectedControls:    23,
			TcpReplacementDroppedBytes:   29,
		},
	}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)
	var decoded management.ConnectedHunter
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	got := hunterToJSON(&decoded)

	require.NotNil(t, got.Stats)
	assert.Equal(t, uint64(7), got.Stats.TCPEstablishedIdleRetentions)
	assert.Equal(t, uint64(11), got.Stats.TCPPreRearmDiscardedChunks)
	assert.Equal(t, uint64(13), got.Stats.TCPRearmRejectedChunks)
	assert.Equal(t, uint64(17), got.Stats.TCPRearmKeepaliveChunks)
	assert.Equal(t, uint64(19), got.Stats.TCPOrphanControls)
	assert.Equal(t, uint64(23), got.Stats.TCPAcceptRejectedControls)
	assert.Equal(t, uint64(29), got.Stats.TCPReplacementDroppedBytes)
}
