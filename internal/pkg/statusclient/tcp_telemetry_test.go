package statusclient

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHunterToJSONIncludesTCPStreamTelemetry(t *testing.T) {
	got := hunterToJSON(&management.ConnectedHunter{
		Stats: &management.HunterStats{
			TcpEstablishedIdleRetentions: 7,
			TcpPreRearmDiscardedChunks:   11,
			TcpRearmRejectedChunks:       13,
		},
	})

	require.NotNil(t, got.Stats)
	assert.Equal(t, uint64(7), got.Stats.TCPEstablishedIdleRetentions)
	assert.Equal(t, uint64(11), got.Stats.TCPPreRearmDiscardedChunks)
	assert.Equal(t, uint64(13), got.Stats.TCPRearmRejectedChunks)
}
