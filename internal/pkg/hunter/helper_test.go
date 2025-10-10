package hunter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStatsValues(t *testing.T) {
	h := &Hunter{
		stats: Stats{},
	}

	// Set some values
	h.stats.PacketsCaptured.Store(1000)
	h.stats.PacketsMatched.Store(800)
	h.stats.PacketsForwarded.Store(750)
	h.stats.PacketsDropped.Store(50)
	h.stats.BufferBytes.Store(100000)

	captured, matched, forwarded, dropped, bufferBytes := h.GetStatsValues()

	assert.Equal(t, uint64(1000), captured)
	assert.Equal(t, uint64(800), matched)
	assert.Equal(t, uint64(750), forwarded)
	assert.Equal(t, uint64(50), dropped)
	assert.Equal(t, uint64(100000), bufferBytes)
}

func TestCleanup(t *testing.T) {
	h := &Hunter{
		dataConn:       nil, // No actual connection
		managementConn: nil,
		packetBuffer:   nil,
	}

	// Should not panic even with nil connections
	h.cleanup()

	assert.Nil(t, h.dataClient)
	assert.Nil(t, h.mgmtClient)
}
