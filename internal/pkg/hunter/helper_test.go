package hunter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/stretchr/testify/assert"
)

func TestGetStatsValues(t *testing.T) {
	h := &Hunter{
		statsCollector: stats.New(),
	}

	// Initially all stats should be zero
	captured, matched, forwarded, dropped, bufferBytes := h.GetStatsValues()
	assert.Equal(t, uint64(0), captured)
	assert.Equal(t, uint64(0), matched)
	assert.Equal(t, uint64(0), forwarded)
	assert.Equal(t, uint64(0), dropped)
	assert.Equal(t, uint64(0), bufferBytes)
}
