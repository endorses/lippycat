//go:build tui || all

package filters

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNumericComparisonFilter_GreaterThan(t *testing.T) {
	filter, err := NewNumericComparisonFilter("mos", ">3.5")
	require.NoError(t, err)

	// Should match MOS > 3.5
	goodCall := components.Call{
		CallID: "test-call-1",
		MOS:    4.2,
	}
	assert.True(t, filter.Match(goodCall), "Should match MOS > 3.5")

	// Should NOT match MOS <= 3.5
	badCall := components.Call{
		CallID: "test-call-2",
		MOS:    3.0,
	}
	assert.False(t, filter.Match(badCall), "Should NOT match MOS <= 3.5")

	// Edge case: exactly 3.5
	edgeCall := components.Call{
		CallID: "test-call-3",
		MOS:    3.5,
	}
	assert.False(t, filter.Match(edgeCall), "Should NOT match MOS = 3.5 with > operator")
}

func TestNumericComparisonFilter_LessThan(t *testing.T) {
	filter, err := NewNumericComparisonFilter("jitter", "<50")
	require.NoError(t, err)

	// Should match jitter < 50
	goodCall := components.Call{
		CallID: "test-call-1",
		Jitter: 25.0,
	}
	assert.True(t, filter.Match(goodCall), "Should match jitter < 50")

	// Should NOT match jitter >= 50
	badCall := components.Call{
		CallID: "test-call-2",
		Jitter: 75.0,
	}
	assert.False(t, filter.Match(badCall), "Should NOT match jitter >= 50")
}

func TestNumericComparisonFilter_GreaterOrEqual(t *testing.T) {
	filter, err := NewNumericComparisonFilter("loss", ">=5")
	require.NoError(t, err)

	// Should match loss >= 5
	highLoss := components.Call{
		CallID:     "test-call-1",
		PacketLoss: 10.0,
	}
	assert.True(t, filter.Match(highLoss), "Should match loss > 5")

	// Edge case: exactly 5
	edgeCall := components.Call{
		CallID:     "test-call-2",
		PacketLoss: 5.0,
	}
	assert.True(t, filter.Match(edgeCall), "Should match loss = 5 with >= operator")

	// Should NOT match loss < 5
	lowLoss := components.Call{
		CallID:     "test-call-3",
		PacketLoss: 2.0,
	}
	assert.False(t, filter.Match(lowLoss), "Should NOT match loss < 5")
}

func TestNumericComparisonFilter_Equal(t *testing.T) {
	filter, err := NewNumericComparisonFilter("packets", "=100")
	require.NoError(t, err)

	// Should match packets = 100
	exactCall := components.Call{
		CallID:      "test-call-1",
		PacketCount: 100,
	}
	assert.True(t, filter.Match(exactCall), "Should match packets = 100")

	// Should NOT match different packet counts
	differentCall := components.Call{
		CallID:      "test-call-2",
		PacketCount: 150,
	}
	assert.False(t, filter.Match(differentCall), "Should NOT match packets != 100")
}

func TestNumericComparisonFilter_Duration_Seconds(t *testing.T) {
	filter, err := NewNumericComparisonFilter("duration", ">30s")
	require.NoError(t, err)

	// Should match duration > 30s
	longCall := components.Call{
		CallID:   "test-call-1",
		Duration: 60 * time.Second,
	}
	assert.True(t, filter.Match(longCall), "Should match duration > 30s")

	// Should NOT match duration <= 30s
	shortCall := components.Call{
		CallID:   "test-call-2",
		Duration: 15 * time.Second,
	}
	assert.False(t, filter.Match(shortCall), "Should NOT match duration <= 30s")
}

func TestNumericComparisonFilter_Duration_Minutes(t *testing.T) {
	filter, err := NewNumericComparisonFilter("duration", ">5m")
	require.NoError(t, err)

	// Should match duration > 5 minutes
	longCall := components.Call{
		CallID:   "test-call-1",
		Duration: 10 * time.Minute,
	}
	assert.True(t, filter.Match(longCall), "Should match duration > 5m")

	// Should NOT match duration <= 5 minutes
	shortCall := components.Call{
		CallID:   "test-call-2",
		Duration: 3 * time.Minute,
	}
	assert.False(t, filter.Match(shortCall), "Should NOT match duration <= 5m")
}

func TestNumericComparisonFilter_Duration_Complex(t *testing.T) {
	filter, err := NewNumericComparisonFilter("duration", ">1h30m")
	require.NoError(t, err)

	// 1h30m = 5400 seconds
	// Should match duration > 1h30m
	longCall := components.Call{
		CallID:   "test-call-1",
		Duration: 2 * time.Hour,
	}
	assert.True(t, filter.Match(longCall), "Should match duration > 1h30m")

	// Should NOT match duration <= 1h30m
	shortCall := components.Call{
		CallID:   "test-call-2",
		Duration: 1 * time.Hour,
	}
	assert.False(t, filter.Match(shortCall), "Should NOT match duration <= 1h30m")
}

func TestNumericComparisonFilter_String(t *testing.T) {
	filter, err := NewNumericComparisonFilter("duration", ">30s")
	require.NoError(t, err)
	assert.Equal(t, "duration:>30s", filter.String())

	filter2, err := NewNumericComparisonFilter("mos", ">=3.5")
	require.NoError(t, err)
	assert.Equal(t, "mos:>=3.5", filter2.String())
}

func TestNumericComparisonFilter_SupportedRecordTypes(t *testing.T) {
	filter, err := NewNumericComparisonFilter("mos", ">3.5")
	require.NoError(t, err)

	// Should return nil (supports all record types)
	assert.Nil(t, filter.SupportedRecordTypes())
}

func TestNumericComparisonFilter_Selectivity(t *testing.T) {
	// Equality should be most selective
	equalFilter, err := NewNumericComparisonFilter("mos", "=4.0")
	require.NoError(t, err)
	assert.Equal(t, 0.9, equalFilter.Selectivity())

	// Range comparison should be less selective
	rangeFilter, err := NewNumericComparisonFilter("mos", ">3.5")
	require.NoError(t, err)
	assert.Equal(t, 0.7, rangeFilter.Selectivity())
}

func TestNumericComparisonFilter_InvalidOperator(t *testing.T) {
	_, err := NewNumericComparisonFilter("mos", "~3.5")
	assert.Error(t, err, "Should error on invalid operator")
}

func TestNumericComparisonFilter_InvalidValue(t *testing.T) {
	_, err := NewNumericComparisonFilter("mos", ">abc")
	assert.Error(t, err, "Should error on non-numeric value")
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
		hasError bool
	}{
		{"30s", 30, false},
		{"5m", 300, false},
		{"1h", 3600, false},
		{"1h30m", 5400, false},
		{"2h30m15s", 9015, false},
		{"30", 30, false}, // Plain number = seconds
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseDuration(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
