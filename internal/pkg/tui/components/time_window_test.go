//go:build tui || all

package components

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeWindow_String(t *testing.T) {
	tests := []struct {
		window   TimeWindow
		expected string
	}{
		{TimeWindow1Min, "1m"},
		{TimeWindow5Min, "5m"},
		{TimeWindow15Min, "15m"},
		{TimeWindowAll, "All"},
		{TimeWindow(99), "?"}, // Invalid value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.window.String())
		})
	}
}

func TestTimeWindow_Duration(t *testing.T) {
	tests := []struct {
		window   TimeWindow
		expected time.Duration
	}{
		{TimeWindow1Min, 1 * time.Minute},
		{TimeWindow5Min, 5 * time.Minute},
		{TimeWindow15Min, 15 * time.Minute},
		{TimeWindowAll, 0},  // No limit
		{TimeWindow(99), 0}, // Invalid value returns 0
	}

	for _, tt := range tests {
		t.Run(tt.window.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.window.Duration())
		})
	}
}

func TestTimeWindow_Next(t *testing.T) {
	tests := []struct {
		window   TimeWindow
		expected TimeWindow
	}{
		{TimeWindow1Min, TimeWindow5Min},
		{TimeWindow5Min, TimeWindow15Min},
		{TimeWindow15Min, TimeWindowAll},
		{TimeWindowAll, TimeWindow1Min},  // Wraps around
		{TimeWindow(99), TimeWindow1Min}, // Invalid defaults to 1m
	}

	for _, tt := range tests {
		t.Run(tt.window.String()+"->"+tt.expected.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.window.Next())
		})
	}
}

func TestTimeWindow_CycleComplete(t *testing.T) {
	// Test that cycling through all windows returns to start
	tw := TimeWindow1Min

	tw = tw.Next() // 5m
	assert.Equal(t, TimeWindow5Min, tw)

	tw = tw.Next() // 15m
	assert.Equal(t, TimeWindow15Min, tw)

	tw = tw.Next() // All
	assert.Equal(t, TimeWindowAll, tw)

	tw = tw.Next() // Back to 1m
	assert.Equal(t, TimeWindow1Min, tw)
}

func TestAllTimeWindows(t *testing.T) {
	windows := AllTimeWindows()

	assert.Len(t, windows, 4)
	assert.Equal(t, TimeWindow1Min, windows[0])
	assert.Equal(t, TimeWindow5Min, windows[1])
	assert.Equal(t, TimeWindow15Min, windows[2])
	assert.Equal(t, TimeWindowAll, windows[3])
}
