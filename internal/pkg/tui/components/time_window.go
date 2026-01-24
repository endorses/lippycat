//go:build tui || all

package components

import "time"

// TimeWindow represents a time window for statistics display.
type TimeWindow int

const (
	// TimeWindow1Min shows the last 1 minute of data
	TimeWindow1Min TimeWindow = iota
	// TimeWindow5Min shows the last 5 minutes of data
	TimeWindow5Min
	// TimeWindow15Min shows the last 15 minutes of data
	TimeWindow15Min
	// TimeWindowAll shows all data from session start
	TimeWindowAll
)

// String returns a human-readable label for the time window.
func (tw TimeWindow) String() string {
	switch tw {
	case TimeWindow1Min:
		return "1m"
	case TimeWindow5Min:
		return "5m"
	case TimeWindow15Min:
		return "15m"
	case TimeWindowAll:
		return "All"
	default:
		return "?"
	}
}

// Duration returns the duration for the time window.
// Returns 0 for TimeWindowAll (meaning no limit).
func (tw TimeWindow) Duration() time.Duration {
	switch tw {
	case TimeWindow1Min:
		return 1 * time.Minute
	case TimeWindow5Min:
		return 5 * time.Minute
	case TimeWindow15Min:
		return 15 * time.Minute
	case TimeWindowAll:
		return 0 // No limit
	default:
		return 0
	}
}

// Next cycles to the next time window.
func (tw TimeWindow) Next() TimeWindow {
	switch tw {
	case TimeWindow1Min:
		return TimeWindow5Min
	case TimeWindow5Min:
		return TimeWindow15Min
	case TimeWindow15Min:
		return TimeWindowAll
	case TimeWindowAll:
		return TimeWindow1Min
	default:
		return TimeWindow1Min
	}
}

// AllTimeWindows returns all available time windows for UI rendering.
func AllTimeWindows() []TimeWindow {
	return []TimeWindow{
		TimeWindow1Min,
		TimeWindow5Min,
		TimeWindow15Min,
		TimeWindowAll,
	}
}
