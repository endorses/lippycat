//go:build tui || all

// Package responsive provides utilities for responsive TUI layouts.
package responsive

// Breakpoint thresholds for responsive layouts
const (
	// NarrowMaxWidth is the maximum width for narrow layout (icons only, minimal text)
	NarrowMaxWidth = 79

	// MediumMaxWidth is the maximum width for medium layout (abbreviated labels)
	MediumMaxWidth = 119

	// Wide layout is used for widths >= 120 (full labels and content)
)

// WidthClass represents the responsive width category
type WidthClass int

const (
	// Narrow is for terminals < 80 chars (minimal display, icons/abbreviations)
	Narrow WidthClass = iota

	// Medium is for terminals 80-119 chars (abbreviated labels)
	Medium

	// Wide is for terminals >= 120 chars (full display)
	Wide
)

// GetWidthClass returns the width class for a given terminal width
func GetWidthClass(width int) WidthClass {
	switch {
	case width <= NarrowMaxWidth:
		return Narrow
	case width <= MediumMaxWidth:
		return Medium
	default:
		return Wide
	}
}

// String returns a human-readable name for the width class
func (w WidthClass) String() string {
	switch w {
	case Narrow:
		return "narrow"
	case Medium:
		return "medium"
	case Wide:
		return "wide"
	default:
		return "unknown"
	}
}
