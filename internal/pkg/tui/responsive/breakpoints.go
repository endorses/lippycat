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

// Dashboard-specific breakpoint thresholds
const (
	// DashboardNarrowMax is the maximum width for narrow dashboard (single column)
	DashboardNarrowMax = 80

	// DashboardMediumMax is the maximum width for medium dashboard (2 columns)
	DashboardMediumMax = 120

	// DashboardWideMin is the minimum width for wide dashboard (optimal 2-column with full content)
	DashboardWideMin = 160
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

// LayoutMode represents the layout mode for dashboard components
type LayoutMode int

const (
	// LayoutNarrow uses single-column layout for narrow terminals
	LayoutNarrow LayoutMode = iota

	// LayoutMedium uses 2-column layout with abbreviated content
	LayoutMedium

	// LayoutWide uses optimal 2-column layout with full content
	LayoutWide
)

// GetLayoutMode returns the appropriate dashboard layout mode for a given width
func GetLayoutMode(width int) LayoutMode {
	switch {
	case width < DashboardNarrowMax:
		return LayoutNarrow
	case width < DashboardMediumMax:
		return LayoutMedium
	default:
		return LayoutWide
	}
}

// String returns a human-readable name for the layout mode
func (l LayoutMode) String() string {
	switch l {
	case LayoutNarrow:
		return "narrow"
	case LayoutMedium:
		return "medium"
	case LayoutWide:
		return "wide"
	default:
		return "unknown"
	}
}
