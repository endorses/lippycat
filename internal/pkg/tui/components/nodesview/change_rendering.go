//go:build tui || all

package nodesview

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// fitCell pads terminal cells, never ANSI bytes or Unicode code points.
func fitCell(value string, width int) string {
	value = TruncateString(value, width)
	return value + strings.Repeat(" ", max(0, width-lipgloss.Width(value)))
}

func metricText(value string, change MetricChange, width int) string {
	marker := " "
	if change.Changed && value != "-" {
		if change.Direction > 0 {
			marker = "↑"
		} else if change.Direction < 0 {
			marker = "↓"
		}
	}
	// Keep the complete value if it fills this column; the cue is optional.
	if lipgloss.Width(value) >= width {
		return fitCell(value, width)
	}
	return fitCell(value, width-1) + marker
}

func changeAccent(value string, changed, selected, quiet bool, theme themes.Theme) string {
	if !changed || quiet {
		return value
	}
	style := lipgloss.NewStyle().Bold(true)
	if selected {
		style = style.Underline(true)
	} else {
		style = style.Background(theme.StatusBarBg).Foreground(theme.Foreground)
	}
	return style.Render(value)
}

func filterText(value uint32, change NodeChanges, width int) string {
	text := fmt.Sprintf("%d", value)
	if change.FiltersChanged {
		delta := fmt.Sprintf(" %+d", change.FilterDelta)
		if lipgloss.Width(text+delta) <= width {
			text += delta
		}
	}
	return fitCell(text, width)
}

func withChangeLabel(value, label string, width int) string {
	if label != "" && lipgloss.Width(value)+lipgloss.Width(label)+1 <= width {
		return value + " " + label
	}
	return TruncateString(value, width)
}

func activityMarker(active bool) string {
	if active {
		return "·"
	}
	return " "
}

func hasNodeAccent(change NodeChanges, quiet bool) bool {
	return !quiet && (change.StatusChanged || change.Label != "" || change.CPU.Changed || change.Memory.Changed || change.FiltersChanged)
}

// Table columns retain cue space even when no change is active. Optional columns
// disappear first on narrow terminals so identity, health and metrics survive.
func nodeTableWidths(width int, flat bool) []int {
	widths := []int{2, 15, 8, 20, 10, 6, 7, 10, 10, 12}
	if flat {
		widths[0], widths[2] = 8, 0
	}
	total := func() int {
		n, columns := 0, 0
		for _, w := range widths {
			if w > 0 {
				n += w
				columns++
			}
		}
		return n + max(0, columns-1)
	}
	for _, column := range []int{3, 4, 2, 8, 7} {
		if total() <= width {
			break
		}
		widths[column] = 0
	}
	if total() > width {
		widths[9] = 7
	}
	if total() > width {
		widths[1] = max(4, widths[1]-(total()-width))
	} else {
		// Give long identities and lifecycle labels room on wide terminals.
		widths[1] += min(17, width-total())
	}
	return widths
}

func nodeTableLine(widths []int, values ...string) string {
	cells := make([]string, 0, len(widths))
	for i, width := range widths {
		if width > 0 {
			cells = append(cells, fitCell(values[i], width))
		}
	}
	return strings.Join(cells, " ")
}

// Unavailable telemetry is distinct from counters whose known value is zero.
func hunterMetricValues(hunter types.HunterInfo, change NodeChanges, filterWidth int) (cpu, memory, captured, forwarded, filters string, visibleChange NodeChanges) {
	visibleChange = change
	if hunter.StatsUnavailable {
		visibleChange.CPU, visibleChange.Memory = MetricChange{}, MetricChange{}
		visibleChange.Activity, visibleChange.FiltersChanged = false, false
		return "-", "-", "-", "-", fitCell("-", filterWidth), visibleChange
	}
	return FormatCPU(hunter.CPUPercent), FormatMemory(hunter.MemoryRSSBytes), FormatPacketNumber(hunter.PacketsCaptured), FormatPacketNumber(hunter.PacketsForwarded), filterText(hunter.ActiveFilters, change, filterWidth), visibleChange
}

// Render the raw status text once: Lip Gloss underline styling splits input by
// rune, so wrapping an already ANSI-colored symbol corrupts its escape codes.
func statusCell(text string, color lipgloss.Color, changed, selected, quiet bool, theme themes.Theme) string {
	style := lipgloss.NewStyle().Foreground(color)
	if changed && !quiet {
		style = style.Bold(true)
		if selected {
			style = style.Underline(true)
		} else {
			style = style.Background(theme.StatusBarBg)
		}
	}
	return style.Render(text)
}

// Inline cell styles end with an ANSI reset. Resume the row's base style after
// each reset so colored health and emphasized cells do not erase selection.
// The supplied style has only text attributes (no width, padding or borders).
func renderTableRow(text string, style lipgloss.Style) string {
	const reset = "\x1b[0m"
	prefix := strings.TrimSuffix(style.Render(""), reset)
	if prefix != "" {
		text = strings.ReplaceAll(text, reset, reset+prefix)
	}
	return style.Render(text)
}
