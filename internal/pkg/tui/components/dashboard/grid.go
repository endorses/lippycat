//go:build tui || all

package dashboard

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Grid provides a flexible grid layout for arranging items in columns.
type Grid struct {
	Columns int      // Number of columns
	Gap     int      // Gap between columns in characters
	Items   []string // Pre-rendered items to arrange
}

// GridOption is a functional option for configuring a Grid.
type GridOption func(*Grid)

// WithColumns sets the number of columns.
func WithColumns(cols int) GridOption {
	return func(g *Grid) {
		g.Columns = cols
	}
}

// WithGap sets the gap between columns.
func WithGap(gap int) GridOption {
	return func(g *Grid) {
		g.Gap = gap
	}
}

// NewGrid creates a new Grid with the given items.
func NewGrid(items []string, opts ...GridOption) *Grid {
	g := &Grid{
		Columns: 2,
		Gap:     2,
		Items:   items,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Render arranges items in a grid layout within the given width.
// Items are distributed across columns, with each column getting equal width.
func (g *Grid) Render(width int) string {
	if len(g.Items) == 0 {
		return ""
	}

	if g.Columns <= 0 {
		g.Columns = 2
	}

	// Calculate column width (accounting for gaps)
	totalGapWidth := g.Gap * (g.Columns - 1)
	colWidth := (width - totalGapWidth) / g.Columns

	if colWidth < 10 {
		// Fall back to single column if too narrow
		return strings.Join(g.Items, "\n\n")
	}

	// Arrange items in rows
	var rows []string
	for i := 0; i < len(g.Items); i += g.Columns {
		rowItems := make([]string, 0, g.Columns)

		for j := 0; j < g.Columns && i+j < len(g.Items); j++ {
			item := g.Items[i+j]
			// Constrain item to column width
			itemStyle := lipgloss.NewStyle().Width(colWidth)
			rowItems = append(rowItems, itemStyle.Render(item))
		}

		// Join items horizontally with gap
		row := lipgloss.JoinHorizontal(lipgloss.Top, insertGaps(rowItems, g.Gap)...)
		rows = append(rows, row)
	}

	return strings.Join(rows, "\n")
}

// RenderRow renders a single row of items side-by-side.
// This is a convenience function for simple two-column layouts.
func RenderRow(left, right string, width, gap int) string {
	colWidth := (width - gap) / 2

	leftStyle := lipgloss.NewStyle().Width(colWidth)
	rightStyle := lipgloss.NewStyle().Width(colWidth)

	gapStr := strings.Repeat(" ", gap)

	return leftStyle.Render(left) + gapStr + rightStyle.Render(right)
}

// RenderRowWithWidths renders a row with custom column widths.
func RenderRowWithWidths(items []string, widths []int, gap int) string {
	if len(items) == 0 {
		return ""
	}

	if len(widths) != len(items) {
		// Default to equal widths
		widths = make([]int, len(items))
		for i := range widths {
			widths[i] = 40
		}
	}

	styled := make([]string, len(items))
	for i, item := range items {
		style := lipgloss.NewStyle().Width(widths[i])
		styled[i] = style.Render(item)
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, insertGaps(styled, gap)...)
}

// insertGaps inserts gap spacing between rendered strings.
func insertGaps(items []string, gap int) []string {
	if len(items) <= 1 || gap <= 0 {
		return items
	}

	gapStr := strings.Repeat(" ", gap)
	result := make([]string, 0, len(items)*2-1)

	for i, item := range items {
		result = append(result, item)
		if i < len(items)-1 {
			result = append(result, gapStr)
		}
	}

	return result
}

// ColumnLayout represents a layout with multiple columns of potentially different heights.
// It handles vertical alignment and proper joining.
type ColumnLayout struct {
	Gap int
}

// NewColumnLayout creates a new column layout helper.
func NewColumnLayout(gap int) *ColumnLayout {
	return &ColumnLayout{Gap: gap}
}

// JoinSideBySide joins two multi-line strings side by side.
// Lines are padded to match heights.
func (cl *ColumnLayout) JoinSideBySide(left, right string, leftWidth, rightWidth int) string {
	leftLines := strings.Split(left, "\n")
	rightLines := strings.Split(right, "\n")

	// Determine max lines
	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}

	// Pad shorter side
	for len(leftLines) < maxLines {
		leftLines = append(leftLines, "")
	}
	for len(rightLines) < maxLines {
		rightLines = append(rightLines, "")
	}

	// Build result
	leftStyle := lipgloss.NewStyle().Width(leftWidth)
	rightStyle := lipgloss.NewStyle().Width(rightWidth)
	gapStr := strings.Repeat(" ", cl.Gap)

	var result strings.Builder
	for i := 0; i < maxLines; i++ {
		if i > 0 {
			result.WriteString("\n")
		}
		result.WriteString(leftStyle.Render(leftLines[i]))
		result.WriteString(gapStr)
		result.WriteString(rightStyle.Render(rightLines[i]))
	}

	return result.String()
}
