//go:build tui || all

package dashboard

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// StatBox represents a compact stat display with a value and label.
// Used for displaying metrics like "17,487 packets" or "12.0 MB bytes".
type StatBox struct {
	Value string       // The primary value to display
	Label string       // Descriptive label below the value
	Width int          // Box width (0 = auto based on content)
	theme themes.Theme // Theme for styling
}

// StatBoxOption is a functional option for configuring a StatBox.
type StatBoxOption func(*StatBox)

// WithStatBoxWidth sets the stat box width.
func WithStatBoxWidth(width int) StatBoxOption {
	return func(s *StatBox) {
		s.Width = width
	}
}

// NewStatBox creates a new StatBox with the given value and label.
func NewStatBox(value, label string, theme themes.Theme, opts ...StatBoxOption) *StatBox {
	s := &StatBox{
		Value: value,
		Label: label,
		theme: theme,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// SetTheme updates the stat box theme.
func (s *StatBox) SetTheme(theme themes.Theme) {
	s.theme = theme
}

// Render returns the styled stat box as a string.
// Layout:
//
//	┌─────────┐
//	│ 17,487  │
//	│ packets │
//	└─────────┘
func (s *StatBox) Render() string {
	// Calculate width
	width := s.Width
	if width <= 0 {
		valueWidth := lipgloss.Width(s.Value)
		labelWidth := lipgloss.Width(s.Label)
		width = valueWidth
		if labelWidth > width {
			width = labelWidth
		}
		width += 4 // padding
	}

	// Value style (bold, prominent)
	valueStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.Foreground).
		Align(lipgloss.Center).
		Width(width - 2) // account for border

	// Label style (dimmer, below value)
	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Align(lipgloss.Center).
		Width(width - 2)

	// Box style with border
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(s.theme.BorderColor).
		Padding(0, 1)

	var content strings.Builder
	content.WriteString(valueStyle.Render(s.Value))
	content.WriteString("\n")
	content.WriteString(labelStyle.Render(s.Label))

	return boxStyle.Render(content.String())
}

// RenderCompact returns a compact single-line representation.
// Format: "17,487 packets"
func (s *StatBox) RenderCompact() string {
	valueStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.Foreground)

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	return valueStyle.Render(s.Value) + " " + labelStyle.Render(s.Label)
}

// RenderInline returns value and label on separate lines without border.
func (s *StatBox) RenderInline() string {
	valueStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.Foreground)

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	return valueStyle.Render(s.Value) + "\n" + labelStyle.Render(s.Label)
}

// StatBoxRow renders multiple StatBoxes in a horizontal row.
func StatBoxRow(boxes []*StatBox, gap int) string {
	if len(boxes) == 0 {
		return ""
	}

	// Render all boxes
	rendered := make([]string, len(boxes))
	for i, box := range boxes {
		rendered[i] = box.Render()
	}

	// Join horizontally with gap
	return lipgloss.JoinHorizontal(lipgloss.Top, addGaps(rendered, gap)...)
}

// addGaps inserts gap spacing between rendered strings.
func addGaps(items []string, gap int) []string {
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
