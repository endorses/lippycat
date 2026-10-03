//go:build tui || all

package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// DetailPaneGeometry describes the content rectangle inside exact outer pane
// dimensions. Compact panes trade decorative padding for usable content.
func DetailPaneGeometry(width, height int) (x, y, contentWidth, contentHeight int) {
	if width <= 0 || height <= 0 {
		return 0, 0, 0, 0
	}
	if width >= 3 && height >= 3 {
		x, y = 1, 1
		if width >= 48 && height >= 12 {
			x, y = 3, 2
		}
	}
	return x, y, max(1, width-2*x), max(1, height-2*y)
}

func renderDetailPane(content string, width, height int, focused bool, theme themes.Theme) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	x, y, cw, ch := DetailPaneGeometry(width, height)
	// Crop a temporary render, never the prepared content or its scroll state.
	lines := strings.Split(content, "\n")
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], cw, "")
	}
	content = strings.Join(lines[:min(len(lines), ch)], "\n")
	style := lipgloss.NewStyle().Width(width).Height(height)
	if x > 0 {
		border, color := lipgloss.RoundedBorder(), theme.BorderColor
		if focused {
			border, color = lipgloss.ThickBorder(), theme.SelectionBg
		}
		style = style.Border(border).BorderForeground(color).Padding(y-1, x-1).Width(width - 2).Height(height - 2)
	}
	return style.Render(content)
}

func wrapDetailContent(content string, width int, compact bool) string {
	if compact {
		content = strings.ReplaceAll(content, "\n\n", "\n")
	}
	return ansi.Hardwrap(content, max(1, width), true)
}

// Separate sections by one blank line, accounting for the last row's newline.
func writeDetailSectionBreak(content *strings.Builder) {
	s := content.String()
	switch {
	case s == "", strings.HasSuffix(s, "\n\n"):
		return
	case strings.HasSuffix(s, "\n"):
		content.WriteByte('\n')
	default:
		content.WriteString("\n\n")
	}
}
