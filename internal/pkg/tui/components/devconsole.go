//go:build tui || all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// DevConsole displays debug log messages in a scrollable panel
type DevConsole struct {
	visible    bool
	width      int
	height     int
	scrollPos  int
	theme      themes.Theme
	autoScroll bool
}

// NewDevConsole creates a new dev console component
func NewDevConsole() *DevConsole {
	return &DevConsole{
		visible:    false,
		autoScroll: true,
		theme:      themes.Solarized(),
	}
}

// SetTheme updates the component's theme
func (d *DevConsole) SetTheme(theme themes.Theme) {
	d.theme = theme
}

// SetSize sets the console dimensions
func (d *DevConsole) SetSize(width, height int) {
	d.width = width
	d.height = height
}

// Toggle shows/hides the console
func (d *DevConsole) Toggle() {
	d.visible = !d.visible
	if d.visible {
		d.autoScroll = true
		d.scrollPos = 0
	}
}

// IsVisible returns whether the console is visible
func (d *DevConsole) IsVisible() bool {
	return d.visible
}

// ScrollUp scrolls the view up
func (d *DevConsole) ScrollUp(lines int) {
	d.autoScroll = false
	d.scrollPos += lines
}

// ScrollDown scrolls the view down
func (d *DevConsole) ScrollDown(lines int) {
	d.scrollPos -= lines
	if d.scrollPos < 0 {
		d.scrollPos = 0
		d.autoScroll = true
	}
}

// ScrollToBottom enables auto-scroll and jumps to bottom
func (d *DevConsole) ScrollToBottom() {
	d.scrollPos = 0
	d.autoScroll = true
}

// Clear clears the console buffer
func (d *DevConsole) Clear() {
	if buf := logger.GetConsoleBuffer(); buf != nil {
		buf.Clear()
	}
}

// View renders the dev console
func (d *DevConsole) View() string {
	if !d.visible {
		return ""
	}

	buf := logger.GetConsoleBuffer()
	if buf == nil {
		return ""
	}

	// Calculate usable area (leave room for border and title)
	// Height: top border (1) + title (1) + content (N) + bottom border (1) = N + 3
	contentHeight := d.height - 3
	if contentHeight < 1 {
		contentHeight = 1
	}
	// Width: left border (1) + content (W) + right border (1) = W + 2
	contentWidth := d.width - 2
	if contentWidth < 20 {
		contentWidth = 20
	}

	// Get entries to display
	entries := buf.GetRecent(contentHeight + d.scrollPos)

	// Line style - white on black, full width
	lineStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#000000")).
		Foreground(lipgloss.Color("#ffffff")).
		Width(contentWidth)

	// Build content lines
	var lines []string
	startIdx := d.scrollPos
	endIdx := startIdx + contentHeight
	if endIdx > len(entries) {
		endIdx = len(entries)
	}

	// Entries are newest-first, but we want to show oldest at top
	// So reverse the slice portion we're displaying
	for i := endIdx - 1; i >= startIdx && i < len(entries); i-- {
		entry := entries[i]
		line := d.formatEntry(entry, contentWidth)
		lines = append(lines, lineStyle.Render(line))
	}

	// Pad with empty lines if needed
	emptyLine := lineStyle.Render(strings.Repeat(" ", contentWidth))
	for len(lines) < contentHeight {
		lines = append(lines, emptyLine)
	}

	content := strings.Join(lines, "\n")

	// Title bar - full width
	scrollIndicator := ""
	if d.autoScroll {
		scrollIndicator = " [AUTO]"
	} else if d.scrollPos > 0 {
		scrollIndicator = fmt.Sprintf(" [+%d]", d.scrollPos)
	}

	titleText := fmt.Sprintf(" Dev Console (%d msgs)%s - ` close, PgUp/Dn scroll, End=bottom, c=clear ",
		buf.Count(), scrollIndicator)
	titleStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#444444")).
		Foreground(lipgloss.Color("#ffffff")).
		Bold(true).
		Width(contentWidth)
	title := titleStyle.Render(titleText)

	// Border style
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#888888")).
		BorderBackground(lipgloss.Color("#000000"))

	inner := lipgloss.JoinVertical(lipgloss.Left, title, content)

	return boxStyle.Render(inner)
}

// formatEntry formats a single log entry for display (plain text, no styling)
func (d *DevConsole) formatEntry(entry logger.LogEntry, maxWidth int) string {
	// Format: HH:MM:SS.mmm LVL message attrs...
	timeStr := entry.Time.Format("15:04:05.000")
	level := logger.FormatLevel(entry.Level)

	// Build the line - plain text only
	prefix := fmt.Sprintf("%s %s ", timeStr, level)
	prefixLen := len(prefix)

	// Calculate remaining space for message and attrs
	remaining := maxWidth - prefixLen
	if remaining < 10 {
		remaining = 10
	}

	msg := entry.Message
	attrs := entry.Attrs

	// Truncate if needed
	if len(msg)+len(attrs)+1 > remaining {
		if len(attrs) > 0 {
			// Show as much message as possible, then attrs
			msgSpace := remaining - len(attrs) - 4 // " ..."
			if msgSpace < 10 {
				msgSpace = 10
			}
			if len(msg) > msgSpace {
				msg = msg[:msgSpace] + "..."
			}
			attrSpace := remaining - len(msg) - 1
			if len(attrs) > attrSpace {
				attrs = attrs[:attrSpace-3] + "..."
			}
		} else if len(msg) > remaining {
			msg = msg[:remaining-3] + "..."
		}
	}

	result := prefix + msg
	if attrs != "" {
		result += " " + attrs
	}

	return result
}
