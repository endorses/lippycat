//go:build tui || all
// +build tui all

package nodesview

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// ProcessorConnectionState represents the connection state of a processor
type ProcessorConnectionState int

const (
	ProcessorConnectionStateDisconnected ProcessorConnectionState = iota
	ProcessorConnectionStateConnecting
	ProcessorConnectionStateConnected
	ProcessorConnectionStateFailed
)

// TruncateString truncates a string to maxLen with ellipsis if needed
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// FormatPacketNumber formats a packet count with K/M/G suffixes
func FormatPacketNumber(n uint64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.1fG", float64(n)/1000000000)
	}
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// FormatDuration formats a duration in nanoseconds to human-readable string
func FormatDuration(ns int64) string {
	d := time.Duration(ns)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// IsVoIPHunter determines if a hunter supports VoIP filters based on capabilities
func IsVoIPHunter(capabilities *management.HunterCapabilities) bool {
	if capabilities == nil || len(capabilities.FilterTypes) == 0 {
		// No capabilities - assume generic (backward compatibility)
		return false
	}

	// Check if hunter supports VoIP-specific filters (sip_user is the indicator)
	for _, ft := range capabilities.FilterTypes {
		if ft == "sip_user" {
			return true
		}
	}

	return false
}

// GetHunterModeBadge returns a styled badge for hunter mode
func GetHunterModeBadge(capabilities *management.HunterCapabilities, theme themes.Theme) string {
	if IsVoIPHunter(capabilities) {
		// VoIP badge - use purple/magenta color
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("63")).
			Padding(0, 1).
			Render("VoIP")
	}

	// Generic badge - use gray color
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("240")).
		Padding(0, 1).
		Render("Generic")
}

// RenderBox renders a box with rounded corners around the given lines
func RenderBox(lines []string, width int, style lipgloss.Style) string {
	var b strings.Builder

	// Top border
	b.WriteString("╭")
	b.WriteString(strings.Repeat("─", width-2))
	b.WriteString("╮")
	b.WriteString("\n")

	// Content lines
	for _, line := range lines {
		// Truncate or pad to fit width
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString("│ ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(style.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" │")
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString("╰")
	b.WriteString(strings.Repeat("─", width-2))
	b.WriteString("╯")

	return b.String()
}

// RenderProcessorBox renders a processor box with optional selection highlighting and status color
func RenderProcessorBox(lines []string, width int, style lipgloss.Style, isSelected bool, connState ProcessorConnectionState, status management.ProcessorStatus, theme themes.Theme) string {
	var b strings.Builder

	// Determine status color for text - prioritize connection state
	var statusColor lipgloss.Color

	// First check connection state (takes precedence)
	switch connState {
	case ProcessorConnectionStateDisconnected:
		statusColor = lipgloss.Color("240") // Gray for disconnected
	case ProcessorConnectionStateConnecting:
		statusColor = lipgloss.Color("11") // Cyan/blue for connecting
	case ProcessorConnectionStateFailed:
		statusColor = theme.ErrorColor // Red for failed
	case ProcessorConnectionStateConnected:
		// When connected, use the processor's reported status
		switch status {
		case management.ProcessorStatus_PROCESSOR_HEALTHY:
			statusColor = theme.SuccessColor
		case management.ProcessorStatus_PROCESSOR_WARNING:
			statusColor = theme.WarningColor
		case management.ProcessorStatus_PROCESSOR_ERROR:
			statusColor = theme.ErrorColor
		default:
			statusColor = theme.SuccessColor
		}
	default:
		// Unknown state - show as gray
		statusColor = lipgloss.Color("240")
	}

	// For selected boxes, use cyan border and status-colored text
	// For unselected boxes, use default border and status-colored text
	var borderStyle lipgloss.Style
	var contentStyle lipgloss.Style
	var topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical string

	if isSelected {
		// Selected: cyan border with heavy/bold box characters, status-colored text
		borderStyle = lipgloss.NewStyle().Foreground(theme.SelectionBg)
		contentStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		topLeft = "┏"
		topRight = "┓"
		bottomLeft = "┗"
		bottomRight = "┛"
		horizontal = "━"
		vertical = "┃"
	} else {
		// Unselected: gray border with light rounded box characters, status-colored text
		borderStyle = lipgloss.NewStyle().Foreground(theme.Foreground)
		contentStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		topLeft = "╭"
		topRight = "╮"
		bottomLeft = "╰"
		bottomRight = "╯"
		horizontal = "─"
		vertical = "│"
	}

	// Top border
	b.WriteString(borderStyle.Render(topLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(topRight))
	b.WriteString("\n")

	// Content lines
	for _, line := range lines {
		// Truncate or pad to fit width
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(contentStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString(borderStyle.Render(bottomLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(bottomRight))

	return b.String()
}

// ColumnWidthCalculator provides column width calculation for table views
type ColumnWidthCalculator struct {
	Width int
}

// GetColumnWidths returns responsive column widths based on available width
func (c *ColumnWidthCalculator) GetColumnWidths() (idCol, hostCol, statusCol, uptimeCol, capturedCol, forwardedCol, filtersCol int) {
	// Account for spacing between columns (7 columns = 6 spaces)
	availableWidth := c.Width - 2 // Account for left/right padding

	// Minimum widths
	minIdCol := 8
	minHostCol := 8
	minStatusCol := 7
	minUptimeCol := 6
	minCapturedCol := 8
	minForwardedCol := 9
	minFiltersCol := 7

	// Preferred widths
	idCol = 15
	hostCol = 20
	statusCol = 8
	uptimeCol = 10
	capturedCol = 10
	forwardedCol = 10
	filtersCol = 8

	// Calculate total preferred width
	totalPreferred := idCol + hostCol + statusCol + uptimeCol + capturedCol + forwardedCol + filtersCol

	// If we have enough space, use preferred widths
	if totalPreferred <= availableWidth {
		return
	}

	// Otherwise, start with minimum widths
	idCol = minIdCol
	hostCol = minHostCol
	statusCol = minStatusCol
	uptimeCol = minUptimeCol
	capturedCol = minCapturedCol
	forwardedCol = minForwardedCol
	filtersCol = minFiltersCol

	minTotal := idCol + hostCol + statusCol + uptimeCol + capturedCol + forwardedCol + filtersCol

	// If even minimum doesn't fit, use minimum and let it overflow
	if minTotal >= availableWidth {
		return
	}

	// Distribute remaining space proportionally to ID and Hostname
	remaining := availableWidth - minTotal
	extra := remaining / 2
	idCol += extra
	hostCol += remaining - extra

	return
}

// RenderHunterBox renders a hunter box with centered bold headers and left-aligned body
func RenderHunterBox(headerLines []string, bodyLines []string, width int, baseStyle lipgloss.Style, isSelected bool, status management.HunterStatus, theme themes.Theme) string {
	var b strings.Builder

	// Determine status color for header text
	var statusColor lipgloss.Color
	switch status {
	case management.HunterStatus_STATUS_HEALTHY:
		statusColor = theme.SuccessColor
	case management.HunterStatus_STATUS_WARNING:
		statusColor = theme.WarningColor
	case management.HunterStatus_STATUS_ERROR:
		statusColor = theme.ErrorColor
	case management.HunterStatus_STATUS_STOPPING:
		statusColor = lipgloss.Color("240")
	default:
		statusColor = theme.SuccessColor
	}

	// For selected boxes, use cyan border and status-colored text
	// For unselected boxes, use default border and status-colored text
	var borderStyle lipgloss.Style
	var headerStyle lipgloss.Style
	var bodyStyle lipgloss.Style
	var topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical string

	if isSelected {
		// Selected: cyan border with heavy/bold box characters, status-colored header text
		borderStyle = lipgloss.NewStyle().Foreground(theme.SelectionBg)
		headerStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		bodyStyle = lipgloss.NewStyle().Foreground(theme.Foreground).Bold(false)
		topLeft = "┏"
		topRight = "┓"
		bottomLeft = "┗"
		bottomRight = "┛"
		horizontal = "━"
		vertical = "┃"
	} else {
		// Unselected: normal border with light rounded box characters, status-colored header text
		borderStyle = lipgloss.NewStyle().Foreground(theme.Foreground)
		headerStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		bodyStyle = baseStyle.Bold(false)
		topLeft = "╭"
		topRight = "╮"
		bottomLeft = "╰"
		bottomRight = "╯"
		horizontal = "─"
		vertical = "│"
	}

	// Top border
	b.WriteString(borderStyle.Render(topLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(topRight))
	b.WriteString("\n")

	// Header lines (centered and bold)
	for _, line := range headerLines {
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(headerStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Empty line separator between header and body
	b.WriteString(borderStyle.Render(vertical))
	b.WriteString(" ")
	b.WriteString(strings.Repeat(" ", width-4))
	b.WriteString(" ")
	b.WriteString(borderStyle.Render(vertical))
	b.WriteString("\n")

	// Body lines (left-aligned, not bold)
	for _, line := range bodyLines {
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(bodyStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString(borderStyle.Render(bottomLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(bottomRight))

	return b.String()
}
