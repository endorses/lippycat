package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Header displays the top header bar
type Header struct {
	width       int
	theme       themes.Theme
	capturing   bool
	paused      bool
	iface       string
	packets     int
	captureMode CaptureMode
}

// NewHeader creates a new header component
func NewHeader() Header {
	return Header{
		width:       80,
		theme:       themes.SolarizedDark(),
		capturing:   true,
		paused:      false,
		iface:       "any",
		packets:     0,
		captureMode: CaptureModeLive,
	}
}

// SetTheme updates the theme
func (h *Header) SetTheme(theme themes.Theme) {
	h.theme = theme
}

// SetWidth sets the header width
func (h *Header) SetWidth(width int) {
	h.width = width
}

// SetState updates the capture state
func (h *Header) SetState(capturing, paused bool) {
	h.capturing = capturing
	h.paused = paused
}

// SetInterface sets the interface name
func (h *Header) SetInterface(ifaceName string) {
	h.iface = ifaceName
}

// SetPacketCount sets the packet count
func (h *Header) SetPacketCount(count int) {
	h.packets = count
}

// SetCaptureMode sets the capture mode
func (h *Header) SetCaptureMode(mode CaptureMode) {
	h.captureMode = mode
}

// View renders the header
func (h *Header) View() string {
	// Clean header with visible text
	leftStyle := lipgloss.NewStyle().
		Foreground(h.theme.Foreground).
		Bold(true).
		Padding(0, 1)

	middleStyle := lipgloss.NewStyle().
		Foreground(h.theme.Foreground).
		Padding(0, 1)

	rightStyle := lipgloss.NewStyle().
		Foreground(h.theme.Foreground).
		Padding(0, 1)

	// Status indicator with color
	var statusText string
	var statusColor lipgloss.Color
	if h.paused {
		statusText = "⏸ PAUSED"
		statusColor = h.theme.SuccessColor // Green for paused
	} else if h.capturing {
		if h.captureMode == CaptureModeOffline {
			statusText = "● READING"
			statusColor = h.theme.InfoColor // Blue for reading file
		} else {
			statusText = "● CAPTURING"
			statusColor = h.theme.ErrorColor // Red for capturing
		}
	} else {
		statusText = "○ STOPPED"
		statusColor = lipgloss.Color("240")
	}

	statusStyle := leftStyle.Copy().Foreground(statusColor)

	// Fixed width sections to prevent shifting
	// Left: 20 chars, Middle: flexible, Right: 20 chars
	leftWidth := 20
	rightWidth := 20

	// Create fixed-width left section (status)
	leftContent := statusStyle.Render(statusText)
	leftPart := leftStyle.Copy().Width(leftWidth).Render(leftContent)

	// Middle part - interface or file (takes remaining space)
	var middleText string
	if h.captureMode == CaptureModeOffline {
		middleText = fmt.Sprintf("File: %s", h.iface)
	} else {
		middleText = fmt.Sprintf("Interface: %s", h.iface)
	}
	middleWidth := h.width - leftWidth - rightWidth
	middlePart := middleStyle.Copy().Width(middleWidth).Align(lipgloss.Center).Render(middleText)

	// Right part - packet count (fixed width)
	rightText := fmt.Sprintf("Packets: %s", formatNumber(h.packets))
	rightPart := rightStyle.Copy().Width(rightWidth).Align(lipgloss.Right).Render(rightText)

	// Join parts
	header := lipgloss.JoinHorizontal(
		lipgloss.Top,
		leftPart,
		middlePart,
		rightPart,
	)

	// Add bottom border
	borderStyle := lipgloss.NewStyle().
		Foreground(h.theme.BorderColor)
	border := borderStyle.Render(lipgloss.NewStyle().Width(h.width).Render(strings.Repeat("─", h.width)))

	return header + "\n" + border
}

// formatNumber formats a number with thousand separators
func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}

	str := fmt.Sprintf("%d", n)
	var result string
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}