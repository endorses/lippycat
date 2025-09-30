package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Header displays the top header bar
type Header struct {
	width      int
	theme      themes.Theme
	capturing  bool
	paused     bool
	iface      string
	packets    int
}

// NewHeader creates a new header component
func NewHeader() Header {
	return Header{
		width:     80,
		theme:     themes.SolarizedDark(),
		capturing: true,
		paused:    false,
		iface:     "any",
		packets:   0,
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
		statusText = "● CAPTURING"
		statusColor = h.theme.ErrorColor // Red for capturing
	} else {
		statusText = "○ STOPPED"
		statusColor = lipgloss.Color("240")
	}

	statusStyle := leftStyle.Copy().Foreground(statusColor)
	leftPart := statusStyle.Render(statusText)

	// Middle part - interface
	middlePart := middleStyle.Render(fmt.Sprintf("Interface: %s", h.iface))

	// Right part - packet count
	rightPart := rightStyle.Render(fmt.Sprintf("Packets: %s", formatNumber(h.packets)))

	// Calculate spacing
	leftWidth := lipgloss.Width(leftPart)
	middleWidth := lipgloss.Width(middlePart)
	rightWidth := lipgloss.Width(rightPart)

	totalContentWidth := leftWidth + middleWidth + rightWidth
	remainingSpace := h.width - totalContentWidth

	// Create spacers without background
	var leftSpacer, rightSpacer string
	if remainingSpace > 0 {
		leftSpacerWidth := remainingSpace / 3
		rightSpacerWidth := remainingSpace - leftSpacerWidth
		leftSpacer = strings.Repeat(" ", leftSpacerWidth)
		rightSpacer = strings.Repeat(" ", rightSpacerWidth)
	}

	// Join parts
	header := lipgloss.JoinHorizontal(
		lipgloss.Top,
		leftPart,
		leftSpacer,
		middlePart,
		rightSpacer,
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