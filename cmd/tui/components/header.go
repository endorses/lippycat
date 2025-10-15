//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Header displays the top header bar
type Header struct {
	width          int
	theme          themes.Theme
	capturing      bool
	paused         bool
	iface          string
	packets        int
	captureMode    CaptureMode
	nodeCount      int // Number of connected remote nodes (hunters)
	processorCount int // Number of connected processors
}

// NewHeader creates a new header component
func NewHeader() Header {
	return Header{
		width:       80,
		theme:       themes.Solarized(),
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

// SetNodeCount sets the number of connected remote nodes (hunters)
func (h *Header) SetNodeCount(count int) {
	h.nodeCount = count
}

// SetProcessorCount sets the number of connected processors
func (h *Header) SetProcessorCount(count int) {
	h.processorCount = count
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
		statusText = "|| PAUSED"
		statusColor = h.theme.SuccessColor // Green for paused
	} else if h.capturing {
		switch h.captureMode {
		case CaptureModeOffline:
			statusText = "● READING"
			statusColor = h.theme.InfoColor // Blue for reading file
		case CaptureModeRemote:
			statusText = "● STREAMING"
			statusColor = h.theme.InfoColor // Blue for streaming from remote
		default:
			statusText = "● CAPTURING"
			statusColor = h.theme.ErrorColor // Red for capturing
		}
	} else {
		statusText = "○ STOPPED"
		statusColor = lipgloss.Color("240")
	}

	statusStyle := leftStyle.Copy().Foreground(statusColor)

	// Fixed width sections to prevent shifting
	// Account for padding (0,1) = 2 chars per section = 6 total
	// Left: 20 chars, Middle: flexible, Right: 20 chars
	leftWidth := 20
	rightWidth := 20
	paddingTotal := 6 // 2 per section * 3 sections

	// Create fixed-width left section (status)
	leftContent := statusStyle.Render(statusText)
	leftPart := leftStyle.Copy().Width(leftWidth).Render(leftContent)

	// Middle part - interface, file, or remote address (takes remaining space)
	var middleText string
	switch h.captureMode {
	case CaptureModeOffline:
		middleText = fmt.Sprintf("File: %s", h.iface)
	case CaptureModeRemote:
		if h.nodeCount > 0 || h.processorCount > 0 {
			// Show processor and hunter counts
			if h.processorCount > 0 {
				processorWord := "processor"
				if h.processorCount > 1 {
					processorWord = "processors"
				}
				hunterWord := "hunter"
				if h.nodeCount > 1 {
					hunterWord = "hunters"
				}
				middleText = fmt.Sprintf("Nodes: %d %s | %d %s", h.processorCount, processorWord, h.nodeCount, hunterWord)
			} else {
				// Direct hunter connections (no processors)
				hunterWord := "hunter"
				if h.nodeCount > 1 {
					hunterWord = "hunters"
				}
				middleText = fmt.Sprintf("Nodes: %d %s (direct)", h.nodeCount, hunterWord)
			}
		} else if h.iface != "" {
			middleText = fmt.Sprintf("Nodes: %s", h.iface)
		} else {
			middleText = "Nodes: add nodes via Nodes tab"
		}
	default:
		middleText = fmt.Sprintf("Interface: %s", h.iface)
	}
	middleWidth := h.width - leftWidth - rightWidth - paddingTotal
	if middleWidth < 10 {
		middleWidth = 10 // Minimum width
	}
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
