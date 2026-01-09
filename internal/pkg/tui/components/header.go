//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Header displays the top header bar
type Header struct {
	width          int
	theme          themes.Theme
	capturing      bool
	paused         bool
	iface          string
	packets        int
	bufferSize     int // Maximum buffer capacity
	captureMode    CaptureMode
	nodeCount      int  // Number of connected remote nodes (hunters)
	processorCount int  // Number of connected processors
	tlsDecryption  bool // True when TLS decryption is active
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

// SetPacketCount sets the packet count and buffer size
func (h *Header) SetPacketCount(count, bufferSize int) {
	h.packets = count
	h.bufferSize = bufferSize
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

// SetTLSDecryption sets whether TLS decryption is active
func (h *Header) SetTLSDecryption(active bool) {
	h.tlsDecryption = active
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
			statusColor = h.theme.DNSColor // Yellow (solarized) to match Nodes tab
		default:
			statusText = "● CAPTURING"
			statusColor = h.theme.ErrorColor // Red for capturing
		}
	} else {
		statusText = "○ STOPPED"
		statusColor = lipgloss.Color("240")
	}

	// Add TLS indicator if decryption is active
	if h.tlsDecryption {
		tlsStyle := lipgloss.NewStyle().Foreground(h.theme.TLSColor).Bold(true)
		statusText = statusText + " " + tlsStyle.Render("TLS")
	}

	statusStyle := leftStyle.Foreground(statusColor)

	// Fixed width sections to prevent shifting
	// Account for padding (0,1) = 2 chars per section = 6 total
	// Left: 25 chars (extra space for "TLS" indicator), Middle: flexible, Right: 20 chars
	leftWidth := 25
	rightWidth := 20
	paddingTotal := 6 // 2 per section * 3 sections

	// Create fixed-width left section (status)
	leftContent := statusStyle.Render(statusText)
	leftPart := leftStyle.Width(leftWidth).Render(leftContent)

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
	middlePart := middleStyle.Width(middleWidth).Align(lipgloss.Center).Render(middleText)

	// Right part - packet count (fixed width) with color based on buffer utilization
	rightText := fmt.Sprintf("Packets: %s", formatNumber(h.packets))

	// Calculate buffer utilization percentage and select color
	var packetCountColor lipgloss.Color
	if h.bufferSize > 0 {
		utilization := float64(h.packets) / float64(h.bufferSize) * 100.0
		switch {
		case utilization >= 100.0:
			packetCountColor = h.theme.ErrorColor // Red (solarizedRed)
		case utilization >= 66.0:
			packetCountColor = h.theme.WarningColor // Orange (solarizedOrange)
		case utilization >= 33.0:
			packetCountColor = h.theme.DNSColor // Yellow (solarizedYellow)
		default:
			packetCountColor = h.theme.SuccessColor // Green (solarizedGreen)
		}
	} else {
		// No buffer size set, use default foreground color
		packetCountColor = h.theme.Foreground
	}

	rightPart := rightStyle.Foreground(packetCountColor).Width(rightWidth).Align(lipgloss.Right).Render(rightText)

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
