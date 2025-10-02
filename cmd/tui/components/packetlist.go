package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// PacketDisplay represents a packet for display
type PacketDisplay struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Length    int
	Info      string
	RawData   []byte // Raw packet bytes for hex dump
}

// PacketList is a component that displays a list of packets
type PacketList struct {
	packets      []PacketDisplay
	cursor       int // Currently selected packet
	offset       int // Scroll offset
	width        int
	height       int
	headerHeight int
	autoScroll   bool         // Whether to auto-scroll to bottom (like chat)
	theme        themes.Theme // Color theme
}

// NewPacketList creates a new packet list component
func NewPacketList() PacketList {
	return PacketList{
		packets:      []PacketDisplay{},
		cursor:       0,
		offset:       0,
		width:        80,
		height:       20,
		headerHeight: 2,                      // Header + separator
		autoScroll:   true,                   // Start with auto-scroll enabled
		theme:        themes.SolarizedDark(), // Default theme
	}
}

// SetTheme updates the theme
func (p *PacketList) SetTheme(theme themes.Theme) {
	p.theme = theme
}

// SetPackets updates the packet list
func (p *PacketList) SetPackets(packets []PacketDisplay) {
	p.packets = packets

	// Auto-scroll to bottom if enabled (like chat)
	if p.autoScroll && len(p.packets) > 0 {
		p.cursor = len(p.packets) - 1
		p.adjustOffset()
	}
}

// Reset resets the packet list to initial state
func (p *PacketList) Reset() {
	p.packets = []PacketDisplay{}
	p.cursor = 0
	p.offset = 0
	p.autoScroll = true
}

// SetSize sets the display size
func (p *PacketList) SetSize(width, height int) {
	p.width = width
	p.height = height
	p.adjustOffset()
}

// CursorUp moves the cursor up
func (p *PacketList) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
		p.adjustOffset()
		// Disable auto-scroll when user manually navigates
		p.autoScroll = false
	}
}

// CursorDown moves the cursor down
func (p *PacketList) CursorDown() {
	if p.cursor < len(p.packets)-1 {
		p.cursor++
		p.adjustOffset()
		// Check if we're at the bottom - re-enable auto-scroll
		if p.cursor == len(p.packets)-1 {
			p.autoScroll = true
		} else {
			p.autoScroll = false
		}
	}
}

// GotoTop moves to the first packet
func (p *PacketList) GotoTop() {
	p.cursor = 0
	p.offset = 0
	// Disable auto-scroll when jumping to top
	p.autoScroll = false
}

// GotoBottom moves to the last packet
func (p *PacketList) GotoBottom() {
	if len(p.packets) > 0 {
		p.cursor = len(p.packets) - 1
		p.adjustOffset()
		// Re-enable auto-scroll when going to bottom
		p.autoScroll = true
	}
}

// PageUp moves up by one page
func (p *PacketList) PageUp() {
	// Must match the calculation in View() and adjustOffset()
	contentHeight := p.height - 3
	pageSize := contentHeight - p.headerHeight
	if pageSize < 1 {
		pageSize = 1
	}

	p.cursor -= pageSize
	if p.cursor < 0 {
		p.cursor = 0
	}
	p.adjustOffset()
	// Disable auto-scroll when paging up
	p.autoScroll = false
}

// PageDown moves down by one page
func (p *PacketList) PageDown() {
	// Must match the calculation in View() and adjustOffset()
	contentHeight := p.height - 3
	pageSize := contentHeight - p.headerHeight
	if pageSize < 1 {
		pageSize = 1
	}

	p.cursor += pageSize
	if p.cursor >= len(p.packets) {
		p.cursor = len(p.packets) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
	p.adjustOffset()
	// Re-enable auto-scroll if we reached the bottom
	if p.cursor == len(p.packets)-1 {
		p.autoScroll = true
	} else {
		p.autoScroll = false
	}
}

// adjustOffset ensures the cursor is visible
func (p *PacketList) adjustOffset() {
	// Must match the calculation in View()
	// Box overhead: 3 lines to match details panel
	// Header: 2 lines
	contentHeight := p.height - 3
	visibleLines := contentHeight - p.headerHeight

	if visibleLines < 1 {
		visibleLines = 1
	}

	// Cursor above visible area
	if p.cursor < p.offset {
		p.offset = p.cursor
	}

	// Cursor below visible area
	if p.cursor >= p.offset+visibleLines {
		p.offset = p.cursor - visibleLines + 1
	}

	// Ensure offset is valid
	if p.offset < 0 {
		p.offset = 0
	}
}

// IsAutoScrolling returns whether auto-scroll is enabled
func (p *PacketList) IsAutoScrolling() bool {
	return p.autoScroll
}

// GetCursor returns the current cursor position
func (p *PacketList) GetCursor() int {
	return p.cursor
}

// View renders the packet list
func (p *PacketList) View(focused bool) string {
	// Calculate the space available for content inside the box
	// Box overhead: 2 (border) + 2 (vertical padding) = 4
	// So the content height should be p.height - 3 to match details panel
	contentHeight := p.height - 3

	// The content includes header (2 lines) + packet lines
	// So available lines for packets = contentHeight - 2
	availableForPackets := contentHeight - p.headerHeight

	var sb strings.Builder

	if len(p.packets) == 0 {
		sb.WriteString(p.renderHeader())
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("No packets captured yet..."))

		// Fill remaining space
		for i := 1; i < availableForPackets; i++ {
			sb.WriteString("\n")
		}
	} else {
		// Render header
		sb.WriteString(p.renderHeader())
		sb.WriteString("\n")

		// Calculate visible range based on available space
		visibleLines := availableForPackets
		if visibleLines < 1 {
			visibleLines = 1
		}

		start := p.offset
		end := p.offset + visibleLines

		if end > len(p.packets) {
			end = len(p.packets)
		}

		// Render visible packets
		for i := start; i < end; i++ {
			line := p.renderPacket(i, i == p.cursor)
			sb.WriteString(line)
			if i < end-1 {
				sb.WriteString("\n")
			}
		}

		// Fill remaining space to maintain consistent box size
		linesRendered := end - start
		for i := linesRendered; i < visibleLines; i++ {
			if i > 0 || linesRendered > 0 {
				sb.WriteString("\n")
			}
			// Empty line for padding
		}
	}

	// Wrap in border - the height should match our total height minus margins
	borderColor := p.theme.BorderColor
	if focused {
		borderColor = p.theme.FocusedBorderColor // Solarized yellow when focused
	}

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(p.width - 4).
		Height(contentHeight)

	return borderStyle.Render(sb.String())
}

// getColumnWidths returns responsive column widths based on available width
func (p *PacketList) getColumnWidths() (timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth int) {
	// Account for padding and borders (estimate)
	availableWidth := p.width - 10

	// Define minimum and preferred widths
	const (
		timeMin  = 8  // HH:MM:SS
		timePref = 15 // HH:MM:SS.microsec

		srcMin  = 9  // Short IP or partial
		srcPref = 22 // Full IP:Port

		dstMin  = 9
		dstPref = 22

		protoMin  = 3 // Short protocol names
		protoPref = 8

		lenMin  = 4 // Length
		lenPref = 8

		infoMin = 10 // Minimal info
	)

	// Start with minimum widths
	totalMin := timeMin + srcMin + dstMin + protoMin + lenMin + infoMin + 5 // +5 for spaces

	if availableWidth < totalMin {
		// Extremely narrow - use absolute minimums
		return timeMin, srcMin, dstMin, protoMin, lenMin, infoMin
	}

	// Try preferred widths
	totalPref := timePref + srcPref + dstPref + protoPref + lenPref + infoMin + 5

	if availableWidth >= totalPref {
		// Plenty of space - use preferred widths + remaining for info
		infoWidth = availableWidth - timePref - srcPref - dstPref - protoPref - lenPref - 5
		return timePref, srcPref, dstPref, protoPref, lenPref, infoWidth
	}

	// Medium width - scale between min and preferred
	remaining := availableWidth - totalMin

	// Distribute remaining space proportionally
	timeExtra := min(remaining/6, timePref-timeMin)
	remaining -= timeExtra

	srcExtra := min(remaining/5, srcPref-srcMin)
	remaining -= srcExtra

	dstExtra := min(remaining/4, dstPref-dstMin)
	remaining -= dstExtra

	protoExtra := min(remaining/3, protoPref-protoMin)
	remaining -= protoExtra

	lenExtra := min(remaining/2, lenPref-lenMin)
	remaining -= lenExtra

	// Give remaining to info
	infoWidth = infoMin + remaining

	return timeMin + timeExtra, srcMin + srcExtra, dstMin + dstExtra,
	       protoMin + protoExtra, lenMin + lenExtra, infoWidth
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// renderHeader renders the table header
func (p *PacketList) renderHeader() string {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(p.theme.HeaderBg).
		Reverse(true)

	// Get responsive column widths
	timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth := p.getColumnWidths()

	header := fmt.Sprintf(
		"%-*s %-*s %-*s %-*s %-*s %-*s",
		timeWidth, truncate("Time", timeWidth),
		srcWidth, truncate("Source", srcWidth),
		dstWidth, truncate("Destination", dstWidth),
		protoWidth, truncate("Protocol", protoWidth),
		lenWidth, truncate("Length", lenWidth),
		infoWidth, truncate("Info", infoWidth),
	)

	// Ensure header spans full width
	renderedHeader := headerStyle.Render(header)
	headerLen := lipgloss.Width(renderedHeader)
	if headerLen < p.width {
		padding := p.width - headerLen
		renderedHeader += headerStyle.Render(strings.Repeat(" ", padding))
	}

	return renderedHeader
}

// truncate truncates a string to fit width with ellipsis if needed
func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// renderPacket renders a single packet row
func (p *PacketList) renderPacket(index int, selected bool) string {
	pkt := p.packets[index]

	// Get responsive column widths (match header)
	timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth := p.getColumnWidths()

	// Format timestamp based on available width
	var timeStr string
	if timeWidth >= 15 {
		timeStr = pkt.Timestamp.Format("15:04:05.000000")
	} else if timeWidth >= 12 {
		timeStr = pkt.Timestamp.Format("15:04:05.000")
	} else {
		timeStr = pkt.Timestamp.Format("15:04:05")
	}
	timeStr = truncate(timeStr, timeWidth)

	// Format source and destination
	src := fmt.Sprintf("%s:%s", pkt.SrcIP, pkt.SrcPort)
	dst := fmt.Sprintf("%s:%s", pkt.DstIP, pkt.DstPort)

	// Truncate addresses intelligently
	src = truncate(src, srcWidth)
	dst = truncate(dst, dstWidth)

	// Truncate protocol
	proto := truncate(pkt.Protocol, protoWidth)

	// Truncate info
	info := truncate(pkt.Info, infoWidth)

	// Format row
	row := fmt.Sprintf(
		"%-*s %-*s %-*s %-*s %-*d %-*s",
		timeWidth, timeStr,
		srcWidth, src,
		dstWidth, dst,
		protoWidth, proto,
		lenWidth, pkt.Length,
		infoWidth, info,
	)

	// Apply styling
	style := lipgloss.NewStyle()

	if selected {
		// Make selection stand out with distinct colors
		style = style.
			Foreground(p.theme.SelectionBg).
			Reverse(true).
			Bold(true)

		// Ensure selection spans full width
		renderedRow := style.Render(row)
		rowLen := lipgloss.Width(renderedRow)
		if rowLen < p.width {
			padding := p.width - rowLen
			renderedRow += style.Render(strings.Repeat(" ", padding))
		}
		return renderedRow
	} else {
		// No background - transparent
		// Protocol-based coloring using theme
		style = style.Foreground(p.getProtocolColor(pkt.Protocol))

		return style.Render(row)
	}
}

// getProtocolColor returns the theme color for a protocol
func (p *PacketList) getProtocolColor(protocol string) lipgloss.Color {
	switch protocol {
	case "TCP":
		return p.theme.TCPColor
	case "UDP":
		return p.theme.UDPColor
	case "SIP":
		return p.theme.SIPColor
	case "RTP":
		return p.theme.RTPColor
	case "DNS":
		return p.theme.DNSColor
	case "HTTP", "HTTPS":
		return p.theme.HTTPColor
	case "TLS", "SSL":
		return p.theme.TLSColor
	case "ICMP":
		return p.theme.ICMPColor
	default:
		return p.theme.Foreground
	}
}
