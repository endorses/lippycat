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
}

// PacketList is a component that displays a list of packets
type PacketList struct {
	packets      []PacketDisplay
	cursor       int          // Currently selected packet
	offset       int          // Scroll offset
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
		headerHeight: 2, // Header + separator
		autoScroll:   true, // Start with auto-scroll enabled
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
	pageSize := p.height - p.headerHeight
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
	pageSize := p.height - p.headerHeight
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
	visibleLines := p.height - p.headerHeight

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
func (p *PacketList) View() string {
	if len(p.packets) == 0 {
		return p.renderHeader() + "\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("No packets captured yet...")
	}

	var sb strings.Builder

	// Render header
	sb.WriteString(p.renderHeader())
	sb.WriteString("\n")

	// Calculate visible range
	visibleLines := p.height - p.headerHeight
	start := p.offset
	end := p.offset + visibleLines

	if end > len(p.packets) {
		end = len(p.packets)
	}

	// Render visible packets
	for i := start; i < end; i++ {
		line := p.renderPacket(i, i == p.cursor)
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	// Fill remaining space
	for i := end - start; i < visibleLines; i++ {
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderHeader renders the table header
func (p *PacketList) renderHeader() string {
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(p.theme.SelectionFg).
		Background(p.theme.InfoColor)

	// Column widths
	timeWidth := 15
	srcWidth := 22 // IP:Port
	dstWidth := 22
	protoWidth := 8
	lenWidth := 8
	infoWidth := p.width - timeWidth - srcWidth - dstWidth - protoWidth - lenWidth - 10

	if infoWidth < 10 {
		infoWidth = 10
	}

	header := fmt.Sprintf(
		"%-*s %-*s %-*s %-*s %-*s %-*s",
		timeWidth, "Time",
		srcWidth, "Source",
		dstWidth, "Destination",
		protoWidth, "Protocol",
		lenWidth, "Length",
		infoWidth, "Info",
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

// renderPacket renders a single packet row
func (p *PacketList) renderPacket(index int, selected bool) string {
	pkt := p.packets[index]

	// Column widths (match header)
	timeWidth := 15
	srcWidth := 22
	dstWidth := 22
	protoWidth := 8
	lenWidth := 8
	infoWidth := p.width - timeWidth - srcWidth - dstWidth - protoWidth - lenWidth - 10

	if infoWidth < 10 {
		infoWidth = 10
	}

	// Format timestamp
	timeStr := pkt.Timestamp.Format("15:04:05.000000")
	if len(timeStr) > timeWidth {
		timeStr = timeStr[:timeWidth]
	}

	// Format source and destination
	src := fmt.Sprintf("%s:%s", pkt.SrcIP, pkt.SrcPort)
	dst := fmt.Sprintf("%s:%s", pkt.DstIP, pkt.DstPort)

	// Truncate if needed
	if len(src) > srcWidth {
		src = src[:srcWidth-3] + "..."
	}
	if len(dst) > dstWidth {
		dst = dst[:dstWidth-3] + "..."
	}

	// Truncate info
	info := pkt.Info
	if len(info) > infoWidth {
		info = info[:infoWidth-3] + "..."
	}

	// Format row
	row := fmt.Sprintf(
		"%-*s %-*s %-*s %-*s %-*d %-*s",
		timeWidth, timeStr,
		srcWidth, src,
		dstWidth, dst,
		protoWidth, pkt.Protocol,
		lenWidth, pkt.Length,
		infoWidth, info,
	)

	// Apply styling
	style := lipgloss.NewStyle()

	if selected {
		// Make selection stand out with distinct colors
		style = style.
			Background(p.theme.InfoColor).
			Foreground(p.theme.SelectionFg).
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
		// Zebra striping - alternating row colors
		if index%2 == 0 {
			// Even rows get a subtle background
			style = style.Background(p.theme.Background)
		} else {
			// Odd rows get slightly highlighted background
			style = style.Background(p.theme.HeaderBg)
		}

		// Protocol-based coloring using theme
		style = style.Foreground(p.getProtocolColor(pkt.Protocol))

		// Ensure row spans full width
		renderedRow := style.Render(row)
		rowLen := lipgloss.Width(renderedRow)
		if rowLen < p.width {
			padding := p.width - rowLen
			renderedRow += style.Render(strings.Repeat(" ", padding))
		}
		return renderedRow
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
