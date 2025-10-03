package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// VoIPMetadata contains parsed VoIP-specific data
type VoIPMetadata struct {
	From      string            // SIP From header
	To        string            // SIP To header
	CallID    string            // SIP Call-ID header
	Method    string            // SIP method (INVITE, BYE, etc.)
	User      string            // Username from URI
	Codec     string            // RTP codec (if applicable)
	Headers   map[string]string // All SIP headers
	IsRTP     bool              // Whether this is an RTP packet
	SSRC      uint32            // RTP SSRC
	SeqNumber uint16            // RTP sequence number
}

// PacketDisplay represents a packet for display
type PacketDisplay struct {
	Timestamp    time.Time
	SrcIP        string
	DstIP        string
	SrcPort      string
	DstPort      string
	Protocol     string
	Length       int
	Info         string
	RawData      []byte        // Raw packet bytes for hex dump
	NodeID       string        // Source node identifier: "Local", hunter_id, or processor_id
	Interface    string        // Network interface where packet was captured
	VoIPData     *VoIPMetadata // Parsed VoIP metadata (nil if not VoIP)
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

	// Cached rendering state (invalidated on size/theme change)
	cachedStyles     map[string]lipgloss.Style // protocol -> style
	cachedColWidths  [7]int                    // column widths cache
	cachedBorderStyle lipgloss.Style            // border style cache
	cachedHeaderStyle lipgloss.Style            // header style cache
	sizeChanged      bool                       // flag to recalculate caches
}

// NewPacketList creates a new packet list component
func NewPacketList() PacketList {
	p := PacketList{
		packets:      make([]PacketDisplay, 0, 10000), // Pre-allocate for typical buffer size
		cursor:       0,
		offset:       0,
		width:        80,
		height:       20,
		headerHeight: 2,                      // Header + separator
		autoScroll:   true,                   // Start with auto-scroll enabled
		theme:        themes.SolarizedDark(), // Default theme
		cachedStyles: make(map[string]lipgloss.Style),
		sizeChanged:  true, // Force initial cache build
	}
	p.rebuildStyleCache()
	return p
}

// SetTheme updates the theme
func (p *PacketList) SetTheme(theme themes.Theme) {
	p.theme = theme
	p.rebuildStyleCache() // Invalidate cache on theme change
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
	p.packets = make([]PacketDisplay, 0, 10000) // Pre-allocate for typical buffer size
	p.cursor = 0
	p.offset = 0
	p.autoScroll = true
}

// SetSize sets the display size
func (p *PacketList) SetSize(width, height int) {
	if p.width != width || p.height != height {
		p.width = width
		p.height = height
		p.sizeChanged = true // Mark for recalculation
		p.adjustOffset()
	}
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

// GetOffset returns the current scroll offset
func (p *PacketList) GetOffset() int {
	return p.offset
}

// SetCursor sets the cursor position directly (for mouse clicks)
func (p *PacketList) SetCursor(position int) {
	if position < 0 {
		position = 0
	}
	if position >= len(p.packets) {
		position = len(p.packets) - 1
	}
	if position < 0 {
		position = 0
	}
	p.cursor = position
	p.adjustOffset()
	// Disable auto-scroll when manually selecting a packet
	p.autoScroll = false
	// Re-enable auto-scroll if we're at the bottom
	if len(p.packets) > 0 && p.cursor == len(p.packets)-1 {
		p.autoScroll = true
	}
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
// Results are cached and only recalculated when window size changes
func (p *PacketList) getColumnWidths() (nodeWidth, timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth int) {
	// Return cached values if size hasn't changed
	if !p.sizeChanged && p.cachedColWidths[0] != 0 {
		return p.cachedColWidths[0], p.cachedColWidths[1], p.cachedColWidths[2],
			p.cachedColWidths[3], p.cachedColWidths[4], p.cachedColWidths[5], p.cachedColWidths[6]
	}

	// Recalculate column widths
	// Account for padding and borders (estimate)
	availableWidth := p.width - 10

	// Define minimum and preferred widths
	const (
		nodeMin  = 5  // "Local" or short ID
		nodePref = 12 // Full node ID

		timeMin  = 8  // HH:MM:SS
		timePref = 12 // HH:MM:SS.ms

		srcMin  = 9  // Short IP or partial
		srcPref = 22 // Full IP:Port

		dstMin  = 9
		dstPref = 22

		protoMin  = 3 // Short protocol names
		protoPref = 8

		lenMin  = 4 // Length
		lenPref = 6

		infoMin = 10 // Minimal info
	)

	// Start with minimum widths
	totalMin := nodeMin + timeMin + srcMin + dstMin + protoMin + lenMin + infoMin + 6 // +6 for spaces

	if availableWidth < totalMin {
		// Extremely narrow - use absolute minimums
		return nodeMin, timeMin, srcMin, dstMin, protoMin, lenMin, infoMin
	}

	// Try preferred widths
	totalPref := nodePref + timePref + srcPref + dstPref + protoPref + lenPref + infoMin + 6

	if availableWidth >= totalPref {
		// Plenty of space - use preferred widths + remaining for info
		infoWidth = availableWidth - nodePref - timePref - srcPref - dstPref - protoPref - lenPref - 6
		return nodePref, timePref, srcPref, dstPref, protoPref, lenPref, infoWidth
	}

	// Medium width - scale between min and preferred
	remaining := availableWidth - totalMin

	// Distribute remaining space proportionally
	nodeExtra := min(remaining/7, nodePref-nodeMin)
	remaining -= nodeExtra

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

	// Cache the results
	p.cachedColWidths = [7]int{
		nodeMin + nodeExtra,
		timeMin + timeExtra,
		srcMin + srcExtra,
		dstMin + dstExtra,
		protoMin + protoExtra,
		lenMin + lenExtra,
		infoWidth,
	}
	p.sizeChanged = false // Mark cache as valid

	return p.cachedColWidths[0], p.cachedColWidths[1], p.cachedColWidths[2],
		p.cachedColWidths[3], p.cachedColWidths[4], p.cachedColWidths[5], p.cachedColWidths[6]
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
	// Get responsive column widths (cached if size hasn't changed)
	nodeWidth, timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth := p.getColumnWidths()

	header := fmt.Sprintf(
		"%-*s %-*s %-*s %-*s %-*s %-*s %-*s",
		nodeWidth, truncate("Node", nodeWidth),
		timeWidth, truncate("Time", timeWidth),
		srcWidth, truncate("Source", srcWidth),
		dstWidth, truncate("Destination", dstWidth),
		protoWidth, truncate("Protocol", protoWidth),
		lenWidth, truncate("Length", lenWidth),
		infoWidth, truncate("Info", infoWidth),
	)

	// Ensure header spans full width
	renderedHeader := p.cachedHeaderStyle.Render(header)
	headerLen := lipgloss.Width(renderedHeader)
	if headerLen < p.width {
		padding := p.width - headerLen
		renderedHeader += p.cachedHeaderStyle.Render(strings.Repeat(" ", padding))
	}

	return renderedHeader
}

// sanitizeString removes problematic characters that can break terminal rendering
// Optimized to avoid allocations when string is already clean
func sanitizeString(s string) string {
	// Fast path: check if sanitization is needed
	needsSanitization := false
	for _, r := range s {
		if (r < 32 && r != '\t') || r == 127 || r == 0xFFFD {
			needsSanitization = true
			break
		}
	}

	if !needsSanitization {
		return s // Return original string, no allocation
	}

	// Slow path: sanitize the string
	runes := []rune(s)
	for i, r := range runes {
		if r < 32 && r != '\t' {
			runes[i] = ' '
		} else if r == 127 {
			runes[i] = ' '
		} else if r == 0xFFFD {
			runes[i] = '?'
		}
	}
	return string(runes)
}

// truncate truncates a string to fit width with ellipsis if needed
// Uses lipgloss.Width() to properly handle Unicode and multi-width characters
// Optimized with strings.Builder to reduce allocations
func truncate(s string, width int) string {
	// Sanitize first to remove problematic characters
	s = sanitizeString(s)

	currentWidth := lipgloss.Width(s)
	if currentWidth <= width {
		return s
	}

	if width <= 3 {
		// Too narrow for ellipsis, just truncate
		var b strings.Builder
		b.Grow(width * 4) // Pre-allocate (up to 4 bytes per char for UTF-8)
		w := 0
		for _, r := range s {
			b.WriteRune(r)
			w = lipgloss.Width(b.String())
			if w >= width {
				break
			}
		}
		return b.String()
	}

	// Truncate to fit width-3 (leaving room for "...")
	targetWidth := width - 3
	var b strings.Builder
	b.Grow(targetWidth * 4) // Pre-allocate

	for _, r := range s {
		b.WriteRune(r)
		if lipgloss.Width(b.String()) > targetWidth {
			// Remove last rune and add ellipsis
			result := b.String()
			result = result[:len(result)-len(string(r))]
			return result + "..."
		}
	}
	return b.String() + "..."
}

// renderPacket renders a single packet row
func (p *PacketList) renderPacket(index int, selected bool) string {
	pkt := p.packets[index]

	// Get responsive column widths (match header)
	nodeWidth, timeWidth, srcWidth, dstWidth, protoWidth, lenWidth, infoWidth := p.getColumnWidths()

	// Format node ID with color
	nodeID := pkt.NodeID
	if nodeID == "" {
		nodeID = "Local" // Default for local capture
	}
	nodeID = truncate(nodeID, nodeWidth)

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
		"%-*s %-*s %-*s %-*s %-*s %-*d %-*s",
		nodeWidth, nodeID,
		timeWidth, timeStr,
		srcWidth, src,
		dstWidth, dst,
		protoWidth, proto,
		lenWidth, pkt.Length,
		infoWidth, info,
	)

	// Apply styling
	if selected {
		// Make selection stand out with distinct colors
		style := lipgloss.NewStyle().
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
		// Use cached protocol style
		style := p.getCachedStyle(pkt.Protocol)
		return style.Render(row)
	}
}

// rebuildStyleCache rebuilds the cached lipgloss styles
func (p *PacketList) rebuildStyleCache() {
	// Cache protocol styles
	p.cachedStyles = make(map[string]lipgloss.Style)
	protocols := []string{"TCP", "UDP", "SIP", "RTP", "DNS", "HTTP", "HTTPS", "TLS", "SSL", "ICMP"}
	for _, proto := range protocols {
		p.cachedStyles[proto] = lipgloss.NewStyle().Foreground(p.getProtocolColor(proto))
	}
	p.cachedStyles["default"] = lipgloss.NewStyle().Foreground(p.theme.Foreground)

	// Cache header style
	p.cachedHeaderStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(p.theme.HeaderBg).
		Reverse(true)

	// Cache border styles
	p.cachedBorderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(p.theme.BorderColor)
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

// getCachedStyle returns a cached style for a protocol
func (p *PacketList) getCachedStyle(protocol string) lipgloss.Style {
	if style, ok := p.cachedStyles[protocol]; ok {
		return style
	}
	return p.cachedStyles["default"]
}
