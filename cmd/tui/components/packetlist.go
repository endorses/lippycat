//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Type aliases for backward compatibility within TUI
// These types are now defined in internal/pkg/types to enable sharing
// across the codebase without violating Go architecture principles.
type (
	VoIPMetadata  = types.VoIPMetadata
	PacketDisplay = types.PacketDisplay
)

// PacketList is a component that displays a list of packets
type PacketList struct {
	packets        []PacketDisplay
	cursor         int // Currently selected packet
	offset         int // Scroll offset
	width          int
	height         int
	headerHeight   int
	autoScroll     bool         // Whether to auto-scroll to bottom (like chat)
	theme          themes.Theme // Color theme
	detailsVisible bool         // Whether details panel is visible (affects column widths)

	// Cached rendering state (invalidated on size/theme change)
	cachedStyles      map[string]lipgloss.Style // protocol -> style
	cachedColWidths   [7]int                    // column widths cache
	cachedBorderStyle lipgloss.Style            // border style cache
	cachedHeaderStyle lipgloss.Style            // header style cache
	sizeChanged       bool                      // flag to recalculate caches
}

// NewPacketList creates a new packet list component
func NewPacketList() PacketList {
	p := PacketList{
		packets:      make([]PacketDisplay, 0, 10000), // Pre-allocate for typical buffer size
		cursor:       0,
		offset:       0,
		width:        80,
		height:       20,
		headerHeight: 2,                  // Header + separator
		autoScroll:   true,               // Start with auto-scroll enabled
		theme:        themes.Solarized(), // Default theme
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
	oldLen := len(p.packets)
	newLen := len(packets)
	wasAtBottom := (oldLen == 0) || (p.cursor >= oldLen-1)

	// Store the currently selected packet (if any) to try to preserve selection
	var selectedPacket *PacketDisplay
	if oldLen > 0 && p.cursor >= 0 && p.cursor < oldLen {
		pkt := p.packets[p.cursor]
		selectedPacket = &pkt
	}

	// Detect if this is a filter change (drastic change in packet list)
	// This happens when:
	// 1. Old first packet is not found near the start of new list
	// 2. New list is significantly smaller than old list (newLen < oldLen * 0.8) - applying filter
	// OR when new list is significantly larger (newLen > oldLen * 1.3) - clearing filter
	isFilterChange := false
	if oldLen > 0 && newLen > 0 {
		sizeRatio := float64(newLen) / float64(oldLen)
		if sizeRatio < 0.8 || sizeRatio > 1.3 {
			// Check if old first packet is at/near the start of new list
			oldFirstPacket := p.packets[0]
			foundAtStart := false
			// For filter changes, old first packet should be at index 0 or very close
			// If it's found further in (index > 2), it's likely a filter change
			for i := 0; i < newLen && i < 3; i++ {
				if packets[i].Timestamp.Equal(oldFirstPacket.Timestamp) &&
					packets[i].SrcIP == oldFirstPacket.SrcIP &&
					packets[i].DstIP == oldFirstPacket.DstIP &&
					packets[i].SrcPort == oldFirstPacket.SrcPort &&
					packets[i].DstPort == oldFirstPacket.DstPort {
					foundAtStart = true
					break
				}
			}
			// If old first packet is not at the start of new list, it's a filter change
			if !foundAtStart {
				isFilterChange = true
			}
		}
	}

	// When buffer is full (circular buffer wrapping), packets are removed from the front
	// We need to adjust the cursor to compensate for the removed packets
	// Otherwise the cursor "drifts forward" and eventually reaches the bottom
	packetsRemovedFromFront := 0
	if oldLen > 0 && newLen > 0 && !isFilterChange {
		// Find where the old first packet appears in the new list (if at all)
		// This tells us exactly how many packets were removed from the front
		oldFirstPacket := p.packets[0]

		// Search for the old first packet in the new list
		foundIndex := -1
		for i := 0; i < newLen && i < 100; i++ { // Check first 100 to avoid O(n^2) in worst case
			if packets[i].Timestamp.Equal(oldFirstPacket.Timestamp) &&
				packets[i].SrcIP == oldFirstPacket.SrcIP &&
				packets[i].DstIP == oldFirstPacket.DstIP &&
				packets[i].SrcPort == oldFirstPacket.SrcPort &&
				packets[i].DstPort == oldFirstPacket.DstPort {
				foundIndex = i
				break
			}
		}

		if foundIndex > 0 {
			// Old first packet is now at position foundIndex, meaning foundIndex packets were removed
			packetsRemovedFromFront = foundIndex
		} else if foundIndex == -1 && newLen == oldLen {
			// Old first packet not found and buffer size is the same - it was removed
			// Try to find any overlap to calculate the shift
			// Look for the old packet at cursor position in the new list
			if p.cursor > 0 && p.cursor < oldLen {
				oldCursorPacket := p.packets[p.cursor]
				for i := 0; i < newLen && i < p.cursor+100; i++ {
					if packets[i].Timestamp.Equal(oldCursorPacket.Timestamp) &&
						packets[i].SrcIP == oldCursorPacket.SrcIP &&
						packets[i].DstIP == oldCursorPacket.DstIP {
						// Found the cursor packet at index i, it was originally at p.cursor
						// So (p.cursor - i) packets were removed from the front
						shift := p.cursor - i
						if shift > 0 {
							packetsRemovedFromFront = shift
						}
						break
					}
				}
			}
		}
	}

	// Store old packets before updating
	oldPackets := p.packets
	p.packets = packets

	// If this is a filter change, try to preserve the selected packet
	if isFilterChange {
		// Reset offset first - we'll recalculate it after finding the packet
		p.offset = 0

		// Try to find the selected packet in the new list
		if selectedPacket != nil && len(p.packets) > 0 {
			// First, try exact match
			foundIndex := -1
			for i := 0; i < len(p.packets); i++ {
				if p.packets[i].Timestamp.Equal(selectedPacket.Timestamp) &&
					p.packets[i].SrcIP == selectedPacket.SrcIP &&
					p.packets[i].DstIP == selectedPacket.DstIP &&
					p.packets[i].SrcPort == selectedPacket.SrcPort &&
					p.packets[i].DstPort == selectedPacket.DstPort {
					foundIndex = i
					break
				}
			}

			// If exact match not found, find closest packet by timestamp
			if foundIndex == -1 {
				// Binary search for closest timestamp
				closestIndex := 0
				minDiff := selectedPacket.Timestamp.Sub(p.packets[0].Timestamp)
				minDiff = max(-minDiff, minDiff)

				for i := 1; i < len(p.packets); i++ {
					diff := selectedPacket.Timestamp.Sub(p.packets[i].Timestamp)
					diff = max(-diff, diff)
					if diff < minDiff {
						minDiff = diff
						closestIndex = i
					}
					// Stop searching if we've gone past the target time
					if p.packets[i].Timestamp.After(selectedPacket.Timestamp) {
						break
					}
				}
				foundIndex = closestIndex
			}

			if foundIndex != -1 {
				// Selected packet (or closest) found - keep it selected
				p.cursor = foundIndex

				// Center the selected packet in the view (or position it nicely)
				contentHeight := p.height - 3
				visibleLines := contentHeight - p.headerHeight
				if visibleLines < 1 {
					visibleLines = 1
				}

				// Try to center the cursor, but ensure we show from the top if there aren't enough packets above
				idealOffset := p.cursor - (visibleLines / 3) // Position at top third for better context
				if idealOffset < 0 {
					p.offset = 0
				} else if idealOffset > len(p.packets)-visibleLines {
					// Ensure we don't scroll past the end
					p.offset = max(0, len(p.packets)-visibleLines)
				} else {
					p.offset = idealOffset
				}

				p.autoScroll = false
				return
			}
		}
		// No packets or couldn't find anything - go to top
		p.cursor = 0
		p.offset = 0
		p.autoScroll = false
		return
	}

	// Adjust cursor position if packets were removed from the front
	// This keeps the cursor pointing at the same relative position in the list
	if packetsRemovedFromFront > 0 && !wasAtBottom {
		p.cursor -= packetsRemovedFromFront
		if p.cursor < 0 {
			p.cursor = 0
		}

		// Verify the cursor still points to approximately the same packet
		// by checking if the packet at the cursor position matches expectations
		if p.cursor < len(oldPackets) && p.cursor < len(p.packets) {
			// This is just a sanity check - the packet at cursor should be similar
			// to what was there before (plus packetsRemovedFromFront)
			expectedIndex := p.cursor + packetsRemovedFromFront
			if expectedIndex < len(oldPackets) {
				// We're good - cursor adjustment seems correct
			}
		}
	}

	// Auto-scroll to bottom only if:
	// 1. autoScroll is enabled AND
	// 2. cursor was already at the bottom of the old list (or list was empty)
	// This prevents jumping to the bottom when the user has navigated away
	if p.autoScroll && len(p.packets) > 0 && wasAtBottom {
		p.cursor = len(p.packets) - 1
		p.adjustOffset()
	} else if p.cursor >= len(p.packets) && len(p.packets) > 0 {
		// Cursor is now out of bounds, adjust it to the last valid position
		p.cursor = len(p.packets) - 1
		p.adjustOffset()
	} else {
		// Just adjust offset to keep cursor visible
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

// GetPackets returns the current packet list
func (p *PacketList) GetPackets() []PacketDisplay {
	return p.packets
}

// SetCursor sets the cursor position directly (for mouse clicks)
func (p *PacketList) SetCursor(position int) {
	position = max(0, position)
	if position >= len(p.packets) {
		position = len(p.packets) - 1
	}
	position = max(0, position)
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
func (p *PacketList) View(focused bool, detailsVisible bool) string {
	// Store detailsVisible for column width calculations
	if p.detailsVisible != detailsVisible {
		p.detailsVisible = detailsVisible
		p.sizeChanged = true // Force recalculation of column widths
	}

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
	// When details are hidden, always show unfocused (gray with rounded borders)
	// When details are visible, show focused state based on focused parameter
	borderColor := p.theme.BorderColor
	borderType := lipgloss.RoundedBorder()
	if focused && detailsVisible {
		borderColor = p.theme.SelectionBg   // Cyan when focused
		borderType = lipgloss.ThickBorder() // Heavy box characters when focused
	}

	// Adaptive width: when details hidden, use full width (width - 2)
	// When details visible (split mode), use width with padding (width - 4)
	borderWidth := p.width - 4
	if !detailsVisible {
		borderWidth = p.width - 2
	}

	borderStyle := lipgloss.NewStyle().
		Border(borderType).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(borderWidth).
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
	// Border width is adaptive: p.width - 2 when details hidden, p.width - 4 when details visible
	// Content width = box_width - padding - border
	// Details hidden: (p.width - 2) - 4 (padding) - 2 (border) = p.width - 8
	// Details visible: (p.width - 4) - 4 (padding) - 2 (border) = p.width - 10
	// We add 1 char back for better spacing
	availableWidth := p.width - 8
	if !p.detailsVisible { // Full-width mode (details hidden)
		availableWidth = p.width - 6
	}

	// Define minimum, preferred, and maximum widths
	const (
		nodeMin  = 5  // "Local" or short ID
		nodePref = 12 // Full node ID

		timeMin  = 8  // HH:MM:SS
		timePref = 19 // YYYY-MM-DD HH:MM:SS (2025-10-23 07:48:29)

		srcMin  = 9  // Short IP or partial
		srcPref = 22 // Full IP:Port

		dstMin  = 9
		dstPref = 22

		protoMin  = 3  // Short protocol names
		protoPref = 10 // Longest protocol: "PostgreSQL"

		lenMin  = 4 // Length
		lenPref = 6

		infoMin = 10 // Minimal info
	)

	// Dynamic max widths based on available width
	// For narrow views (details visible), use conservative max for fixed columns
	// For wide views (details hidden), use generous max
	// Info column always gets all remaining space
	var nodeMax, timeMax, srcMax, dstMax, protoMax, lenMax int
	if availableWidth < 100 {
		// Very narrow - use preferred as max
		nodeMax = nodePref
		timeMax = timePref
		srcMax = srcPref
		dstMax = dstPref
		protoMax = protoPref
		lenMax = lenPref
	} else if availableWidth < 150 {
		// Narrow/medium (split view with details) - keep columns compact, give space to Info
		nodeMax = 13
		timeMax = 19
		srcMax = 22
		dstMax = 22
		protoMax = 10
		lenMax = 6
	} else {
		// Wide (full width, no details) - generous max
		nodeMax = 25
		timeMax = 23
		srcMax = 35
		dstMax = 35
		protoMax = 12
		lenMax = 6
	}

	// Start with minimum widths
	totalMin := nodeMin + timeMin + srcMin + dstMin + protoMin + lenMin + infoMin + 6 // +6 for spaces

	if availableWidth < totalMin {
		// Extremely narrow - use absolute minimums
		return nodeMin, timeMin, srcMin, dstMin, protoMin, lenMin, infoMin
	}

	// Calculate with preferred widths
	totalPref := nodePref + timePref + srcPref + dstPref + protoPref + lenPref + infoMin + 6

	if availableWidth < totalPref {
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
		p.sizeChanged = false
		return p.cachedColWidths[0], p.cachedColWidths[1], p.cachedColWidths[2],
			p.cachedColWidths[3], p.cachedColWidths[4], p.cachedColWidths[5], p.cachedColWidths[6]
	}

	// Wide terminal - expand columns beyond preferred up to max, then give rest to info
	totalMax := nodeMax + timeMax + srcMax + dstMax + protoMax + lenMax + infoMin + 6

	if availableWidth >= totalMax {
		// Very wide - use max widths + remaining for info
		infoWidth = availableWidth - nodeMax - timeMax - srcMax - dstMax - protoMax - lenMax - 6
		p.cachedColWidths = [7]int{nodeMax, timeMax, srcMax, dstMax, protoMax, lenMax, infoWidth}
		p.sizeChanged = false
		return nodeMax, timeMax, srcMax, dstMax, protoMax, lenMax, infoWidth
	}

	// Between preferred and max - scale proportionally
	remaining := availableWidth - totalPref

	// Distribute remaining space to expand columns toward max
	nodeExtra := min(remaining/7, nodeMax-nodePref)
	remaining -= nodeExtra

	timeExtra := min(remaining/6, timeMax-timePref)
	remaining -= timeExtra

	srcExtra := min(remaining/5, srcMax-srcPref)
	remaining -= srcExtra

	dstExtra := min(remaining/4, dstMax-dstPref)
	remaining -= dstExtra

	protoExtra := min(remaining/3, protoMax-protoPref)
	remaining -= protoExtra

	lenExtra := min(remaining/2, lenMax-lenPref)
	remaining -= lenExtra

	// Give remaining to info
	infoWidth = infoMin + remaining

	// Cache the results
	p.cachedColWidths = [7]int{
		nodePref + nodeExtra,
		timePref + timeExtra,
		srcPref + srcExtra,
		dstPref + dstExtra,
		protoPref + protoExtra,
		lenPref + lenExtra,
		infoWidth,
	}
	p.sizeChanged = false

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
		nodeWidth, truncate("Origin", nodeWidth),
		timeWidth, truncate("Time", timeWidth),
		srcWidth, truncate("Src IP:Port", srcWidth),
		dstWidth, truncate("Dst IP:Port", dstWidth),
		protoWidth, truncate("Protocol", protoWidth),
		lenWidth, truncate("Length", lenWidth),
		infoWidth, truncate("Info", infoWidth),
	)

	// Render header with style
	return p.cachedHeaderStyle.Render(header)
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

// isASCII checks if a string contains only ASCII characters
// Fast check to enable optimized truncation path for packet data
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// truncate truncates a string to fit width with ellipsis if needed
// Uses lipgloss.Width() to properly handle Unicode and multi-width characters
// Optimized with ASCII fast-path since packet data is typically ASCII
func truncate(s string, width int) string {
	// Sanitize first to remove problematic characters
	s = sanitizeString(s)

	// Fast path for ASCII strings (common case for IPs, ports, protocols)
	if isASCII(s) {
		if len(s) <= width {
			return s
		}
		if width <= 3 {
			// Too narrow for ellipsis, just truncate
			return s[:width]
		}
		// Truncate with ellipsis
		return s[:width-3] + "..."
	}

	// Slow path for Unicode (rare in packet data)
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

	// Format source: "nodeID (interface)" for remote, just "interface" for local
	var source string
	if pkt.NodeID == "" || pkt.NodeID == "Local" {
		// Local capture - show only interface
		source = pkt.Interface
	} else {
		// Remote capture - show nodeID (interface)
		source = fmt.Sprintf("%s (%s)", pkt.NodeID, pkt.Interface)
	}
	source = truncate(source, nodeWidth)

	// Format timestamp based on available width
	var timeStr string
	if timeWidth >= 23 {
		// Full date + time + milliseconds: "2025-10-23 07:48:29.123"
		timeStr = pkt.Timestamp.Format("2006-01-02 15:04:05.000")
	} else if timeWidth >= 19 {
		// Date + time without milliseconds: "2025-10-23 07:48:29"
		timeStr = pkt.Timestamp.Format("2006-01-02 15:04:05")
	} else if timeWidth >= 15 {
		timeStr = pkt.Timestamp.Format("15:04:05.000000")
	} else if timeWidth >= 12 {
		timeStr = pkt.Timestamp.Format("15:04:05.000")
	} else {
		timeStr = pkt.Timestamp.Format("15:04:05")
	}

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
		nodeWidth, source,
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
		return style.Render(row)
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
	protocols := []string{"TCP", "UDP", "SIP", "RTP", "DNS", "HTTP", "HTTPS", "HTTP2", "gRPC", "TLS", "SSL", "SSH", "ICMP", "ICMPv6", "ARP", "OpenVPN", "WireGuard", "IKEv2", "IKEv1", "L2TP", "PPTP"}
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
	case "HTTP", "HTTPS", "HTTP2", "gRPC":
		return p.theme.HTTPColor
	case "TLS", "SSL":
		return p.theme.TLSColor
	case "SSH":
		return p.theme.SSHColor
	case "ICMP":
		return p.theme.ICMPColor
	case "ICMPv6":
		return p.theme.ICMPv6Color
	case "ARP":
		return p.theme.ARPColor
	case "OpenVPN", "WireGuard", "IKEv2", "IKEv1", "L2TP", "PPTP":
		return p.theme.VPNColor
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
