//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// extractSIPURI extracts the SIP URI from a header value, removing display names and parameters
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "sip:alicent@domain.com"
// Example: "<sip:robb@example.org>;tag=456" -> "sip:robb@example.org"
// Example: "sip:robb@example.org;tag=456" -> "sip:robb@example.org"
func extractSIPURI(header string) string {
	// Find the URI between < and > if present
	start := strings.Index(header, "<")
	if start != -1 {
		end := strings.Index(header[start:], ">")
		if end != -1 {
			return header[start+1 : start+end]
		}
	}

	// No angle brackets, find sip: or sips: prefix
	sipStart := strings.Index(header, "sip:")
	if sipStart == -1 {
		sipStart = strings.Index(header, "sips:")
		if sipStart == -1 {
			return header // Return original if no SIP URI found
		}
	}

	// Find the end of the URI (space, semicolon, or newline)
	uri := header[sipStart:]
	for i, ch := range uri {
		if ch == ' ' || ch == ';' || ch == '\r' || ch == '\n' || ch == '>' {
			return uri[:i]
		}
	}

	return uri
}

// CallState represents the state of a VoIP call
type CallState int

const (
	CallStateRinging CallState = iota
	CallStateActive
	CallStateEnded
	CallStateFailed
)

func (cs CallState) String() string {
	switch cs {
	case CallStateRinging:
		return "Ringing"
	case CallStateActive:
		return "Active"
	case CallStateEnded:
		return "Ended"
	case CallStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// Call represents a tracked VoIP call
type Call struct {
	CallID      string
	From        string
	To          string
	State       CallState
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	Codec       string
	PacketCount int
	PacketLoss  float64
	Jitter      float64
	MOS         float64 // Mean Opinion Score
	NodeID      string  // Which hunter/processor captured this
}

// CallsView displays active VoIP calls
type CallsView struct {
	calls            []Call
	selected         int
	offset           int
	width            int
	height           int
	theme            themes.Theme
	showDetails      bool
	correlatedCalls  map[string]*CorrelatedCall // Map from Call-ID to correlated call data
	correlatedCallMu sync.RWMutex               // Protect concurrent access to correlatedCalls
}

// CorrelatedCall represents a correlated call with multiple legs
type CorrelatedCall struct {
	CorrelationID string
	TagPair       [2]string
	FromUser      string
	ToUser        string
	Legs          []CallLeg
	StartTime     time.Time
	LastSeen      time.Time
	State         string
}

// CallLeg represents one leg of a multi-hop call
type CallLeg struct {
	CallID       string
	HunterID     string
	SrcIP        string
	DstIP        string
	Method       string
	ResponseCode uint32
	PacketCount  int
	StartTime    time.Time
	LastSeen     time.Time
}

// NewCallsView creates a new calls view
func NewCallsView() CallsView {
	return CallsView{
		calls:           make([]Call, 0),
		selected:        0,
		offset:          0,
		showDetails:     false,
		theme:           themes.Solarized(),
		correlatedCalls: make(map[string]*CorrelatedCall),
	}
}

// SetTheme sets the color theme
func (cv *CallsView) SetTheme(theme themes.Theme) {
	cv.theme = theme
}

// SetSize sets the dimensions
func (cv *CallsView) SetSize(width, height int) {
	cv.width = width
	cv.height = height
}

// SetCalls updates the call list
func (cv *CallsView) SetCalls(calls []Call) {
	// Sort calls: first by start timestamp, then by call ID
	sort.Slice(calls, func(i, j int) bool {
		if calls[i].StartTime.Equal(calls[j].StartTime) {
			return calls[i].CallID < calls[j].CallID
		}
		return calls[i].StartTime.Before(calls[j].StartTime)
	})

	cv.calls = calls
	// Adjust selection if needed
	if cv.selected >= len(cv.calls) && len(cv.calls) > 0 {
		cv.selected = len(cv.calls) - 1
	}
	if cv.selected < 0 {
		cv.selected = 0
	}
}

// GetSelected returns the currently selected call
func (cv *CallsView) GetSelected() *Call {
	if cv.selected >= 0 && cv.selected < len(cv.calls) {
		return &cv.calls[cv.selected]
	}
	return nil
}

// SelectNext moves selection down
func (cv *CallsView) SelectNext() {
	if cv.selected < len(cv.calls)-1 {
		cv.selected++
		// Auto-scroll
		if cv.selected-cv.offset >= cv.height-4 {
			cv.offset++
		}
	}
}

// SelectPrevious moves selection up
func (cv *CallsView) SelectPrevious() {
	if cv.selected > 0 {
		cv.selected--
		// Auto-scroll
		if cv.selected < cv.offset {
			cv.offset = cv.selected
		}
	}
}

// ToggleDetails toggles the details panel
func (cv *CallsView) ToggleDetails() {
	cv.showDetails = !cv.showDetails
}

// IsShowingDetails returns whether the details panel is visible
func (cv *CallsView) IsShowingDetails() bool {
	return cv.showDetails
}

// SetCorrelatedCalls updates the correlated calls data
func (cv *CallsView) SetCorrelatedCalls(correlatedCallsInfo []types.CorrelatedCallInfo) {
	cv.correlatedCallMu.Lock()
	defer cv.correlatedCallMu.Unlock()

	// Import types package at the top of the file
	// Convert types.CorrelatedCallInfo to internal CorrelatedCall
	for _, info := range correlatedCallsInfo {
		cc := &CorrelatedCall{
			CorrelationID: info.CorrelationID,
			TagPair:       info.TagPair,
			FromUser:      info.FromUser,
			ToUser:        info.ToUser,
			StartTime:     info.StartTime,
			LastSeen:      info.LastSeen,
			State:         info.State,
			Legs:          make([]CallLeg, len(info.Legs)),
		}

		// Convert legs
		for i, leg := range info.Legs {
			cc.Legs[i] = CallLeg{
				CallID:       leg.CallID,
				HunterID:     leg.HunterID,
				SrcIP:        leg.SrcIP,
				DstIP:        leg.DstIP,
				Method:       leg.Method,
				ResponseCode: leg.ResponseCode,
				PacketCount:  leg.PacketCount,
				StartTime:    leg.StartTime,
				LastSeen:     leg.LastSeen,
			}

			// Index by Call-ID for quick lookup
			cv.correlatedCalls[leg.CallID] = cc
		}
	}
}

// Update handles messages
func (cv *CallsView) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			cv.SelectPrevious()
		case "down", "j":
			cv.SelectNext()
		case "d":
			cv.ToggleDetails()
		case "home", "g":
			if len(cv.calls) > 0 {
				cv.selected = 0
				cv.offset = 0
			}
		case "end", "G":
			if len(cv.calls) > 0 {
				cv.selected = len(cv.calls) - 1
				cv.adjustOffset()
			}
		case "pgup":
			cv.PageUp()
		case "pgdown":
			cv.PageDown()
		}
	case tea.MouseMsg:
		if msg.Type == tea.MouseLeft {
			cv.HandleMouseClick(msg.Y)
		}
	}
	return nil
}

// HandleMouseClick handles mouse clicks on call rows
func (cv *CallsView) HandleMouseClick(mouseY int) {
	// Calculate which row was clicked
	// Header is at row 3 (border top + padding + header line)
	// Content starts at row 4
	headerOffset := 4
	if mouseY < headerOffset {
		return // Clicked on header or above
	}

	clickedRow := mouseY - headerOffset + cv.offset
	if clickedRow >= 0 && clickedRow < len(cv.calls) {
		cv.selected = clickedRow
		cv.adjustOffset()
	}
}

// adjustOffset ensures the selected call is visible
func (cv *CallsView) adjustOffset() {
	contentHeight := cv.height - 3
	visibleLines := contentHeight - 2 // Subtract header lines
	if visibleLines < 1 {
		visibleLines = 1
	}

	// Cursor above visible area
	if cv.selected < cv.offset {
		cv.offset = cv.selected
	}

	// Cursor below visible area
	if cv.selected >= cv.offset+visibleLines {
		cv.offset = cv.selected - visibleLines + 1
	}

	// Ensure offset is valid
	if cv.offset < 0 {
		cv.offset = 0
	}
}

// PageUp moves up one page
func (cv *CallsView) PageUp() {
	contentHeight := cv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	cv.selected -= pageSize
	if cv.selected < 0 {
		cv.selected = 0
	}
	cv.adjustOffset()
}

// PageDown moves down one page
func (cv *CallsView) PageDown() {
	contentHeight := cv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	cv.selected += pageSize
	if cv.selected >= len(cv.calls) {
		cv.selected = len(cv.calls) - 1
	}
	if cv.selected < 0 {
		cv.selected = 0
	}
	cv.adjustOffset()
}

// View renders the calls view (full width)
func (cv *CallsView) View() string {
	if len(cv.calls) == 0 {
		return cv.renderEmpty()
	}

	// Full width table
	return cv.RenderTable(cv.width, cv.height)
}

// RenderTable renders just the calls table with specified width and height
func (cv *CallsView) RenderTable(width, height int) string {
	if len(cv.calls) == 0 {
		style := lipgloss.NewStyle().
			Foreground(cv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("No active VoIP calls")
	}

	return cv.renderTableWithSize(width, height)
}

// RenderDetails renders the call details panel
func (cv *CallsView) RenderDetails(width, height int) string {
	selectedCall := cv.GetSelected()
	if selectedCall == nil {
		// No call selected
		style := lipgloss.NewStyle().
			Foreground(cv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("Select a call to view details")
	}

	return cv.renderCallDetails(selectedCall, width, height)
}

// renderEmpty shows a message when no calls are present
func (cv *CallsView) renderEmpty() string {
	style := lipgloss.NewStyle().
		Foreground(cv.theme.StatusBarFg).
		Italic(true).
		Width(cv.width).
		Height(cv.height).
		Align(lipgloss.Center, lipgloss.Center)

	return style.Render("No active VoIP calls")
}

// renderTableWithSize shows the calls table with specified dimensions
func (cv *CallsView) renderTableWithSize(width, height int) string {
	// Calculate responsive column widths based on available width
	// Match packet list calculation exactly
	// Border width is adaptive: width - 2 when details hidden, width - 4 when details visible
	// Content width = box_width - padding - border
	// Details hidden: (width - 2) - 4 (padding) - 2 (border) = width - 8
	// Details visible: (width - 4) - 4 (padding) - 2 (border) = width - 10
	// We add 1 char back for better spacing
	availableWidth := width - 6

	// Define column width ranges
	const (
		startTimeMin = 12 // HH:MM:SS.ms
		endTimeMin   = 12
		fromMin      = 15
		fromMax      = 40
		toMin        = 15
		toMax        = 40
		stateMin     = 10
		durationMin  = 8
		codecMin     = 9
		qualityMin   = 8
		nodeMin      = 10
		nodeMax      = 20
		callIDMin    = 20
		callIDMax    = 40
	)

	// Calculate total minimum width needed
	minTotal := callIDMin + startTimeMin + endTimeMin + fromMin + toMin + stateMin + durationMin + codecMin + qualityMin + nodeMin // + 9

	var callIDWidth, startTimeWidth, endTimeWidth, fromWidth, toWidth, stateWidth, durationWidth, codecWidth, qualityWidth, nodeWidth int

	if availableWidth < minTotal {
		// Very narrow terminal - use absolute minimums and give remaining to CallID
		startTimeWidth = 8 // HH:MM:SS
		endTimeWidth = 8
		fromWidth = 8
		toWidth = 8
		stateWidth = 6
		durationWidth = 6
		codecWidth = 4
		qualityWidth = 3
		nodeWidth = 8
		// Give all remaining space to CallID
		fixedNarrow := startTimeWidth + endTimeWidth + fromWidth + toWidth + stateWidth + durationWidth + codecWidth + qualityWidth + nodeWidth + 9
		callIDWidth = availableWidth - fixedNarrow
		if callIDWidth < 10 {
			callIDWidth = 10 // Minimum for CallID
		}
	} else if availableWidth < minTotal+40 {
		// Narrow terminal - use minimums and give remaining to CallID
		startTimeWidth = startTimeMin
		endTimeWidth = endTimeMin
		fromWidth = fromMin
		toWidth = toMin
		stateWidth = stateMin
		durationWidth = durationMin
		codecWidth = codecMin
		qualityWidth = qualityMin
		nodeWidth = nodeMin
		// Give all remaining space to CallID
		fixedNarrow := startTimeWidth + endTimeWidth + fromWidth + toWidth + stateWidth + durationWidth + codecWidth + qualityWidth + nodeWidth + 9
		callIDWidth = availableWidth - fixedNarrow
		if callIDWidth < callIDMin {
			callIDWidth = callIDMin
		}
	} else {
		// Wide terminal - distribute extra space
		// Fixed columns that don't expand
		startTimeWidth = startTimeMin
		endTimeWidth = endTimeMin
		stateWidth = stateMin
		durationWidth = durationMin
		codecWidth = codecMin
		qualityWidth = qualityMin

		// First, try to expand flexible columns up to their max
		// Then give ALL remaining space to CallID (like Info column in PacketList)
		callIDWidth = callIDMin
		fromWidth = fromMin
		toWidth = toMin
		nodeWidth = nodeMin

		// Calculate what's left after fixed columns and minimums of flexible columns
		fixedTotal := startTimeWidth + endTimeWidth + stateWidth + durationWidth + codecWidth + qualityWidth + 9
		flexibleTotal := callIDWidth + fromWidth + toWidth + nodeWidth
		remaining := availableWidth - fixedTotal - flexibleTotal

		if remaining > 0 {
			// Expand flexible columns toward max, but keep track of unused space
			fromExtra := min(remaining, fromMax-fromMin)
			remaining -= fromExtra
			fromWidth += fromExtra

			toExtra := min(remaining, toMax-toMin)
			remaining -= toExtra
			toWidth += toExtra

			nodeExtra := min(remaining, nodeMax-nodeMin)
			remaining -= nodeExtra
			nodeWidth += nodeExtra

			// Give ALL remaining space to CallID (no max limit)
			callIDWidth += remaining
		}
	}

	// Header style - match packet list style (bold, reversed)
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(cv.theme.HeaderBg).
		Reverse(true).
		Inline(true)

	rowStyle := lipgloss.NewStyle().
		Foreground(cv.theme.Foreground).
		Inline(true)

	selectedStyle := lipgloss.NewStyle().
		Foreground(cv.theme.SelectionBg).
		Reverse(true).
		Bold(true).
		Inline(true)

	// Build header - match packet list format
	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
		callIDWidth, truncateCallsView("Call ID", callIDWidth),
		fromWidth, truncateCallsView("From", fromWidth),
		toWidth, truncateCallsView("To", toWidth),
		startTimeWidth, truncateCallsView("Start", startTimeWidth),
		endTimeWidth, truncateCallsView("End", endTimeWidth),
		stateWidth, truncateCallsView("State", stateWidth),
		durationWidth, truncateCallsView("Duration", durationWidth),
		codecWidth, truncateCallsView("Codec", codecWidth),
		qualityWidth, truncateCallsView("Quality", qualityWidth),
		nodeWidth, truncateCallsView("Node", nodeWidth))

	// Border width depends on whether we're in split view or full width
	// Full width: width - 2
	// Split view: use passed width directly (already accounts for split)
	borderWidth := width - 2

	borderStyle := lipgloss.NewStyle().
		Foreground(cv.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(borderWidth)

	var content strings.Builder
	content.WriteString(headerStyle.Render(header))
	content.WriteString("\n")

	// Build rows
	contentHeight := height - 3       // Account for border overhead
	visibleLines := contentHeight - 2 // Subtract header lines
	if visibleLines < 1 {
		visibleLines = 1
	}

	visibleStart := cv.offset
	visibleEnd := cv.offset + visibleLines
	if visibleEnd > len(cv.calls) {
		visibleEnd = len(cv.calls)
	}

	for i := visibleStart; i < visibleEnd; i++ {
		call := cv.calls[i]

		// Calculate duration
		duration := call.Duration
		if call.State == CallStateActive {
			duration = time.Since(call.StartTime)
		}

		// Format timestamps
		startTime := call.StartTime.Format("2006-01-02 15:04:05.000")
		endTime := "N/A"
		if !call.EndTime.IsZero() {
			endTime = call.EndTime.Format("2006-01-02 15:04:05.000")
		} else if call.State == CallStateActive {
			endTime = "Active"
		}

		// Format quality (MOS score)
		quality := fmt.Sprintf("%.1f", call.MOS)
		if call.MOS == 0 {
			quality = "N/A"
		}

		// State string
		state := call.State.String()

		// Extract clean SIP URIs (remove display names and tag parameters)
		fromURI := extractSIPURI(call.From)
		toURI := extractSIPURI(call.To)

		row := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
			callIDWidth, truncateCallsView(call.CallID, callIDWidth),
			fromWidth, truncateCallsView(fromURI, fromWidth),
			toWidth, truncateCallsView(toURI, toWidth),
			startTimeWidth, truncateCallsView(startTime, startTimeWidth),
			endTimeWidth, truncateCallsView(endTime, endTimeWidth),
			stateWidth, truncateCallsView(state, stateWidth),
			durationWidth, nodesview.FormatDuration(int64(duration)),
			codecWidth, truncateCallsView(call.Codec, codecWidth),
			qualityWidth, quality,
			nodeWidth, truncateCallsView(call.NodeID, nodeWidth))

		if i == cv.selected {
			content.WriteString(selectedStyle.Render(row))
		} else {
			// Color by state
			style := rowStyle
			switch call.State {
			case CallStateActive:
				style = style.Foreground(cv.theme.SuccessColor)
			case CallStateFailed:
				style = style.Foreground(cv.theme.ErrorColor)
			case CallStateEnded:
				style = style.Foreground(cv.theme.StatusBarFg)
			}
			content.WriteString(style.Render(row))
		}

		if i < visibleEnd-1 {
			content.WriteString("\n")
		}
	}

	// Pad remaining space to maintain consistent height
	linesRendered := visibleEnd - visibleStart
	for i := linesRendered; i < visibleLines; i++ {
		if i > 0 || linesRendered > 0 {
			content.WriteString("\n")
		}
	}

	return borderStyle.Height(contentHeight).Render(content.String())
}

// sanitizeCallString removes problematic characters that can break terminal rendering
func sanitizeCallString(s string) string {
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

// truncateCallsView truncates a string to fit width with ellipsis if needed
func truncateCallsView(s string, width int) string {
	// Sanitize first to remove newlines and control characters
	s = sanitizeCallString(s)

	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// renderCallDetails shows call details panel with correlation information
func (cv *CallsView) renderCallDetails(selectedCall *Call, width, height int) string {

	// Look up correlated call data
	cv.correlatedCallMu.RLock()
	correlatedCall, hasCorrelation := cv.correlatedCalls[selectedCall.CallID]
	cv.correlatedCallMu.RUnlock()

	// Title style
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(cv.theme.InfoColor).
		MarginBottom(1)

	// Section header style
	sectionHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(cv.theme.SuccessColor)

	// Build details content
	var content strings.Builder

	// Call Details section
	content.WriteString(titleStyle.Render("📞 Call Details"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Call-ID: %s\n", selectedCall.CallID))
	content.WriteString(fmt.Sprintf("From: %s\n", extractSIPURI(selectedCall.From)))
	content.WriteString(fmt.Sprintf("To: %s\n", extractSIPURI(selectedCall.To)))
	content.WriteString(fmt.Sprintf("State: %s\n", selectedCall.State.String()))

	// Show start time
	if !selectedCall.StartTime.IsZero() {
		content.WriteString(fmt.Sprintf("Started: %s\n", selectedCall.StartTime.Format("2006-01-02 15:04:05.000")))
	}

	// Show end time if available
	if !selectedCall.EndTime.IsZero() {
		content.WriteString(fmt.Sprintf("Ended: %s\n", selectedCall.EndTime.Format("2006-01-02 15:04:05.000")))
	}

	// Calculate duration
	duration := selectedCall.Duration
	if selectedCall.State == CallStateActive {
		duration = time.Since(selectedCall.StartTime)
	}
	content.WriteString(fmt.Sprintf("Duration: %s\n", nodesview.FormatDuration(int64(duration))))

	if selectedCall.Codec != "" {
		content.WriteString(fmt.Sprintf("Codec: %s\n", selectedCall.Codec))
	}
	if selectedCall.MOS > 0 {
		content.WriteString(fmt.Sprintf("Quality (MOS): %.1f\n", selectedCall.MOS))
	}

	// Correlation section (if available)
	if hasCorrelation && correlatedCall != nil && len(correlatedCall.Legs) > 1 {
		content.WriteString("\n")
		content.WriteString(sectionHeaderStyle.Render(fmt.Sprintf("Correlation (%d legs across B2BUA hops):", len(correlatedCall.Legs))))
		content.WriteString("\n\n")

		// Sort legs by start time for chronological display
		legs := make([]CallLeg, len(correlatedCall.Legs))
		copy(legs, correlatedCall.Legs)
		sort.Slice(legs, func(i, j int) bool {
			return legs[i].StartTime.Before(legs[j].StartTime)
		})

		// Render each leg
		for i, leg := range legs {
			legStyle := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(cv.theme.BorderColor).
				Padding(0, 1).
				MarginBottom(1).
				Width(width - 6)

			var legContent strings.Builder
			legContent.WriteString(fmt.Sprintf("Leg %d: %s\n", i+1, leg.HunterID))
			legContent.WriteString(fmt.Sprintf("  Call-ID: %s\n", leg.CallID))
			legContent.WriteString(fmt.Sprintf("  Route: %s → %s\n", leg.SrcIP, leg.DstIP))
			legContent.WriteString(fmt.Sprintf("  Packets: %d\n", leg.PacketCount))

			// Calculate timing delta from first leg
			if i == 0 {
				legContent.WriteString(fmt.Sprintf("  Started: %s\n", leg.StartTime.Format("2006-01-02 15:04:05.000")))
			} else {
				delta := leg.StartTime.Sub(legs[0].StartTime)
				legContent.WriteString(fmt.Sprintf("  Started: %s (+%s)\n",
					leg.StartTime.Format("2006-01-02 15:04:05.000"),
					formatMilliseconds(delta)))
			}

			if leg.Method != "" {
				legContent.WriteString(fmt.Sprintf("  Method: %s\n", leg.Method))
			}
			if leg.ResponseCode > 0 {
				legContent.WriteString(fmt.Sprintf("  Response: %d\n", leg.ResponseCode))
			}

			content.WriteString(legStyle.Render(legContent.String()))
		}

		// Add hint about graph view (for future implementation)
		hintStyle := lipgloss.NewStyle().
			Foreground(cv.theme.StatusBarFg).
			Italic(true)
		content.WriteString("\n")
		content.WriteString(hintStyle.Render("Press 'g' to view call topology graph on Nodes tab (coming soon)"))
	} else if hasCorrelation && correlatedCall != nil {
		content.WriteString("\n")
		content.WriteString(sectionHeaderStyle.Render("Correlation:"))
		content.WriteString("\n")
		content.WriteString("Single leg call (no B2BUA hops detected)\n")
	}

	// Wrap in border
	borderStyle := lipgloss.NewStyle().
		Foreground(cv.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(width - 2).
		Height(height - 2)

	return borderStyle.Render(content.String())
}

// formatMilliseconds formats a duration as milliseconds with unit
func formatMilliseconds(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.3fs", float64(ms)/1000.0)
}

// Note: TruncateString() and FormatDuration() helper functions are now
// imported from cmd/tui/components/nodesview package
