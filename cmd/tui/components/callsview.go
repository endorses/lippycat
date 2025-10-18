//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/components/nodesview"
	"github.com/endorses/lippycat/cmd/tui/themes"
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
	calls       []Call
	selected    int
	offset      int
	width       int
	height      int
	theme       themes.Theme
	showDetails bool
}

// NewCallsView creates a new calls view
func NewCallsView() CallsView {
	return CallsView{
		calls:       make([]Call, 0),
		selected:    0,
		offset:      0,
		showDetails: false,
		theme:       themes.Solarized(),
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

// View renders the calls view
func (cv *CallsView) View() string {
	if len(cv.calls) == 0 {
		return cv.renderEmpty()
	}

	if cv.showDetails && cv.GetSelected() != nil {
		return cv.renderSplitView()
	}

	return cv.renderTable()
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

// renderTable shows the calls table
func (cv *CallsView) renderTable() string {
	// Calculate responsive column widths based on available width
	// Match packet list calculation exactly
	// Border width is adaptive: cv.width - 2 when details hidden, cv.width - 4 when details visible
	// Content width = box_width - padding - border
	// Details hidden: (cv.width - 2) - 4 (padding) - 2 (border) = cv.width - 8
	// Details visible: (cv.width - 4) - 4 (padding) - 2 (border) = cv.width - 10
	// We add 1 char back for better spacing
	// CallsView is always full-width (no split view), so always use the "details hidden" calculation
	availableWidth := cv.width - 6

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

	// Border width for full-width mode (no split view)
	// Match packet list: width - 2 when details hidden
	borderWidth := cv.width - 2

	borderStyle := lipgloss.NewStyle().
		Foreground(cv.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(borderWidth)

	var content strings.Builder
	content.WriteString(headerStyle.Render(header))
	content.WriteString("\n")

	// Build rows
	contentHeight := cv.height - 3    // Account for border overhead
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
		startTime := call.StartTime.Format("15:04:05.000")
		endTime := "N/A"
		if !call.EndTime.IsZero() {
			endTime = call.EndTime.Format("15:04:05.000")
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

// renderSplitView shows table + details
func (cv *CallsView) renderSplitView() string {
	// For now, just show the table
	// TODO: Add split view with call details
	return cv.renderTable()
}

// Note: TruncateString() and FormatDuration() helper functions are now
// imported from cmd/tui/components/nodesview package
