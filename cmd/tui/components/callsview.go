//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

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
	CallID       string
	From         string
	To           string
	State        CallState
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Codec        string
	PacketCount  int
	PacketLoss   float64
	Jitter       float64
	MOS          float64 // Mean Opinion Score
	NodeID       string  // Which hunter/processor captured this
}

// CallsView displays active VoIP calls
type CallsView struct {
	calls         []Call
	selected      int
	offset        int
	width         int
	height        int
	theme         themes.Theme
	showDetails   bool
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
		}
	}
	return nil
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
	// Column widths
	callIDWidth := 20
	fromWidth := 20
	toWidth := 20
	stateWidth := 10
	durationWidth := 10
	codecWidth := 10
	qualityWidth := 8
	nodeWidth := cv.width - callIDWidth - fromWidth - toWidth - stateWidth - durationWidth - codecWidth - qualityWidth - 10

	if nodeWidth < 8 {
		nodeWidth = 8
	}

	// Styles
	headerStyle := lipgloss.NewStyle().
		Foreground(cv.theme.HeaderFg).
		Bold(true).
		Padding(0, 1)

	rowStyle := lipgloss.NewStyle().
		Foreground(cv.theme.Foreground).
		Padding(0, 1)

	selectedStyle := lipgloss.NewStyle().
		Foreground(cv.theme.SelectionFg).
		Background(cv.theme.SelectionBg).
		Bold(true).
		Padding(0, 1)

	borderStyle := lipgloss.NewStyle().
		Foreground(cv.theme.BorderColor).
		Border(lipgloss.NormalBorder())

	// Build header
	var rows []string
	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
		callIDWidth, "Call ID",
		fromWidth, "From",
		toWidth, "To",
		stateWidth, "State",
		durationWidth, "Duration",
		codecWidth, "Codec",
		qualityWidth, "Quality",
		nodeWidth, "Node")
	rows = append(rows, headerStyle.Render(header))
	rows = append(rows, strings.Repeat("─", cv.width-4))

	// Build rows
	visibleStart := cv.offset
	visibleEnd := cv.offset + cv.height - 4
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

		// Format quality (MOS score)
		quality := fmt.Sprintf("%.1f", call.MOS)
		if call.MOS == 0 {
			quality = "N/A"
		}

		// State color
		state := call.State.String()

		row := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
			callIDWidth, truncate(call.CallID, callIDWidth),
			fromWidth, truncate(call.From, fromWidth),
			toWidth, truncate(call.To, toWidth),
			stateWidth, state,
			durationWidth, formatDuration(int64(duration)),
			codecWidth, truncate(call.Codec, codecWidth),
			qualityWidth, quality,
			nodeWidth, truncate(call.NodeID, nodeWidth))

		if i == cv.selected {
			rows = append(rows, selectedStyle.Render(row))
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
			rows = append(rows, style.Render(row))
		}
	}

	// Pad remaining space
	for len(rows) < cv.height-2 {
		rows = append(rows, "")
	}

	content := strings.Join(rows, "\n")
	return borderStyle.Width(cv.width - 4).Height(cv.height - 2).Render(content)
}

// renderSplitView shows table + details
func (cv *CallsView) renderSplitView() string {
	// For now, just show the table
	// TODO: Add split view with call details
	return cv.renderTable()
}

// Helper functions - use truncate and formatDuration from other components
// (defined in nodesview.go and packetlist.go)
