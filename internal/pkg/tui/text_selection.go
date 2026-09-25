//go:build tui || all

package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/selection"
)

type mouseTextSelection struct {
	selection.Selection
	press     tea.MouseMsg
	region    selection.Rect
	pressLine string
}

func (m Model) textSelectionAllowed() bool {
	return !m.offlineOpening && m.offlineFilter == nil && !m.uiState.Quitting &&
		!m.uiState.ProtocolSelector.IsActive() && !m.uiState.HunterSelector.IsActive() &&
		!m.uiState.FilterManager.IsActive() && !m.uiState.SettingsView.IsFileDialogActive() &&
		!m.uiState.FileDialog.IsActive() && !m.uiState.ConfirmDialog.IsActive() &&
		!m.uiState.NodesView.IsModalOpen() &&
		(m.uiState.DevConsole == nil || !m.uiState.DevConsole.IsVisible())
}

// Click actions are deferred until release so dragging a row cannot change the
// details, toggle a pane, or activate a control. Scrollbars bypass this handler.
func (m Model) handleTextSelectionMouse(msg tea.MouseMsg) (Model, tea.Cmd) {
	if m.textSelection != nil {
		switch msg.Action {
		case tea.MouseActionMotion:
			m.textSelection.Move(msg.X, msg.Y)
			return m, nil
		case tea.MouseActionRelease:
			selected := m.textSelection
			m.textSelection = nil
			if selected.Dragged() {
				// Some terminals omit coordinates on release. Motion is the
				// authoritative endpoint, so release never moves the selection.
				m.uiState.LastClickTime = time.Time{}
				m.uiState.LastEventClickTime = time.Time{}
				m.offlineLastClickValid = false
				if text := selected.Text(); strings.TrimSpace(text) != "" {
					return m, copyTextCmd(text)
				}
				return m, nil
			}
			// Live arrivals can move a row while the snapshot is displayed.
			// Never apply a deferred click to a different visible row.
			if selectionClickLine(m.View(), selected.region, selected.press.Y) == selected.pressLine {
				return m.handleMouse(selected.press)
			}
			return m, nil
		default:
			// A new click or wheel gesture dismisses the pending selection.
			m.textSelection = nil
		}
	}
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft && m.textSelectionAllowed() {
		// Render once before resolving regions: legacy components prepare
		// their viewport on render. The snapshot also keeps live arrivals
		// from changing the text under the pointer during a drag.
		view := m.View()
		if region, ok := m.textSelectionRegion(msg.X, msg.Y); ok {
			m.textSelection = &mouseTextSelection{
				Selection: selection.New(view, region, msg.X, msg.Y), press: msg,
				region: region, pressLine: selectionClickLine(view, region, msg.Y),
			}
			return m, nil
		}
	}
	return m.handleMouse(msg)
}

func selectionClickLine(view string, region selection.Rect, y int) string {
	lines := strings.Split(view, "\n")
	if y < 0 || y >= len(lines) {
		return ""
	}
	return ansi.Strip(ansi.Cut(lines[y], region.X, region.X+region.Width))
}

func (m Model) textSelectionRegion(x, y int) (selection.Rect, bool) {
	top := lipgloss.Height(m.uiState.Header.View()) + lipgloss.Height(m.uiState.Tabs.View())
	var region selection.Rect
	var ok bool
	switch m.uiState.Tabs.GetActive() {
	case 0:
		return m.captureTextSelectionRegion(x, y, top)
	case 1:
		region, ok = m.uiState.NodesView.TextSelectionAt(x, y-top)
	case 2:
		region, ok = m.uiState.StatisticsView.TextSelectionAt(x, y-top)
	case 4:
		region, ok = m.uiState.HelpView.TextSelectionAt(x, y-top)
	}
	region.Y += top
	return region, ok
}

func captureTextBody(left, top int, pane string) selection.Rect {
	return selection.Rect{X: left + 3, Y: top + 2, Width: max(0, lipgloss.Width(pane)-6), Height: max(0, lipgloss.Height(pane)-4)}
}

func (m Model) captureTextSelectionRegion(x, y, top int) (selection.Rect, bool) {
	height := m.uiState.Height - 10
	width := m.uiState.Width
	var list, details string
	packetDetails := false
	switch m.uiState.ViewMode {
	case "events":
		if m.uiState.EventShowDetails && width >= 160 {
			list = m.uiState.EventsView.RenderTimeline(width-79, height, m.uiState.FocusedPane == "left")
			details = m.uiState.EventsView.RenderDetails(77, height, m.uiState.FocusedPane == "right")
		} else {
			list = m.uiState.EventsView.RenderTimeline(width, height, false)
		}
	case "calls":
		if m.uiState.CallsView.IsShowingDetails() && width >= 120 {
			list = m.uiState.CallsView.RenderTable(width-79, height, m.uiState.FocusedPane == "left")
			details = m.uiState.CallsView.RenderDetails(79, height, m.uiState.FocusedPane == "right")
		} else {
			list = m.uiState.CallsView.View()
		}
	case "packets", "":
		packetDetails = m.uiState.ShowDetails && width >= 160
		list = m.uiState.PacketList.View(m.uiState.FocusedPane == "left", packetDetails)
		if packetDetails {
			details = m.uiState.DetailsPanel.View(m.uiState.FocusedPane == "right")
		}
	default:
		return selection.Rect{}, false
	}
	region := captureTextBody(0, top, list)
	if region.Contains(x, y) {
		return region, true
	}
	if details == "" {
		return selection.Rect{}, false
	}
	left := lipgloss.Width(list)
	if packetDetails {
		region, ok := m.uiState.DetailsPanel.TextSelectionAt(x-left, y-top)
		region.X += left
		region.Y += top
		return region, ok
	}
	region = captureTextBody(left, top, details)
	return region, region.Contains(x, y)
}
