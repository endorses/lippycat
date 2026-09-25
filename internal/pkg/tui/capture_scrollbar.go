//go:build tui || all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// handleCaptureScrollbar handles the right padding column inside each capture
// pane. Its geometry matches renderCaptureTab and captureScrollbar.
func (m Model) handleCaptureScrollbar(msg tea.MouseMsg, contentTop, contentHeight int) (Model, tea.Cmd, bool) {
	trackTop := contentTop + 2
	trackHeight := max(0, contentHeight-4)
	if trackHeight == 0 {
		return m, nil, false
	}
	if msg.Action == tea.MouseActionRelease {
		if m.scrollDrag != "" {
			m.scrollDrag = ""
			return m, nil, true
		}
		return m, nil, false
	}

	target := m.scrollDrag
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		if msg.Y < trackTop || msg.Y >= trackTop+trackHeight {
			return m, nil, false
		}
		listWidth := m.uiState.Width
		details := false
		switch m.uiState.ViewMode {
		case "events":
			details = m.uiState.EventShowDetails && m.uiState.Width >= 160
			if details {
				listWidth -= 79
			}
			listWidth = lipgloss.Width(m.uiState.EventsView.RenderTimeline(listWidth, contentHeight, m.uiState.FocusedPane == "left"))
		case "calls":
			details = m.uiState.CallsView.IsShowingDetails() && m.uiState.Width >= 120
			if details {
				listWidth -= 79
			}
			listWidth = lipgloss.Width(m.uiState.CallsView.RenderTable(listWidth, contentHeight, m.uiState.FocusedPane == "left"))
		default:
			details = m.uiState.ShowDetails && m.uiState.Width >= 160
			listWidth = lipgloss.Width(m.uiState.PacketList.View(m.uiState.FocusedPane == "left", details))
		}
		if msg.X == listWidth-2 {
			target = "list"
		} else if details && msg.X == m.uiState.Width-2 {
			target = "details"
		} else {
			return m, nil, false
		}
	} else if msg.Action != tea.MouseActionMotion || target == "" {
		return m, nil, false
	}

	var total, visible, offset int
	switch m.uiState.ViewMode {
	case "events":
		if target == "list" {
			total, visible, offset = m.uiState.EventsView.TimelineScrollState(contentHeight)
		} else {
			total, visible, offset = m.uiState.EventsView.DetailsScrollState()
		}
	case "calls":
		if target == "list" {
			total, visible, offset = m.uiState.CallsView.TableScrollState(contentHeight)
		} else {
			total, visible, offset = m.uiState.CallsView.DetailsScrollState()
		}
	default:
		if target == "list" {
			total = int(m.uiState.PacketList.LogicalCount())
			visible = m.uiState.PacketList.VisibleRows()
			offset = int(m.uiState.PacketList.LogicalOffset())
		} else {
			total, visible, offset = m.uiState.DetailsPanel.ScrollState()
		}
	}
	if msg.Action == tea.MouseActionPress {
		start, size := components.ScrollbarThumb(total, visible, offset, trackHeight)
		row := msg.Y - trackTop
		m.scrollDrag = target
		m.scrollDragRow = row
		if row >= start && row < start+size {
			m.scrollDragOffset = offset
			return m, nil, true
		}
		newOffset := components.ScrollbarOffsetForRow(total, visible, trackHeight, row, size/2)
		m.scrollDragOffset = newOffset
		if newOffset == offset {
			return m, nil, true
		}
		return m.setCaptureScrollOffset(target, newOffset, contentHeight)
	}
	newOffset := components.ScrollbarOffsetForDrag(total, visible, trackHeight, m.scrollDragOffset, m.scrollDragRow, msg.Y-trackTop)
	if newOffset == offset {
		return m, nil, true
	}
	return m.setCaptureScrollOffset(target, newOffset, contentHeight)
}

func (m Model) setCaptureScrollOffset(target string, newOffset, contentHeight int) (Model, tea.Cmd, bool) {
	if target == "details" {
		m.uiState.FocusedPane = "right"
		switch m.uiState.ViewMode {
		case "events":
			m.uiState.EventsView.SetDetailsScrollOffset(newOffset)
		case "calls":
			m.uiState.CallsView.SetDetailsScrollOffset(newOffset)
		default:
			m.uiState.DetailsPanel.SetScrollOffset(newOffset)
		}
		return m, nil, true
	}
	m.uiState.FocusedPane = "left"
	switch m.uiState.ViewMode {
	case "events":
		if id, ok := m.uiState.EventsView.EventIDAtIndex(newOffset); ok {
			m.eventStore.SelectByIDFollowingLatest(id)
			m.syncEventsView()
		}
		m.uiState.EventsView.SetTimelineScrollOffset(newOffset, contentHeight)
	case "calls":
		m.uiState.CallsView.SetTableScrollOffset(newOffset, contentHeight)
	default:
		m.uiState.PacketList.SetScrollOffset(uint64(newOffset))
		m.updateDetailsPanel()
		if m.offlineSession != nil {
			return m, m.syncOfflineBrowser(), true
		}
	}
	return m, nil, true
}
