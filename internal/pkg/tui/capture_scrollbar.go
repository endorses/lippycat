//go:build tui || all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// handleCaptureScrollbar handles the right padding column inside each capture
// pane. Its geometry matches renderCaptureTab and captureScrollbar.
func (m Model) handleCaptureScrollbar(msg tea.MouseMsg, contentTop, contentHeight int) (Model, tea.Cmd, bool) {
	if msg.Action == tea.MouseActionRelease {
		if m.scrollDrag != "" {
			m.scrollDrag = ""
			return m, nil, true
		}
		return m, nil, false
	}

	layout := m.captureLayout()
	detailX, _, _, _ := components.DetailPaneGeometry(layout.Details.Width, layout.Details.Height)
	detailScrollbarX := layout.Details.X + layout.Details.Width - 1
	if detailX >= 3 {
		detailScrollbarX--
	}
	target := m.scrollDrag
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		switch {
		case layout.List.contains(msg.X, msg.Y-contentTop) && msg.X == layout.List.X+layout.List.Width-2:
			target = "list"
		case detailX > 0 && layout.Details.contains(msg.X, msg.Y-contentTop) && msg.X == detailScrollbarX:
			target = "details"
		default:
			return m, nil, false
		}
	} else if msg.Action != tea.MouseActionMotion || target == "" {
		return m, nil, false
	}
	rect := layout.List
	trackTop := contentTop + rect.Y + 2
	trackHeight := max(0, rect.Height-4)
	if target == "details" {
		rect = layout.Details
		_, bodyY, _, bodyHeight := components.DetailPaneGeometry(rect.Width, rect.Height)
		trackTop = contentTop + rect.Y + bodyY
		trackHeight = bodyHeight
	}
	if rect.Width == 0 || trackHeight == 0 {
		m.scrollDrag = ""
		return m, nil, false
	}
	if msg.Action == tea.MouseActionPress && (msg.Y < trackTop || msg.Y >= trackTop+trackHeight) {
		return m, nil, false
	}
	contentHeight = layout.List.Height

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
	start, size := components.ScrollbarThumb(total, visible, offset, trackHeight)
	if size == 0 {
		m.scrollDrag = ""
		return m, nil, false
	}
	if msg.Action == tea.MouseActionPress {
		if target == "details" {
			m.focusCapturePane("right")
		} else {
			m.focusCapturePane("left")
		}
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
		m.focusCapturePane("right")
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
	m.focusCapturePane("left")
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
