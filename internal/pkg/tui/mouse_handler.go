//go:build tui || all

package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// footerKeyAtMouse translates visible hints before input routing, so settings
// editors and filter inputs receive exactly the same message as a key press.
func (m Model) footerKeyAtMouse(msg tea.MouseMsg) (tea.KeyMsg, bool) {
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress ||
		m.uiState.Width <= 0 || m.uiState.Height <= 0 ||
		msg.X < 0 || msg.X >= m.uiState.Width || msg.Y != m.uiState.Height-1 ||
		!m.textSelectionAllowed() {
		return tea.KeyMsg{}, false
	}

	// The footer is the final rendered row. Bubble Tea preserves the bottom
	// rows when tall content (such as filter input or a toast) exceeds the screen.
	return m.uiState.Footer.KeyAtX(msg.X)
}

// handleMouse processes mouse events for the TUI
func (m Model) handleMouse(msg tea.MouseMsg) (Model, tea.Cmd) {
	var resized bool
	m, resized = m.handleCaptureResize(msg)
	if resized {
		return m, nil
	}
	contentStartY := m.captureContentOrigin()
	contentHeight := m.captureContentHeight()
	if msg.Action == tea.MouseActionRelease && m.uiState.Tabs.GetActive() != 0 {
		m.scrollDrag = ""
	}
	if m.uiState.Tabs.GetActive() == 0 && (m.uiState.ViewMode == "packets" || m.uiState.ViewMode == "calls" || m.uiState.ViewMode == "events") {
		if next, cmd, handled := m.handleCaptureScrollbar(msg, contentStartY, contentHeight); handled {
			return next, cmd
		}
	}
	if msg.Action == tea.MouseActionMotion || msg.Action == tea.MouseActionRelease {
		switch m.uiState.Tabs.GetActive() {
		case 1:
			return m, m.uiState.NodesView.Update(msg)
		case 2:
			return m, m.uiState.StatisticsView.Update(msg)
		case 4:
			return m, m.uiState.HelpView.Update(msg)
		}
		return m, nil
	}

	// Wheel gestures follow the visible pane under the pointer.
	if msg.Action == tea.MouseActionPress && (msg.Button == tea.MouseButtonWheelUp || msg.Button == tea.MouseButtonWheelDown) {
		switch m.uiState.Tabs.GetActive() {
		case 0:
			return m.handleCaptureWheel(msg)
		case 1:
			return m, m.uiState.NodesView.Update(msg)
		case 2:
			return m, m.uiState.StatisticsView.Update(msg)
		case 4:
			return m, m.uiState.HelpView.Update(msg)
		}
		return m, nil
	}

	// Handle clicks - use newer Button and Action fields
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress {
		return m, nil
	}

	tabTop, tabBottom := 2, 5
	if m.uiState.Tabs.GetActive() == 0 && m.responsiveCaptureView() {
		header, tabs, _ := m.captureChrome()
		tabTop = nonemptyHeight(header)
		tabBottom = tabTop + nonemptyHeight(tabs)
	}
	if msg.Y >= tabTop && msg.Y < tabBottom {
		// Use the tab component's method to get the clicked tab
		clickedTab := m.uiState.Tabs.GetTabAtX(msg.X)
		if clickedTab >= 0 {
			m.scrollDrag = ""
			m.uiState.Tabs.SetActive(clickedTab)
			if clickedTab == 0 && m.uiState.ViewMode == "events" {
				m.syncEventsViewOnTabEntry()
			}
			// Trigger async content loading when switching to Help tab
			if clickedTab == 4 && m.uiState.HelpView.NeedsContentLoad() {
				return m, m.uiState.HelpView.LoadContentAsync()
			}
		}
		return m, nil
	}

	// Only handle clicks in content area for capture tab
	// (Nodes and Settings tabs handle their own bounds checking)
	if m.uiState.Tabs.GetActive() == 0 {
		if msg.Y < contentStartY || msg.Y >= contentStartY+contentHeight {
			return m, nil
		}
	}

	// Capture tab clicks (tab 0 - can be packet list or calls view)
	if m.uiState.Tabs.GetActive() == 0 {
		if m.uiState.ViewMode == "calls" {
			return m.handleCallsViewClick(msg, contentStartY, contentHeight)
		}
		if m.uiState.ViewMode == "events" {
			return m.handleEventsViewClick(msg, contentStartY)
		}
		return m.handlePacketListClick(msg, contentStartY, contentHeight)
	}

	// Nodes tab clicks (tab 1)
	if m.uiState.Tabs.GetActive() == 1 {
		// DEBUG: Uncomment to trace mouse event forwarding
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "  -> Forwarding to NodesView.Update\n")
		// 	f.Close()
		// }
		// Forward mouse events to the nodes view (like settings tab, let it handle coordinate adjustment)
		cmd := m.uiState.NodesView.Update(msg)
		return m, cmd
	}

	// Statistics tab clicks (tab 2)
	if m.uiState.Tabs.GetActive() == 2 {
		// Forward mouse events to the statistics view
		cmd := m.uiState.StatisticsView.Update(msg)
		return m, cmd
	}

	// Settings tab clicks (tab 3)
	if m.uiState.Tabs.GetActive() == 3 {
		// Forward mouse events to the settings view
		cmd := m.uiState.SettingsView.Update(msg)
		return m, cmd
	}

	// Help tab clicks (tab 4)
	if m.uiState.Tabs.GetActive() == 4 {
		// Forward mouse events to the help view
		cmd := m.uiState.HelpView.Update(msg)
		return m, cmd
	}

	return m, nil
}

// handleCaptureWheel routes scrolling using the same rectangles as rendering.
func (m Model) handleCaptureWheel(msg tea.MouseMsg) (Model, tea.Cmd) {
	layout := m.captureLayout()
	x, y := msg.X, msg.Y-m.captureContentOrigin()
	up := msg.Button == tea.MouseButtonWheelUp
	if layout.Details.contains(x, y) {
		m.focusCapturePane("right")
		switch m.uiState.ViewMode {
		case "events":
			if up {
				m.uiState.EventsView.ScrollDetailsUp()
			} else {
				m.uiState.EventsView.ScrollDetailsDown()
			}
		case "calls":
			if up {
				m.uiState.CallsView.ScrollDetailsUp()
			} else {
				m.uiState.CallsView.ScrollDetailsDown()
			}
		default:
			key := tea.KeyDown
			if up {
				key = tea.KeyUp
			}
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: key})
		}
		return m, nil
	}
	if !layout.List.contains(x, y) {
		return m, nil
	}
	m.focusCapturePane("left")
	switch m.uiState.ViewMode {
	case "events":
		if up {
			m.moveEventSelection(-1)
		} else {
			m.moveEventSelection(1)
		}
	case "calls":
		if up {
			m.uiState.CallsView.SelectPrevious()
		} else {
			m.uiState.CallsView.SelectNext()
		}
	default:
		if up {
			m.uiState.PacketList.CursorUp()
		} else {
			m.uiState.PacketList.CursorDown()
		}
		m.updateDetailsPanel()
	}
	return m, nil
}

// captureClickRow focuses the visible pane and translates a list click to its
// data row, excluding the outer border, padding, and table header.
func (m *Model) captureClickRow(msg tea.MouseMsg) (int, bool) {
	layout := m.captureLayout()
	x, y := msg.X, msg.Y-m.captureContentOrigin()
	if layout.Details.contains(x, y) {
		m.focusCapturePane("right")
		return 0, false
	}
	if !layout.List.contains(x, y) {
		return 0, false
	}
	m.focusCapturePane("left")
	row := y - layout.List.Y - 3
	return row, row >= 0 && row < max(0, layout.List.Height-4)
}

func (m Model) handleEventsViewClick(msg tea.MouseMsg, _ int) (Model, tea.Cmd) {
	row, ok := m.captureClickRow(msg)
	if !ok {
		return m, nil
	}
	id, ok := m.uiState.EventsView.EventIDAtVisibleRow(row)
	if !ok {
		return m, nil
	}
	now := time.Now()
	double := id == m.uiState.LastEventClickID && now.Sub(m.uiState.LastEventClickTime) < 500*time.Millisecond
	if double {
		m.uiState.LastEventClickID = ""
		m.uiState.LastEventClickTime = time.Time{}
	} else {
		m.uiState.LastEventClickID = id
		m.uiState.LastEventClickTime = now
	}
	m.eventStore.SelectByIDFollowingLatest(id)
	m.syncEventsView()
	if double {
		return m.toggleCaptureDetails()
	}
	return m, nil
}

func (m Model) handlePacketListClick(msg tea.MouseMsg, _, _ int) (Model, tea.Cmd) {
	row, ok := m.captureClickRow(msg)
	if !ok {
		return m, nil
	}
	if m.offlineSession != nil {
		if row >= m.uiState.PacketList.VisibleRows() {
			return m, nil
		}
		index := m.uiState.PacketList.LogicalOffset() + uint64(row)
		if index >= m.uiState.PacketList.LogicalCount() {
			return m, nil
		}
		now := time.Now()
		double := m.offlineLastClickValid && index == m.offlineLastClick && now.Sub(m.uiState.LastClickTime) < 500*time.Millisecond
		m.offlineLastClick = index
		m.offlineLastClickValid = !double
		m.uiState.LastClickTime = now
		m.uiState.PacketList.SetLogicalCursor(index)
		m.updateDetailsPanel()
		if msg.Ctrl || msg.Shift {
			m.offlineLastClickValid = false
			cmd := m.markPacketClick(msg)
			return m, cmd
		}
		m.setPacketMarkAnchor()
		if double {
			return m.toggleCaptureDetails()
		}
		return m, nil
	}
	packets := m.uiState.PacketList.GetPackets()
	index := m.uiState.PacketList.GetOffset() + row
	if index < 0 || index >= len(packets) {
		return m, nil
	}
	now := time.Now()
	double := index == m.uiState.LastClickPacket && now.Sub(m.uiState.LastClickTime) < 500*time.Millisecond
	m.uiState.LastClickTime = now
	m.uiState.LastClickPacket = index
	m.uiState.PacketList.SetCursor(index)
	m.updateDetailsPanel()
	if msg.Ctrl || msg.Shift {
		m.uiState.LastClickTime = time.Time{}
		cmd := m.markPacketClick(msg)
		return m, cmd
	}
	m.setPacketMarkAnchor()
	if double {
		m.uiState.LastClickTime = time.Time{}
		return m.toggleCaptureDetails()
	}
	return m, nil
}

func (m Model) handleCallsViewClick(msg tea.MouseMsg, _, _ int) (Model, tea.Cmd) {
	row, ok := m.captureClickRow(msg)
	if !ok {
		return m, nil
	}
	index := m.uiState.CallsView.GetOffset() + row
	if index < 0 || index >= len(m.uiState.CallsView.GetCalls()) {
		return m, nil
	}
	now := time.Now()
	double := index == m.uiState.LastClickPacket && now.Sub(m.uiState.LastClickTime) < 500*time.Millisecond
	m.uiState.LastClickTime = now
	m.uiState.LastClickPacket = index
	m.uiState.CallsView.SetSelected(index)
	if double {
		m.uiState.LastClickTime = time.Time{}
		return m.toggleCaptureDetails()
	}
	return m, nil
}

// toggleDetailsPanel retains the packet-only convenience helper used by tests.
func (m Model) toggleDetailsPanel() Model {
	m, _ = m.toggleCaptureDetails()
	return m
}
