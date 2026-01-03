//go:build tui || all
// +build tui all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// handleFocusLeft focuses the left pane (packet list)
func (m Model) handleFocusLeft() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		// Use spatial navigation in graph mode
		if m.uiState.NodesView.GetViewMode() == "graph" {
			m.uiState.NodesView.SelectLeft()
			return m, nil
		}
	}
	m.uiState.FocusedPane = "left"
	return m, nil
}

// handleFocusRight focuses the right pane (details/hex)
func (m Model) handleFocusRight() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		// Use spatial navigation in graph mode
		if m.uiState.NodesView.GetViewMode() == "graph" {
			m.uiState.NodesView.SelectRight()
			return m, nil
		}
	}
	m.uiState.FocusedPane = "right"
	return m, nil
}

// handleMoveDown moves selection down
func (m Model) handleMoveDown() (Model, tea.Cmd) {
	switch m.uiState.Tabs.GetActive() {
	case 0: // Capture tab
		if m.uiState.ViewMode == "calls" {
			m.uiState.CallsView.SelectNext()
		} else if m.uiState.ViewMode == "queries" {
			m.uiState.DNSQueriesView.SelectNext()
		} else if m.uiState.FocusedPane == "left" {
			m.uiState.PacketList.CursorDown()
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyDown})
		}
	case 1: // Nodes tab
		// In graph mode, use spatial navigation (down = down in tree)
		// In table mode, move down in the list
		if m.uiState.NodesView.GetViewMode() == "graph" {
			m.uiState.NodesView.SelectDown()
		} else {
			m.uiState.NodesView.SelectNext()
		}
	}
	return m, nil
}

// handleMoveUp moves selection up
func (m Model) handleMoveUp() (Model, tea.Cmd) {
	switch m.uiState.Tabs.GetActive() {
	case 0: // Capture tab
		if m.uiState.ViewMode == "calls" {
			m.uiState.CallsView.SelectPrevious()
		} else if m.uiState.ViewMode == "queries" {
			m.uiState.DNSQueriesView.SelectPrevious()
		} else if m.uiState.FocusedPane == "left" {
			m.uiState.PacketList.CursorUp()
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyUp})
		}
	case 1: // Nodes tab
		// In graph mode, use spatial navigation (up = up in tree)
		// In table mode, move up in the list
		if m.uiState.NodesView.GetViewMode() == "graph" {
			m.uiState.NodesView.SelectUp()
		} else {
			m.uiState.NodesView.SelectPrevious()
		}
	}
	return m, nil
}

// handleJumpToTop jumps to the top of the current list
func (m Model) handleJumpToTop() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 0 { // Capture tab
		if m.uiState.ViewMode == "calls" {
			return m, m.uiState.CallsView.Update(tea.KeyMsg{Type: tea.KeyHome})
		} else if m.uiState.ViewMode == "queries" {
			return m, m.uiState.DNSQueriesView.Update(tea.KeyMsg{Type: tea.KeyHome})
		} else if m.uiState.FocusedPane == "left" {
			m.uiState.PacketList.SetCursor(0)
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyHome})
		}
	} else if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyHome})
		return m, cmd
	}
	return m, nil
}

// handleJumpToBottom jumps to the bottom of the current list
func (m Model) handleJumpToBottom() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 0 { // Capture tab
		if m.uiState.ViewMode == "calls" {
			return m, m.uiState.CallsView.Update(tea.KeyMsg{Type: tea.KeyEnd})
		} else if m.uiState.ViewMode == "queries" {
			return m, m.uiState.DNSQueriesView.Update(tea.KeyMsg{Type: tea.KeyEnd})
		} else if m.uiState.FocusedPane == "left" {
			packets := m.uiState.PacketList.GetPackets()
			if len(packets) > 0 {
				m.uiState.PacketList.SetCursor(len(packets) - 1)
			}
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyEnd})
		}
	} else if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyEnd})
		return m, cmd
	}
	return m, nil
}

// handlePageUp moves up one page in the current list
func (m Model) handlePageUp() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 0 { // Capture tab
		if m.uiState.ViewMode == "calls" {
			return m, m.uiState.CallsView.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		} else if m.uiState.ViewMode == "queries" {
			return m, m.uiState.DNSQueriesView.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		} else if m.uiState.FocusedPane == "left" {
			m.uiState.PacketList.PageUp()
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		}
	} else if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyPgUp})
		return m, cmd
	}
	return m, nil
}

// handlePageDown moves down one page in the current list
func (m Model) handlePageDown() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 0 { // Capture tab
		if m.uiState.ViewMode == "calls" {
			return m, m.uiState.CallsView.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		} else if m.uiState.ViewMode == "queries" {
			return m, m.uiState.DNSQueriesView.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		} else if m.uiState.FocusedPane == "left" {
			m.uiState.PacketList.PageDown()
			m.updateDetailsPanel()
		} else if m.uiState.FocusedPane == "right" {
			return m, m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		}
	} else if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		return m, cmd
	}
	return m, nil
}

// handleNextTab switches to the next tab
func (m Model) handleNextTab() (Model, tea.Cmd) {
	currentTab := m.uiState.Tabs.GetActive()
	totalTabs := 5 // Capture, Nodes, Statistics, Settings, Help
	nextTab := (currentTab + 1) % totalTabs
	m.uiState.Tabs.SetActive(nextTab)
	// Trigger async content loading when switching to Help tab
	if nextTab == 4 && m.uiState.HelpView.NeedsContentLoad() {
		return m, m.uiState.HelpView.LoadContentAsync()
	}
	return m, nil
}

// handlePreviousTab switches to the previous tab
func (m Model) handlePreviousTab() (Model, tea.Cmd) {
	currentTab := m.uiState.Tabs.GetActive()
	totalTabs := 5
	prevTab := (currentTab - 1 + totalTabs) % totalTabs
	m.uiState.Tabs.SetActive(prevTab)
	// Trigger async content loading when switching to Help tab
	if prevTab == 4 && m.uiState.HelpView.NeedsContentLoad() {
		return m, m.uiState.HelpView.LoadContentAsync()
	}
	return m, nil
}

// handleAltNumberKey switches to a specific tab by Alt+number
func (m Model) handleAltNumberKey(key string) (Model, tea.Cmd) {
	var targetTab int
	switch key {
	case "alt+1":
		targetTab = 0
	case "alt+2":
		targetTab = 1
	case "alt+3":
		targetTab = 2
	case "alt+4":
		targetTab = 3
	case "alt+5":
		targetTab = 4
	default:
		return m, nil
	}
	m.uiState.Tabs.SetActive(targetTab)
	// Trigger async content loading when switching to Help tab
	if targetTab == 4 && m.uiState.HelpView.NeedsContentLoad() {
		return m, m.uiState.HelpView.LoadContentAsync()
	}
	return m, nil
}

// handleAddNode opens the add node dialog (works on all tabs)
func (m Model) handleAddNode() (Model, tea.Cmd) {
	// Open add node modal regardless of current tab
	m.uiState.NodesView.ShowAddNodeModal()
	return m, nil
}

// handleSubscribeToHunters opens the hunter selector (only on Nodes tab when processor selected)
func (m Model) handleSubscribeToHunters() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.handleOpenHunterSelector()
		return m, cmd
	}
	return m, nil
}

// handleFilterManagerKey opens the filter manager (only on Nodes tab when hunter selected)
func (m Model) handleFilterManagerKey() (Model, tea.Cmd) {
	if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		cmd := m.handleOpenFilterManager()
		return m, cmd
	}
	return m, nil
}
