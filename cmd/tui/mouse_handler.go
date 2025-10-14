//go:build tui || all
// +build tui all

package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// handleMouse processes mouse events for the TUI
func (m Model) handleMouse(msg tea.MouseMsg) (Model, tea.Cmd) {
	// DEBUG: Uncomment to log mouse events to /tmp/lippycat-mouse-debug.log for troubleshooting
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "handleMouse: Y=%d Type=%v Action=%v Button=%v ActiveTab=%d\n",
	// 		msg.Y, msg.Type, msg.Action, msg.Button, m.uiState.Tabs.GetActive())
	// 	f.Close()
	// }

	// Layout constants
	headerHeight := 2                          // Header takes 2 lines (text + border)
	tabsHeight := 4                            // Tabs take 4 lines
	bottomHeight := 4                          // Footer/filter area
	contentStartY := headerHeight + tabsHeight // Y=6
	contentHeight := m.uiState.Height - headerHeight - tabsHeight - bottomHeight

	// Handle mouse wheel scrolling - based on hover position, not focus
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonWheelUp {
		if m.uiState.Tabs.GetActive() == 0 {
			// On capture tab - determine which pane we're hovering over
			minWidthForDetails := 160
			if m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails {
				// Split pane mode - check X position to determine which pane
				detailsWidth := 77
				listWidth := m.uiState.Width - detailsWidth
				detailsContentStart := listWidth - 2

				if msg.X < detailsContentStart {
					// Hovering over packet list - scroll it
					m.uiState.PacketList.CursorUp()
					m.updateDetailsPanel()
				} else {
					// Hovering over details panel - scroll it
					cmd := m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyUp})
					return m, cmd
				}
			} else {
				// Full width packet list - just scroll it
				m.uiState.PacketList.CursorUp()
				m.updateDetailsPanel()
			}
		} else if m.uiState.Tabs.GetActive() == 1 {
			// On nodes tab - pass to NodesView
			cmd := m.uiState.NodesView.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonWheelDown {
		if m.uiState.Tabs.GetActive() == 0 {
			// On capture tab - determine which pane we're hovering over
			minWidthForDetails := 160
			if m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails {
				// Split pane mode - check X position to determine which pane
				detailsWidth := 77
				listWidth := m.uiState.Width - detailsWidth
				detailsContentStart := listWidth - 2

				if msg.X < detailsContentStart {
					// Hovering over packet list - scroll it
					m.uiState.PacketList.CursorDown()
					m.updateDetailsPanel()
				} else {
					// Hovering over details panel - scroll it
					cmd := m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyDown})
					return m, cmd
				}
			} else {
				// Full width packet list - just scroll it
				m.uiState.PacketList.CursorDown()
				m.updateDetailsPanel()
			}
		} else if m.uiState.Tabs.GetActive() == 1 {
			// On nodes tab - pass to NodesView
			cmd := m.uiState.NodesView.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	// Handle clicks - use newer Button and Action fields
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress {
		return m, nil
	}

	// Tab bar is at Y=2-5 (4 lines including borders)
	// Clickable area is Y=2-4 (bottom extends one row too much at Y=5)
	if msg.Y >= 2 && msg.Y <= 4 {
		// Use the tab component's method to get the clicked tab
		clickedTab := m.uiState.Tabs.GetTabAtX(msg.X)
		if clickedTab >= 0 {
			m.uiState.Tabs.SetActive(clickedTab)
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

	// Packet list clicks (only on first tab - capture tab)
	if m.uiState.Tabs.GetActive() == 0 {
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

	// Settings tab clicks (tab 3)
	if m.uiState.Tabs.GetActive() == 3 {
		// Forward mouse events to the settings view
		cmd := m.uiState.SettingsView.Update(msg)
		return m, cmd
	}

	return m, nil
}

// handlePacketListClick processes clicks on the packet list
func (m Model) handlePacketListClick(msg tea.MouseMsg, contentStartY, contentHeight int) (Model, tea.Cmd) {
	minWidthForDetails := 120

	// Check if we're in split pane mode
	if m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails {
		// Split pane: packet list on left (65%), details on right (35%)
		// Both panels have borders and padding, so calculate actual widths
		listWidth := m.uiState.Width * 65 / 100

		// The packet list renders at full listWidth
		// The details panel starts immediately after the packet list
		// Packet list has border(1) + padding(2) = 3 chars on right side
		// So the actual packet list content ends at listWidth - 3
		// Clicks from listWidth - 2 onwards should focus the details panel

		detailsContentStart := listWidth - 2 // Move boundary left to account for packet list's right border/padding

		if msg.X < detailsContentStart {
			// Click in packet list area - switch focus to left pane
			m.uiState.FocusedPane = "left"

			// First line of data is at contentStartY + 1 (after table header)
			tableHeaderY := contentStartY + 1
			if msg.Y > tableHeaderY {
				// Calculate which row was clicked (relative to visible area)
				visibleRow := msg.Y - tableHeaderY - 1 // -1 for separator line

				// Use the packet list from the PacketList component (matches what's displayed)
				packets := m.uiState.PacketList.GetPackets()

				// Add scroll offset to get actual packet index
				actualPacketIndex := m.uiState.PacketList.GetOffset() + visibleRow

				if actualPacketIndex >= 0 && actualPacketIndex < len(packets) {
					// Check for double-click (same packet clicked within 500ms)
					now := time.Now()
					isDoubleClick := actualPacketIndex == m.uiState.LastClickPacket &&
						now.Sub(m.uiState.LastClickTime) < 500*time.Millisecond

					// Update last click tracking
					m.uiState.LastClickTime = now
					m.uiState.LastClickPacket = actualPacketIndex

					// Set cursor directly without scrolling
					m.uiState.PacketList.SetCursor(actualPacketIndex)
					m.uiState.DetailsPanel.SetPacket(&packets[actualPacketIndex])

					// Toggle details panel on double-click
					if isDoubleClick {
						m = m.toggleDetailsPanel()
					}
				}
			}
		} else {
			// Click inside details panel content - switch focus to right pane
			m.uiState.FocusedPane = "right"
		}
	} else {
		// Full width packet list
		tableHeaderY := contentStartY + 1
		if msg.Y > tableHeaderY {
			// Calculate which row was clicked (relative to visible area)
			visibleRow := msg.Y - tableHeaderY - 1

			// Use the packet list from the PacketList component (matches what's displayed)
			packets := m.uiState.PacketList.GetPackets()

			// Add scroll offset to get actual packet index
			actualPacketIndex := m.uiState.PacketList.GetOffset() + visibleRow

			if actualPacketIndex >= 0 && actualPacketIndex < len(packets) {
				// Check for double-click (same packet clicked within 500ms)
				now := time.Now()
				isDoubleClick := actualPacketIndex == m.uiState.LastClickPacket &&
					now.Sub(m.uiState.LastClickTime) < 500*time.Millisecond

				// Update last click tracking
				m.uiState.LastClickTime = now
				m.uiState.LastClickPacket = actualPacketIndex

				// Set cursor directly without scrolling
				m.uiState.PacketList.SetCursor(actualPacketIndex)
				m.uiState.DetailsPanel.SetPacket(&packets[actualPacketIndex])
				m.uiState.FocusedPane = "left"

				// Toggle details panel on double-click
				if isDoubleClick {
					m = m.toggleDetailsPanel()
				}
			}
		}
	}
	return m, nil
}

// toggleDetailsPanel toggles the details panel and recalculates sizes
func (m Model) toggleDetailsPanel() Model {
	m.uiState.ShowDetails = !m.uiState.ShowDetails
	// Recalculate sizes when toggling details
	headerHeight := 2
	tabsHeight := 4
	bottomHeight := 4
	contentHeight := m.uiState.Height - headerHeight - tabsHeight - bottomHeight
	minWidthForDetails := 160
	if m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails {
		detailsWidth := 77
		listWidth := m.uiState.Width - detailsWidth
		m.uiState.PacketList.SetSize(listWidth, contentHeight)
		m.uiState.DetailsPanel.SetSize(detailsWidth, contentHeight)
	} else {
		m.uiState.PacketList.SetSize(m.uiState.Width, contentHeight)
		m.uiState.DetailsPanel.SetSize(0, contentHeight)
	}
	return m
}
