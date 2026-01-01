//go:build tui || all
// +build tui all

package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// handleKeyboard processes keyboard events for the TUI
func (m Model) handleKeyboard(msg tea.KeyMsg) (Model, tea.Cmd) {
	// Handle filter input mode
	if m.uiState.FilterMode {
		model, cmd := m.handleFilterInput(msg)
		return model.(Model), cmd
	}

	// Settings tab gets priority for most keys (except q, ctrl+c, ctrl+z, space, tab/shift+tab)
	if m.uiState.Tabs.GetActive() == 3 {
		// If actively editing ANY field, pass ALL keys to settings view
		// (except quit/suspend keys) to prevent global shortcuts from interfering with text input
		if m.uiState.SettingsView.IsEditing() {
			switch msg.String() {
			case "q", "ctrl+c":
				m.uiState.Quitting = true
				return m, tea.Quit
			case "ctrl+z":
				// Suspend the process
				return m, tea.Suspend
			default:
				// Pass everything to settings view including t, space, etc.
				cmd := m.uiState.SettingsView.Update(msg)
				return m, cmd
			}
		}

		// Normal settings tab key handling (when NOT editing)
		switch msg.String() {
		case "q", "ctrl+c":
			m.uiState.Quitting = true
			return m, tea.Quit
		case "ctrl+z":
			// Suspend the process
			return m, tea.Suspend
		case " ": // Allow space to pause/resume capture
			m.uiState.Paused = !m.uiState.Paused
			// Show toast and resume ticking when unpausing
			if !m.uiState.Paused {
				toastCmd := m.uiState.Toast.Show(
					"Capture resumed",
					components.ToastSuccess,
					components.ToastDurationShort,
				)
				return m, tea.Batch(toastCmd, tickCmd())
			}
			// Show toast for pause
			return m, m.uiState.Toast.Show(
				"Capture paused",
				components.ToastInfo,
				components.ToastDurationShort,
			)
		case "t": // Allow theme toggle
			return m.handleThemeToggle()
		case "tab", "shift+tab", "alt+1", "alt+2", "alt+3", "alt+4", "alt+5", "p", "?":
			// Let these fall through to normal tab switching and global key handling
		default:
			// Forward everything else to settings view
			cmd := m.uiState.SettingsView.Update(msg)
			// Update interface name in header when it changes (for display only)
			// Actual capture interface doesn't change until restart
			return m, cmd
		}
	}

	// Help tab key handling
	if m.uiState.Tabs.GetActive() == 4 {
		// Handle search mode input
		if m.uiState.HelpView.IsSearchMode() {
			switch msg.Type {
			case tea.KeyEsc:
				m.uiState.HelpView.ExitSearchMode()
				return m, nil
			case tea.KeyEnter:
				// Keep search results, exit search mode
				m.uiState.HelpView.ExitSearchMode()
				return m, nil
			case tea.KeyBackspace:
				m.uiState.HelpView.DeleteSearchChar()
				return m, nil
			case tea.KeyRunes:
				for _, r := range msg.Runes {
					m.uiState.HelpView.AddSearchChar(r)
				}
				return m, nil
			}
		}

		// Normal Help tab key handling
		switch msg.String() {
		case "q", "ctrl+c":
			m.uiState.Quitting = true
			return m, tea.Quit
		case "ctrl+z":
			return m, tea.Suspend
		case "n": // Next match
			m.uiState.HelpView.NextMatch()
			return m, nil
		case "N": // Previous match
			m.uiState.HelpView.PrevMatch()
			return m, nil
		case "1": // Keybindings section
			m.uiState.HelpView.SetSection(components.SectionKeybindings)
			return m, nil
		case "2": // Commands section
			m.uiState.HelpView.SetSection(components.SectionCommands)
			return m, nil
		case "3": // Workflows section
			m.uiState.HelpView.SetSection(components.SectionWorkflows)
			return m, nil
		case "j", "down":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyDown})
			return m, cmd
		case "k", "up":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyUp})
			return m, cmd
		case "g", "home":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyHome})
			return m, cmd
		case "G", "end":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyEnd})
			return m, cmd
		case "pgup":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyPgUp})
			return m, cmd
		case "pgdown":
			cmd := m.uiState.HelpView.Update(tea.KeyMsg{Type: tea.KeyPgDown})
			return m, cmd
		case " ": // Pause/resume
			return m.handlePauseResume()
		case "tab", "shift+tab", "alt+1", "alt+2", "alt+3", "alt+4", "alt+5", "p", "?", "/":
			// Let these fall through to normal handling
		default:
			return m, nil
		}
	}

	// Normal mode key handling
	switch msg.String() {
	case "ctrl+z":
		// Suspend the process - Bubbletea will automatically handle resume
		return m, tea.Suspend

	case "q", "ctrl+c":
		m.uiState.Quitting = true
		return m, tea.Quit

	case "/": // Enter filter mode (Capture tab) or search mode (Help tab)
		if m.uiState.Tabs.GetActive() == 0 {
			return m.handleEnterFilterMode()
		}
		if m.uiState.Tabs.GetActive() == 4 {
			m.uiState.HelpView.EnterSearchMode()
			return m, nil
		}
		return m, nil

	case "C": // Clear all filters (Shift+C) - Capture tab only
		if m.uiState.Tabs.GetActive() == 0 {
			return m.handleClearAllFilters()
		}
		return m, nil

	case "c": // Remove last filter - Capture tab only
		if m.uiState.Tabs.GetActive() == 0 {
			return m.handleRemoveLastFilter()
		}
		return m, nil

	case "x": // Clear/flush packets - Capture tab only
		if m.uiState.Tabs.GetActive() == 0 {
			return m.handleClearPackets()
		}
		return m, nil

	case " ": // Space to pause/resume
		return m.handlePauseResume()

	case "d":
		return m.handleDKey()

	case "p": // Open protocol selector
		m.uiState.ProtocolSelector.Activate()
		m.uiState.ProtocolSelector.SetSize(m.uiState.Width, m.uiState.Height)
		return m, nil

	case "v": // Toggle view mode
		return m.handleToggleView()

	case "w": // Save packets to file (or stop streaming save)
		return m.handleSavePackets()

	case "T": // TEST: Show test toast notification (cycles through types)
		return m.handleTestToast()

	case "h", "left": // Focus left pane (packet list)
		return m.handleFocusLeft()

	case "l", "right": // Focus right pane (details/hex)
		return m.handleFocusRight()

	case "j", "down": // Move down
		return m.handleMoveDown()

	case "k", "up": // Move up
		return m.handleMoveUp()

	case "g", "home": // Jump to top
		return m.handleJumpToTop()

	case "G", "end": // Jump to bottom (Shift+G)
		return m.handleJumpToBottom()

	case "pgup": // Page up
		return m.handlePageUp()

	case "pgdown": // Page down
		return m.handlePageDown()

	case "tab": // Switch to next tab
		return m.handleNextTab()

	case "shift+tab": // Switch to previous tab
		return m.handlePreviousTab()

	case "alt+1", "alt+2", "alt+3", "alt+4", "alt+5":
		return m.handleAltNumberKey(msg.String())

	case "?": // Jump to Help tab
		m.uiState.Tabs.SetActive(4)
		return m, nil

	case "a": // Add node (only on Nodes tab)
		return m.handleAddNode()

	case "s": // Subscribe to hunters (only on Nodes tab when processor selected)
		return m.handleSubscribeToHunters()

	case "f": // Open filter manager (only on Nodes tab when hunter selected)
		return m.handleFilterManagerKey()
	}

	return m, nil
}

// handleThemeToggle toggles the UI theme
func (m Model) handleThemeToggle() (Model, tea.Cmd) {
	// For future: add theme cycling logic here
	// Currently only Solarized theme available
	m.uiState.Theme = themes.Solarized()
	// Update all components with new theme
	m.uiState.PacketList.SetTheme(m.uiState.Theme)
	m.uiState.DetailsPanel.SetTheme(m.uiState.Theme)
	m.uiState.Header.SetTheme(m.uiState.Theme)
	m.uiState.Footer.SetTheme(m.uiState.Theme)
	m.uiState.Tabs.SetTheme(m.uiState.Theme)
	m.uiState.StatisticsView.SetTheme(m.uiState.Theme)
	m.uiState.SettingsView.SetTheme(m.uiState.Theme)
	m.uiState.FilterInput.SetTheme(m.uiState.Theme)
	saveThemePreference(m.uiState.Theme)
	return m, nil
}

// handleEnterFilterMode enters filter input mode
func (m Model) handleEnterFilterMode() (Model, tea.Cmd) {
	m.uiState.FilterMode = true
	m.uiState.FilterInput.Activate()
	m.uiState.FilterInput.Clear()
	// Update filter input with current active filters
	filterCount := m.packetStore.FilterChain.Count()
	filterDescs := m.packetStore.FilterChain.GetFilterDescriptions()
	m.uiState.FilterInput.SetActiveFilters(filterCount, filterDescs)
	return m, nil
}

// handleClearAllFilters clears all active filters
func (m Model) handleClearAllFilters() (Model, tea.Cmd) {
	if m.packetStore.HasFilter() {
		filterCount := m.packetStore.FilterChain.Count()
		m.packetStore.ClearFilter()
		m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
		m.packetStore.MatchedPackets = int64(m.packetStore.PacketsCount)
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())

		// Show toast notification with count
		msg := fmt.Sprintf("All filters cleared (%d removed)", filterCount)
		if filterCount == 1 {
			msg = "Filter cleared"
		}
		return m, m.uiState.Toast.Show(
			msg,
			components.ToastInfo,
			components.ToastDurationShort,
		)
	}
	return m, nil
}

// handleRemoveLastFilter removes the last filter in the stack
func (m Model) handleRemoveLastFilter() (Model, tea.Cmd) {
	if m.packetStore.HasFilter() {
		filterCount := m.packetStore.FilterChain.Count()
		if m.packetStore.FilterChain.RemoveLast() {
			// Reapply remaining filters
			m.applyFilters()

			// Update display
			if !m.packetStore.HasFilter() {
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			} else {
				m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
			}

			// Show toast notification
			remainingCount := filterCount - 1
			msg := "Last filter removed"
			if remainingCount > 0 {
				msg = fmt.Sprintf("Last filter removed (%d remaining)", remainingCount)
			}
			return m, m.uiState.Toast.Show(
				msg,
				components.ToastInfo,
				components.ToastDurationShort,
			)
		}
	}
	return m, nil
}

// handleClearPackets clears all packets from the buffer
func (m Model) handleClearPackets() (Model, tea.Cmd) {
	// Store count before clearing
	packetCount := m.packetStore.PacketsCount

	m.packetStore.Packets = make([]components.PacketDisplay, m.packetStore.MaxPackets)
	m.packetStore.PacketsHead = 0
	m.packetStore.PacketsCount = 0
	m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
	m.packetStore.TotalPackets = 0
	m.packetStore.MatchedPackets = 0
	m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	// Reset bounded counters
	m.statistics.ProtocolCounts.Clear()
	m.statistics.SourceCounts.Clear()
	m.statistics.DestCounts.Clear()
	m.statistics.TotalBytes = 0
	m.statistics.TotalPackets = 0
	m.statistics.MinPacketSize = 999999
	m.statistics.MaxPacketSize = 0
	m.uiState.StatisticsView.SetStatistics(m.statistics)

	// Show toast notification
	return m, m.uiState.Toast.Show(
		fmt.Sprintf("Cleared %d packet(s)", packetCount),
		components.ToastInfo,
		components.ToastDurationShort,
	)
}

// handlePauseResume toggles capture pause state
func (m Model) handlePauseResume() (Model, tea.Cmd) {
	m.uiState.Paused = !m.uiState.Paused
	// Show toast and resume ticking when unpausing
	if !m.uiState.Paused {
		toastCmd := m.uiState.Toast.Show(
			"Capture resumed",
			components.ToastSuccess,
			components.ToastDurationShort,
		)
		return m, tea.Batch(toastCmd, tickCmd())
	}
	// Show toast for pause
	return m, m.uiState.Toast.Show(
		"Capture paused",
		components.ToastInfo,
		components.ToastDurationShort,
	)
}

// handleDKey handles the 'd' key (context-sensitive)
func (m Model) handleDKey() (Model, tea.Cmd) {
	// Context-sensitive: toggle details on Capture tab, delete node on Nodes tab
	if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
		return m, m.handleDeleteNode()
	}

	// On Capture tab: check view mode
	if m.uiState.Tabs.GetActive() == 0 {
		// If in calls view mode, toggle CallsView details
		if m.uiState.ViewMode == "calls" {
			m.uiState.CallsView.ToggleDetails()
			return m, nil
		}

		// Otherwise, toggle packet details panel
		m.uiState.ShowDetails = !m.uiState.ShowDetails
		// Recalculate packet list size based on new showDetails state
		headerHeight := 2
		tabsHeight := 4
		bottomHeight := 4
		contentHeight := m.uiState.Height - headerHeight - tabsHeight - bottomHeight
		minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
		if m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails {
			// Details panel gets exactly what it needs for hex dump, packet list gets the rest
			detailsWidth := 77 // Hex dump (72) + borders/padding (5)
			listWidth := m.uiState.Width - detailsWidth
			m.uiState.PacketList.SetSize(listWidth, contentHeight)
			m.uiState.DetailsPanel.SetSize(detailsWidth, contentHeight)
		} else {
			// Full width for packet list
			m.uiState.PacketList.SetSize(m.uiState.Width, contentHeight)
			m.uiState.DetailsPanel.SetSize(0, contentHeight)
		}
		return m, nil
	}

	// Other tabs: no action
	return m, nil
}

// handleToggleView toggles between different view modes
func (m Model) handleToggleView() (Model, tea.Cmd) {
	// On capture tab: toggle between packets and calls for VoIP
	if m.uiState.Tabs.GetActive() == 0 {
		if m.uiState.SelectedProtocol.Name == "VoIP (SIP/RTP)" {
			if m.uiState.ViewMode == "packets" {
				m.uiState.ViewMode = "calls"
			} else {
				m.uiState.ViewMode = "packets"
				// Refresh packet list when switching to packets view
				// This ensures packets that arrived while in calls view are displayed
				if !m.packetStore.HasFilter() {
					m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
				} else {
					m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
				}
			}
		}
	} else if m.uiState.Tabs.GetActive() == 1 {
		// On nodes tab: toggle between table and graph view
		if !m.uiState.NodesView.ToggleView() {
			// Toggle failed - show toast
			cmd := m.uiState.Toast.Show("Select a node to view graph", components.ToastWarning, components.ToastDurationShort)
			return m, cmd
		}
	}
	return m, nil
}

// handleSavePackets initiates or stops packet saving
func (m Model) handleSavePackets() (Model, tea.Cmd) {
	// Only on capture tab (tab 0)
	if m.uiState.Tabs.GetActive() == 0 {
		// Check if streaming save is active
		if m.uiState.StreamingSave {
			// Stop streaming save
			cmd := m.stopStreamingSave()
			// Clear streaming save state
			m.activeWriter = nil
			m.savePath = ""
			m.uiState.StreamingSave = false
			m.uiState.Footer.SetStreamingSave(false) // Update footer hint
			return m, cmd
		}
		// Update default filename with current timestamp before opening file dialog
		m.uiState.FileDialog.SetDefaultFilename(m.generateDefaultFilename())
		// Open file dialog to start new save
		cmd := m.uiState.FileDialog.Activate()
		return m, cmd
	}
	return m, nil
}

// handleTestToast shows a test toast notification (cycles through types)
func (m Model) handleTestToast() (Model, tea.Cmd) {
	// Cycle through all toast types: Success -> Error -> Info -> Warning
	toastTypes := []components.ToastType{
		components.ToastSuccess,
		components.ToastError,
		components.ToastInfo,
		components.ToastWarning,
	}
	typeNames := []string{"Success", "Error", "Info", "Warning"}

	toastType := toastTypes[m.testToastCycle%4]
	typeName := typeNames[m.testToastCycle%4]

	cmd := m.uiState.Toast.Show(
		"Test notification - "+typeName+" toast message!",
		toastType,
		components.ToastDurationShort,
	)

	m.testToastCycle++ // Increment for next test
	return m, cmd
}

// Navigation and tab handling methods continue in next part...
// (The file is getting long, splitting into logical sections)
