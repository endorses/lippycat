//go:build tui || all

package tui

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// handleKeyboard processes keyboard events for the TUI
func (m Model) handleKeyboard(msg tea.KeyMsg) (Model, tea.Cmd) {
	// Handle filter input mode (packet filters)
	if m.uiState.FilterMode {
		model, cmd := m.handleFilterInput(msg)
		return model.(Model), cmd
	}

	// Handle call filter input mode
	if m.uiState.CallFilterMode {
		model, cmd := m.handleCallFilterInput(msg)
		return model.(Model), cmd
	}

	// Settings tab gets priority for most keys (except q, ctrl+c, ctrl+z, space, tab/shift+tab)
	if m.uiState.Tabs.GetActive() == 3 {
		// If actively editing ANY field, pass ALL keys to settings view
		// (except quit/suspend keys) to prevent global shortcuts from interfering with text input
		if m.uiState.SettingsView.IsEditing() {
			switch msg.String() {
			case "q", "ctrl+c":
				m.Shutdown()
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
			// Notify capture pipeline to pause/resume
			pauseSignal := globalCaptureState.GetPauseSignal()
			if m.uiState.Paused {
				pauseSignal.Pause()
			} else {
				pauseSignal.Resume()
			}
			// Show toast when unpausing (existing tick will transition to fast tick)
			if !m.uiState.Paused {
				return m, m.uiState.Toast.ShowWithKey(
					"Capture resumed",
					components.ToastSuccess,
					components.ToastDurationShort,
					components.ToastKeyCaptureState,
				)
			}
			// Show toast for pause
			return m, m.uiState.Toast.ShowWithKey(
				"Capture paused",
				components.ToastInfo,
				components.ToastDurationShort,
				components.ToastKeyCaptureState,
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

	// Statistics tab key handling
	if m.uiState.Tabs.GetActive() == 2 {
		switch msg.String() {
		case "q", "ctrl+c":
			m.uiState.Quitting = true
			return m, tea.Quit
		case "ctrl+z":
			return m, tea.Suspend
		case "v": // Cycle sub-views
			sv := m.uiState.StatisticsView.CycleSubView()
			m.uiState.Footer.SetStatsSubView(sv)
			return m, nil
		case "1": // Overview sub-view
			m.uiState.StatisticsView.SetSubView(components.SubViewOverview)
			m.uiState.Footer.SetStatsSubView(components.SubViewOverview)
			return m, nil
		case "2": // Distributed sub-view
			m.uiState.StatisticsView.SetSubView(components.SubViewDistributed)
			m.uiState.Footer.SetStatsSubView(components.SubViewDistributed)
			return m, nil
		case "e": // Export statistics to JSON
			return m.handleExportStatistics()
		case "j", "down": // Scroll down
			cmd := m.uiState.StatisticsView.Update(tea.KeyMsg{Type: tea.KeyDown})
			return m, cmd
		case "k", "up": // Scroll up
			cmd := m.uiState.StatisticsView.Update(tea.KeyMsg{Type: tea.KeyUp})
			return m, cmd
		case "h", "l", "left", "right": // Forward to viewport for scrolling
			cmd := m.uiState.StatisticsView.Update(msg)
			return m, cmd
		case " ": // Pause/resume
			return m.handlePauseResume()
		case "tab", "shift+tab", "alt+1", "alt+2", "alt+3", "alt+4", "alt+5", "p", "?":
			// Let these fall through to normal handling
		default:
			// Forward to viewport for other keys
			cmd := m.uiState.StatisticsView.Update(msg)
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
		case "c": // Clear search
			m.uiState.HelpView.ClearSearch()
			return m, nil
		case "n": // Next match
			m.uiState.HelpView.NextMatch()
			return m, nil
		case "N": // Previous match
			m.uiState.HelpView.PrevMatch()
			return m, nil
		case "1": // Keybindings section
			cmd := m.uiState.HelpView.SetSection(components.SectionKeybindings)
			return m, cmd
		case "2": // Filters section
			cmd := m.uiState.HelpView.SetSection(components.SectionFilters)
			return m, cmd
		case "3": // Commands section
			cmd := m.uiState.HelpView.SetSection(components.SectionCommands)
			return m, cmd
		case "4": // Workflows section
			cmd := m.uiState.HelpView.SetSection(components.SectionWorkflows)
			return m, cmd
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
		m.Shutdown()
		m.uiState.Quitting = true
		return m, tea.Quit

	case "/": // Enter filter mode (Capture tab) or search mode (Help tab)
		if m.uiState.Tabs.GetActive() == 0 {
			// Check if we're in calls view mode
			if m.uiState.ViewMode == "calls" {
				return m.handleEnterCallFilterMode()
			}
			return m.handleEnterFilterMode()
		}
		if m.uiState.Tabs.GetActive() == 4 {
			m.uiState.HelpView.EnterSearchMode()
			return m, nil
		}
		return m, nil

	case "C": // Clear all filters (Shift+C) - Capture tab only
		if m.uiState.Tabs.GetActive() == 0 {
			// Check if we're in calls view mode
			if m.uiState.ViewMode == "calls" {
				return m.handleClearAllCallFilters()
			}
			return m.handleClearAllFilters()
		}
		return m, nil

	case "c": // Remove last filter - Capture tab only
		if m.uiState.Tabs.GetActive() == 0 {
			// Check if we're in calls view mode
			if m.uiState.ViewMode == "calls" {
				return m.handleRemoveLastCallFilter()
			}
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
		// Trigger async content loading if needed
		if m.uiState.HelpView.NeedsContentLoad() {
			return m, m.uiState.HelpView.LoadContentAsync()
		}
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

		// Reset sync counters for incremental updates
		_, _, total, _ := m.packetStore.GetBufferInfo()
		m.lastSyncedTotal = total
		m.lastSyncedFilteredCount = 0

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
			// Show toast notification first
			remainingCount := filterCount - 1
			msg := "Last filter removed"
			if remainingCount > 0 {
				msg = fmt.Sprintf("Last filter removed (%d remaining)", remainingCount)
			}
			toastCmd := m.uiState.Toast.Show(
				msg,
				components.ToastInfo,
				components.ToastDurationShort,
			)

			// If no filters remain, show all packets
			if !m.packetStore.HasFilter() {
				// Show all packets immediately when paused or offline
				if m.captureMode == components.CaptureModeOffline || m.uiState.IsPaused() {
					m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
					_, _, total, _ := m.packetStore.GetBufferInfo()
					m.lastSyncedTotal = total
					m.lastSyncedFilteredCount = 0
					m.lastFilterState = false
				} else {
					// Reset to unfiltered mode - incremental updates will handle the rest
					m.uiState.PacketList.SetPackets([]components.PacketDisplay{})
					m.lastSyncedTotal = 0
					m.lastSyncedFilteredCount = 0
					m.lastFilterState = false
				}
				return m, toastCmd
			}

			// Reapply remaining filters when paused or offline
			if m.captureMode == components.CaptureModeOffline || m.uiState.IsPaused() {
				m.packetStore.ReapplyFilters()
				m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
				_, _, _, matchedPackets := m.packetStore.GetBufferInfo()
				m.lastSyncedFilteredCount = matchedPackets
				m.lastFilterState = true
			} else {
				// Clear filtered packets - new packets will flow through remaining filters
				// via AddPacketBatch() and incremental updates in updatePacketListFiltered()
				m.packetStore.ClearFilteredPackets()
				m.uiState.PacketList.SetPackets([]components.PacketDisplay{})
				m.lastSyncedFilteredCount = 0
				m.lastFilterState = true
			}

			return m, toastCmd
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

	// Reset incremental sync counters so new packets will be added
	m.lastSyncedTotal = 0
	m.lastSyncedFilteredCount = 0

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
	// Notify capture pipeline to pause/resume
	pauseSignal := globalCaptureState.GetPauseSignal()
	if m.uiState.Paused {
		pauseSignal.Pause()
	} else {
		pauseSignal.Resume()
	}
	// Show toast and resume ticking when unpausing
	if !m.uiState.Paused {
		// Existing tick will transition to fast tick
		return m, m.uiState.Toast.ShowWithKey(
			"Capture resumed",
			components.ToastSuccess,
			components.ToastDurationShort,
			components.ToastKeyCaptureState,
		)
	}
	// Show toast for pause
	return m, m.uiState.Toast.ShowWithKey(
		"Capture paused",
		components.ToastInfo,
		components.ToastDurationShort,
		components.ToastKeyCaptureState,
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

		// If in queries view mode, toggle DNSQueriesView details
		if m.uiState.ViewMode == "queries" {
			m.uiState.DNSQueriesView.ToggleDetails()
			return m, nil
		}

		// If in emails view mode, toggle EmailView details
		if m.uiState.ViewMode == "emails" {
			m.uiState.EmailView.ToggleDetails()
			return m, nil
		}

		// If in http view mode, toggle HTTPView details
		if m.uiState.ViewMode == "http" {
			m.uiState.HTTPView.ToggleDetails()
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
		} else if m.uiState.SelectedProtocol.Name == "DNS" {
			// DNS: toggle between packets and queries view
			if m.uiState.ViewMode == "packets" {
				m.uiState.ViewMode = "queries"
			} else {
				m.uiState.ViewMode = "packets"
				// Refresh packet list when switching to packets view
				if !m.packetStore.HasFilter() {
					m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
				} else {
					m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
				}
			}
		} else if m.uiState.SelectedProtocol.Name == "Email" {
			// Email: toggle between packets and emails view
			if m.uiState.ViewMode == "packets" {
				m.uiState.ViewMode = "emails"
			} else {
				m.uiState.ViewMode = "packets"
				// Refresh packet list when switching to packets view
				if !m.packetStore.HasFilter() {
					m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
				} else {
					m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
				}
			}
		} else if m.uiState.SelectedProtocol.Name == "HTTP" {
			// HTTP: toggle between packets and http view
			if m.uiState.ViewMode == "packets" {
				m.uiState.ViewMode = "http"
			} else {
				m.uiState.ViewMode = "packets"
				// Refresh packet list when switching to packets view
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

// handleExportStatistics exports statistics to a JSON file
func (m Model) handleExportStatistics() (Model, tea.Cmd) {
	// Only on Statistics tab
	if m.uiState.Tabs.GetActive() != 2 {
		return m, nil
	}

	jsonData, err := m.uiState.StatisticsView.ExportJSON()
	if err != nil {
		return m, m.uiState.Toast.Show(
			"Export failed: "+err.Error(),
			components.ToastError,
			components.ToastDurationLong,
		)
	}

	// Generate filename with timestamp
	filename := fmt.Sprintf("statistics_%s.json", time.Now().Format("20060102_150405"))

	// Write to current directory
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return m, m.uiState.Toast.Show(
			"Export failed: "+err.Error(),
			components.ToastError,
			components.ToastDurationLong,
		)
	}

	return m, m.uiState.Toast.Show(
		fmt.Sprintf("Exported to %s", filename),
		components.ToastSuccess,
		components.ToastDurationShort,
	)
}

// Navigation and tab handling methods continue in next part...
// (The file is getting long, splitting into logical sections)
