//go:build tui || all

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

// FileOverwriteData holds information about a file pending overwrite confirmation
type FileOverwriteData struct {
	FilePath string
}

// handleWindowSizeMsg handles terminal window resize events
func (m Model) handleWindowSizeMsg(msg tea.WindowSizeMsg) (Model, tea.Cmd) {
	// Signal that TUI is ready to receive messages (first WindowSizeMsg indicates
	// Bubbletea has completed terminal setup). This unblocks capture goroutines
	// that are waiting to send messages.
	SignalTUIReady()

	m.uiState.Width = msg.Width
	m.uiState.Height = msg.Height

	// Update all component sizes
	m.uiState.Header.SetWidth(msg.Width)
	m.uiState.Footer.SetWidth(msg.Width)
	m.uiState.Tabs.SetWidth(msg.Width)
	m.uiState.FilterInput.SetWidth(msg.Width)
	m.uiState.CallFilterInput.SetWidth(msg.Width)
	m.uiState.FileDialog.SetSize(msg.Width, msg.Height)
	m.uiState.ConfirmDialog.SetSize(msg.Width, msg.Height)
	m.uiState.Toast.SetSize(msg.Width, msg.Height)

	// Set dev console size (full screen when visible)
	if m.uiState.DevConsole != nil {
		m.uiState.DevConsole.SetSize(msg.Width, msg.Height)
	}

	// Calculate available space for main content
	headerHeight := 2 // header (2 lines: text + border)
	tabsHeight := 4   // tabs (4 lines: top border + content + bottom corners + bottom line)
	bottomHeight := 4 // Reserve 4 lines at bottom (footer + space for filter overlay)

	contentHeight := msg.Height - headerHeight - tabsHeight - bottomHeight

	// Set nodes view size (consistent bottom spacing across all tabs)
	// Hints bar is part of the nodes view content, not bottom area
	nodesContentHeight := msg.Height - headerHeight - tabsHeight - bottomHeight
	m.uiState.NodesView.SetSize(msg.Width, nodesContentHeight)

	// Set statistics view size
	m.uiState.StatisticsView.SetSize(msg.Width, contentHeight)

	// Set settings view size
	m.uiState.SettingsView.SetSize(msg.Width, contentHeight)

	// Set help view size (returns cmd if content needs re-rendering due to width change)
	helpCmd := m.uiState.HelpView.SetSize(msg.Width, contentHeight)

	// Set calls view size (always full width, no split view)
	m.uiState.CallsView.SetSize(msg.Width, contentHeight)

	// Auto-hide details panel if terminal is too narrow or if details are toggled off
	minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
	if m.uiState.ShowDetails && msg.Width >= minWidthForDetails {
		// Details panel gets exactly what it needs for hex dump, packet list gets the rest
		detailsWidth := 77 // Hex dump (72) + borders/padding (5)
		listWidth := msg.Width - detailsWidth
		m.uiState.PacketList.SetSize(listWidth, contentHeight)
		m.uiState.DetailsPanel.SetSize(detailsWidth, contentHeight)
	} else {
		// Full width for packet list (details hidden or terminal too narrow)
		m.uiState.PacketList.SetSize(msg.Width, contentHeight)
		m.uiState.DetailsPanel.SetSize(0, contentHeight) // Set to 0 when hidden
	}

	return m, helpCmd
}

// handleResumeMsg handles resume after suspend (ctrl+z / fg)
func (m Model) handleResumeMsg(msg tea.ResumeMsg) (Model, tea.Cmd) {
	// Manually re-enable mouse support as some terminals don't restore it properly
	// This sends the escape sequence to re-enable mouse tracking
	cmd := tea.Batch(
		tea.EnableMouseAllMotion,
		tea.EnterAltScreen,
	)
	if !m.uiState.Paused && m.uiState.Capturing {
		cmd = tea.Batch(cmd, tickCmd())
	}
	return m, cmd
}

// handleTickMsg handles periodic UI refresh ticks
func (m Model) handleTickMsg(msg TickMsg) (Model, tea.Cmd) {
	// When capturing and not paused: full processing
	if !m.uiState.Paused && m.uiState.Capturing {
		// PULL-BASED ARCHITECTURE: Drain pending packets from buffer
		// This ensures TUI is never blocked by incoming packets - it pulls when ready
		pendingPackets := DrainPendingPackets()

		if len(pendingPackets) > 0 {
			m.processPendingPackets(pendingPackets)
		}

		// Use incremental updates to avoid O(n) copies on every tick
		// This only copies new packets instead of the entire buffer
		m.updatePacketListIncremental()

		// Update details panel if showing details
		if m.uiState.ShowDetails {
			m.updateDetailsPanel()
		}

		// Record rates for statistics sparklines (~1 Hz)
		// Rate tracker expects samples at ~1 second intervals
		now := time.Now()
		if now.Sub(m.lastRateRecord) >= time.Second {
			m.uiState.StatisticsView.RecordRates()

			// Update TUI process metrics (CPU/RAM)
			if m.metricsCollector != nil {
				metrics := m.metricsCollector.Get()
				m.uiState.StatisticsView.UpdateTUIMetrics(metrics.CPUPercent, metrics.MemoryRSSBytes)
			}

			m.lastRateRecord = now
		}

		return m, tickCmd()
	}

	// When paused but still capturing: only update TUI metrics
	if m.uiState.Paused && m.uiState.Capturing {
		if m.metricsCollector != nil {
			metrics := m.metricsCollector.Get()
			m.uiState.StatisticsView.UpdateTUIMetrics(metrics.CPUPercent, metrics.MemoryRSSBytes)
		}
		return m, slowTickCmd()
	}

	// When not capturing, stop ticking
	return m, nil
}

// handleUpdateBufferSizeMsg handles buffer size change requests
func (m Model) handleUpdateBufferSizeMsg(msg components.UpdateBufferSizeMsg) (Model, tea.Cmd) {
	// Update buffer size on-the-fly without restarting capture
	// ResizeBuffer handles the resize atomically to prevent races with AddPacket
	m.packetStore.ResizeBuffer(msg.Size)

	// Update packet list display
	if !m.packetStore.HasFilter() {
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	} else {
		m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
	}

	// Save to config file
	m.uiState.SettingsView.SaveBufferSize()

	return m, nil
}

// handleAddNodeMsg handles adding a new remote processor node
func (m Model) handleAddNodeMsg(msg components.AddNodeMsg) (Model, tea.Cmd) {
	// User wants to add a remote node
	if msg.Address != "" {
		// Add processor to tracking if not already present
		if _, exists := m.connectionMgr.Processors[msg.Address]; !exists {
			m.connectionMgr.Processors[msg.Address] = &store.ProcessorConnection{
				Address:      msg.Address,
				State:        store.ProcessorStateDisconnected,
				FailureCount: 0,
				TLSInsecure:  m.insecure, // Set based on --insecure flag
			}

			// Update nodes view to show the new processor immediately
			m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())

			// Save node history to config
			saveNodeHistory(m.uiState.NodesView)

			// Trigger connection attempt
			return m, func() tea.Msg {
				return ProcessorReconnectMsg{Address: msg.Address}
			}
		} else {
			// Processor already exists - show warning toast
			return m, m.uiState.Toast.Show(
				fmt.Sprintf("%s is already connected", msg.Address),
				components.ToastWarning,
				components.ToastDurationNormal,
			)
		}
	}
	return m, nil
}

// handleLoadNodesMsg handles loading nodes from a YAML file
func (m Model) handleLoadNodesMsg(msg components.LoadNodesMsg) (Model, tea.Cmd) {
	// Load nodes from YAML file and connect to them
	if msg.FilePath != "" {
		return m, loadNodesFile(msg.FilePath)
	}
	return m, nil
}

// handleNodesLoadedMsg handles successful nodes file load
func (m Model) handleNodesLoadedMsg(msg NodesLoadedMsg) (Model, tea.Cmd) {
	// Nodes loaded successfully from YAML file
	return m, m.uiState.Toast.Show(
		fmt.Sprintf("Loaded %d node(s) from %s", msg.NodeCount, filepath.Base(msg.FilePath)),
		components.ToastSuccess,
		components.ToastDurationShort,
	)
}

// handleNodesLoadFailedMsg handles failed nodes file load
func (m Model) handleNodesLoadFailedMsg(msg NodesLoadFailedMsg) (Model, tea.Cmd) {
	// Failed to load nodes from YAML file
	return m, m.uiState.Toast.Show(
		fmt.Sprintf("Failed to load %s: %s", filepath.Base(msg.FilePath), msg.Error.Error()),
		components.ToastError,
		components.ToastDurationLong,
	)
}

// handleProtocolSelectedMsg handles protocol selection from protocol selector
func (m Model) handleProtocolSelectedMsg(msg components.ProtocolSelectedMsg) (Model, tea.Cmd) {
	// User selected a protocol from the protocol selector
	m.uiState.SelectedProtocol = msg.Protocol

	// Update statistics view with selected protocol for protocol-specific stats
	m.uiState.StatisticsView.SetSelectedProtocol(msg.Protocol.Name)

	// Apply BPF filter if protocol has one
	var filterErrorCmd tea.Cmd
	if msg.Protocol.BPFFilter != "" {
		// Protocol selection REPLACES existing filters (not stacking)
		m.packetStore.ClearFilter()
		filterErrorCmd = m.parseAndApplyFilter(msg.Protocol.BPFFilter)
		// Reset sync counters for incremental updates
		_, _, _, matchedPackets := m.packetStore.GetBufferInfo()
		m.lastSyncedFilteredCount = matchedPackets
		m.lastSyncedTotal = 0
	} else {
		// "All" protocol - clear filters
		m.packetStore.ClearFilter()
		m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
		m.packetStore.MatchedPackets = int64(m.packetStore.PacketsCount)
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		// Reset sync counters for incremental updates
		_, _, total, _ := m.packetStore.GetBufferInfo()
		m.lastSyncedTotal = total
		m.lastSyncedFilteredCount = 0
	}

	// Switch to calls view if VoIP protocol selected
	// Also enable/disable TCP reassembly for SIP detection
	if msg.Protocol.Name == "VoIP (SIP/RTP)" {
		m.uiState.ViewMode = "calls"
		SetVoIPModeEnabled(true) // Enable TCP reassembly for SIP
	} else {
		m.uiState.ViewMode = "packets"
		SetVoIPModeEnabled(false) // Disable TCP reassembly (matches `lc hunt` behavior)
	}

	// Show toast notification (only if no filter error)
	if filterErrorCmd != nil {
		return m, filterErrorCmd
	}

	var toastMsg string
	if msg.Protocol.Name == "All" {
		toastMsg = "Showing all protocols"
	} else {
		toastMsg = fmt.Sprintf("Filtering: %s", msg.Protocol.Name)
	}
	return m, m.uiState.Toast.Show(
		toastMsg,
		components.ToastInfo,
		components.ToastDurationShort,
	)
}

// handleFileSelectedMsg handles file selection from file dialog
func (m Model) handleFileSelectedMsg(msg components.FileSelectedMsg) (Model, tea.Cmd) {
	// Check if this is from Settings tab (opening file for reading)
	// vs from save dialog (writing file)
	if m.uiState.Tabs.GetActive() == 3 {
		// Settings tab - this is for opening a PCAP file to read
		// Forward the message to Settings view to handle it
		cmd := m.uiState.SettingsView.Update(msg)
		return m, cmd
	}

	// Otherwise, this is from save dialog - user wants to save packets
	filePath := msg.Path()

	// Check if file exists
	if _, err := os.Stat(filePath); err == nil {
		// File exists - show confirmation dialog
		fileName := filepath.Base(filePath)
		cmd := m.uiState.ConfirmDialog.Show(components.ConfirmDialogOptions{
			Type:        components.ConfirmDialogWarning,
			Title:       "File Already Exists",
			Message:     fmt.Sprintf("File '%s' already exists. Overwrite?", fileName),
			Details:     []string{"Path: " + filePath},
			ConfirmText: "y",
			CancelText:  "n",
			UserData: FileOverwriteData{
				FilePath: filePath,
			},
		})
		return m, cmd
	}

	// File doesn't exist, proceed with save
	return m, m.proceedWithSave(filePath)
}

// handleConfirmDialogResult handles confirmation dialog responses
func (m Model) handleConfirmDialogResult(msg components.ConfirmDialogResult) (Model, tea.Cmd) {
	// Check if this is a node deletion confirmation
	if nodeDeletion, ok := msg.UserData.(NodeDeletionData); ok {
		if msg.Confirmed {
			// User confirmed deletion, perform it
			return m, m.performNodeDeletion(nodeDeletion)
		}
		// User cancelled, do nothing
		return m, nil
	}

	// Check if this is a file overwrite confirmation
	if fileOverwrite, ok := msg.UserData.(FileOverwriteData); ok {
		if msg.Confirmed {
			// User confirmed overwrite, proceed with save
			return m, m.proceedWithSave(fileOverwrite.FilePath)
		}
		// User cancelled, do nothing
		return m, nil
	}

	// Legacy fallback: User responded to file overwrite confirmation (for backward compatibility)
	if msg.Confirmed && m.pendingSavePath != "" {
		// User confirmed overwrite, proceed with save
		filePath := m.pendingSavePath
		m.pendingSavePath = "" // Clear pending path
		return m, m.proceedWithSave(filePath)
	} else if m.pendingSavePath != "" {
		// User cancelled
		m.pendingSavePath = "" // Clear pending path
		return m, nil
	}

	return m, nil
}

// handleSaveCompleteMsg handles save operation completion
func (m Model) handleSaveCompleteMsg(msg SaveCompleteMsg) (Model, tea.Cmd) {
	// Save operation completed
	m.uiState.SaveInProgress = false

	// If this was a streaming save completion, update UI
	if msg.Streaming {
		m.uiState.Footer.SetStreamingSave(false)
		m.uiState.Header.SetStreamingSave(false)
	}

	if msg.Success {
		// Show success toast
		toastMsg := fmt.Sprintf("Saved %d packets to %s", msg.PacketsSaved, filepath.Base(msg.Path))
		cmd := m.uiState.Toast.ShowWithKey(
			toastMsg,
			components.ToastSuccess,
			components.ToastDurationLong,
			components.ToastKeyFileSave,
		)
		return m, cmd
	} else {
		// Show error toast
		toastMsg := fmt.Sprintf("Failed to save: %s", msg.Error.Error())
		cmd := m.uiState.Toast.ShowWithKey(
			toastMsg,
			components.ToastError,
			components.ToastDurationLong,
			components.ToastKeyFileSave,
		)
		return m, cmd
	}
}

// handleFilterOperationResultMsg handles filter operation completion
func (m Model) handleFilterOperationResultMsg(msg components.FilterOperationResultMsg) (Model, tea.Cmd) {
	// Filter operation completed (create/update/delete)
	if msg.Success {
		var toastMsg string
		switch msg.Operation {
		case "create":
			toastMsg = fmt.Sprintf("Filter '%s' created", msg.FilterPattern)
		case "update", "toggle":
			toastMsg = fmt.Sprintf("Filter '%s' updated", msg.FilterPattern)
		case "delete":
			toastMsg = fmt.Sprintf("Filter '%s' deleted", msg.FilterPattern)
		default:
			toastMsg = fmt.Sprintf("Filter operation completed")
		}
		return m, m.uiState.Toast.Show(
			toastMsg,
			components.ToastSuccess,
			components.ToastDurationShort,
		)
	}

	// Operation failed - display error with chain context if available
	errorMsg := m.formatChainError(msg.Operation, msg.FilterPattern, msg.Error)
	return m, m.uiState.Toast.Show(
		errorMsg,
		components.ToastError,
		components.ToastDurationLong,
	)
}

// handleHunterSelectionConfirmedMsg handles confirmed hunter selection
func (m Model) handleHunterSelectionConfirmedMsg(msg components.HunterSelectionConfirmedMsg) (Model, tea.Cmd) {
	// User confirmed hunter selection - reconnect with new hunter filter
	return m, m.handleHunterSelectionConfirmed(msg)
}

// handleLoadHuntersFromProcessorMsg handles request to load hunters from processor
func (m Model) handleLoadHuntersFromProcessorMsg(msg components.LoadHuntersFromProcessorMsg) (Model, tea.Cmd) {
	// Load hunters from processor for hunter selector
	return m, m.loadHuntersFromProcessor(msg.ProcessorAddr)
}

// handleHuntersLoadedMsg handles loaded hunters from processor
func (m Model) handleHuntersLoadedMsg(msg components.HuntersLoadedMsg) (Model, tea.Cmd) {
	// Hunters loaded - update hunter selector
	m.uiState.HunterSelector.SetHunters(msg.Hunters)
	return m, nil
}

// handleFiltersLoadedMsg handles loaded filters from processor
func (m Model) handleFiltersLoadedMsg(msg components.FiltersLoadedMsg) (Model, tea.Cmd) {
	// Filters loaded from processor - update filter manager
	if msg.Err != nil {
		logger.Error("Failed to load filters", "error", msg.Err)
		m.uiState.FilterManager.SetFilters([]*management.Filter{})
	} else {
		m.uiState.FilterManager.SetFilters(msg.Filters)
	}
	return m, nil
}

// handleFilterOperationMsg handles filter operation request
func (m Model) handleFilterOperationMsg(msg components.FilterOperationMsg) (Model, tea.Cmd) {
	// Execute filter operation via gRPC
	return m, m.executeFilterOperation(msg)
}

// handleCaptureCompleteMsg handles offline capture completion.
// This is critical for ensuring all packets are processed when reading PCAP files,
// which can complete faster than the TUI tick interval (100ms).
func (m Model) handleCaptureCompleteMsg(msg CaptureCompleteMsg) (Model, tea.Cmd) {
	logger.Debug("Offline capture complete, draining remaining packets",
		"packets_received", msg.PacketsReceived)

	// Drain ALL remaining packets from pending buffer
	// Unlike the tick handler which drains a limited number, we drain everything
	// to ensure no packets are lost when capture completes
	for {
		pendingPackets := DrainPendingPackets()
		if len(pendingPackets) == 0 {
			break
		}
		m.processPendingPackets(pendingPackets)
	}

	// Do a final packet list update
	m.updatePacketListIncremental()

	// Update details panel if showing
	if m.uiState.ShowDetails {
		m.updateDetailsPanel()
	}

	// Get final packet count from store for the toast message
	_, _, totalPackets, _ := m.packetStore.GetBufferInfo()

	// Show completion toast
	toastCmd := m.uiState.Toast.Show(
		fmt.Sprintf("Capture complete: %d packets loaded", totalPackets),
		components.ToastSuccess,
		components.ToastDurationLong,
	)

	// Note: We don't set Capturing = false here because:
	// 1. The user might want to continue viewing/filtering packets
	// 2. The tick handler continues updating the UI as needed
	// 3. Setting it to false would stop all UI updates

	return m, toastCmd
}
