//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pcap"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// captureHandle holds cancellation and completion signaling for a capture session
type captureHandle struct {
	cancel context.CancelFunc
	done   chan struct{} // Closed when capture goroutine exits
}

// Global state for capture management (shared with tui.go)
var (
	currentCaptureHandle *captureHandle
	currentProgram       *tea.Program
)

// PacketMsg is sent when a new packet is captured
type PacketMsg struct {
	Packet components.PacketDisplay
}

// ProcessorConnectedMsg is sent when a processor connection succeeds
type ProcessorConnectedMsg struct {
	Address string
	Client  interface{ Close() }
}

// ProcessorReconnectMsg is sent to trigger a reconnection attempt
type ProcessorReconnectMsg struct {
	Address   string
	HunterIDs []string // Optional: specific hunters to subscribe to (empty = all)
}

// TickMsg is sent periodically to trigger UI updates
type TickMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg{}
	})
}

// CleanupOldProcessorsMsg is sent periodically to clean up old disconnected processors
type CleanupOldProcessorsMsg struct{}

func cleanupProcessorsCmd() tea.Cmd {
	return tea.Tick(5*time.Minute, func(t time.Time) tea.Msg {
		return CleanupOldProcessorsMsg{}
	})
}

// SaveCompleteMsg is sent when a save operation completes
type SaveCompleteMsg struct {
	Success      bool
	Path         string
	Error        error
	PacketsSaved int
	Streaming    bool // True if this was a streaming save stop
}

// Model represents the TUI application state
// Data management is delegated to specialized stores
type Model struct {
	// Data stores (thread-safe)
	packetStore   *store.PacketStore
	connectionMgr *store.ConnectionManager
	uiState       *store.UIState

	// High-level application state
	statistics    *components.Statistics // Statistics data
	interfaceName string                 // Capture interface name
	bpfFilter     string                 // Current BPF filter
	captureMode   components.CaptureMode // Current capture mode (live or offline)
	nodesFilePath string                 // Path to nodes YAML file for remote mode

	// Save state
	activeWriter    pcap.PcapWriter // Active streaming writer (nil if not saving)
	savePath        string          // Path being written to (for streaming save)
	pendingSavePath string          // Path pending confirmation (for overwrite dialog)
	captureLinkType layers.LinkType // Link type from capture source (for PCAP writing)

	// Test state
	testToastCycle int // Cycles through toast types for testing
}

// getPacketsInOrder returns packets from the circular buffer in chronological order
func NewModel(bufferSize int, interfaceName string, bpfFilter string, pcapFile string, promiscuous bool, startInRemoteMode bool, nodesFilePath string) Model {
	// Load theme from config, default to Solarized Dark
	themeName := viper.GetString("tui.theme")
	if themeName == "" {
		themeName = "dark"
	}
	theme := themes.GetTheme(themeName)

	// Initialize data stores
	packetStore := store.NewPacketStore(bufferSize)
	connectionMgr := store.NewConnectionManager()
	uiState := store.NewUIState(theme)

	// Load filter history from config
	loadFilterHistory(&uiState.FilterInput)

	// Determine initial capture mode and interface name
	initialMode := components.CaptureModeLive
	initialInterfaceName := interfaceName
	initialPCAPFile := pcapFile
	if pcapFile != "" {
		initialMode = components.CaptureModeOffline
		initialInterfaceName = pcapFile
		// Update first tab for offline mode
		uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
	} else if startInRemoteMode {
		initialMode = components.CaptureModeRemote
		// Set interface name to nodes file or look for default
		if nodesFilePath == "" {
			// Try default paths: ./nodes.yaml or ~/.config/lippycat/nodes.yaml
			if _, err := os.Stat("nodes.yaml"); err == nil {
				nodesFilePath = "nodes.yaml"
			} else {
				homeDir, err := os.UserHomeDir()
				if err == nil {
					configPath := filepath.Join(homeDir, ".config", "lippycat", "nodes.yaml")
					if _, err := os.Stat(configPath); err == nil {
						nodesFilePath = configPath
					}
				}
			}
		}

		if nodesFilePath != "" {
			initialInterfaceName = nodesFilePath
		} else {
			initialInterfaceName = ""
		}
		// Clear pcapFile and interface for remote mode
		initialPCAPFile = ""
		// Update first tab for remote mode
		uiState.Tabs.UpdateTab(0, "Remote Capture", "🌐")
		// Switch to Nodes tab when starting in remote mode
		uiState.Tabs.SetActive(1)
	}

	// Create settings view with correct initial mode
	uiState.SettingsView = components.NewSettingsView(interfaceName, bufferSize, promiscuous, bpfFilter, initialPCAPFile)
	uiState.SettingsView.SetTheme(theme)
	// Set the correct capture mode in settings
	uiState.SettingsView.SetCaptureMode(initialMode)
	// Set nodes file if in remote mode
	if startInRemoteMode && nodesFilePath != "" {
		uiState.SettingsView.SetNodesFile(nodesFilePath)
	}

	// Initialize statistics with bounded counters to prevent memory growth
	uiState.Statistics = &components.Statistics{
		ProtocolCounts: components.NewBoundedCounter(1000),  // Max 1000 unique protocols
		SourceCounts:   components.NewBoundedCounter(10000), // Max 10000 unique source IPs
		DestCounts:     components.NewBoundedCounter(10000), // Max 10000 unique dest IPs
		MinPacketSize:  999999,
		MaxPacketSize:  0,
	}

	// Set initial capturing state
	// For live/offline modes, capture will auto-start in tui.go
	// For remote mode, capturing will be set when nodes connect
	if initialMode == components.CaptureModeLive || initialMode == components.CaptureModeOffline {
		uiState.SetCapturing(true)
	}

	return Model{
		packetStore:   packetStore,
		connectionMgr: connectionMgr,
		uiState:       uiState,
		statistics:    uiState.Statistics, // Reference to same statistics
		interfaceName: initialInterfaceName,
		bpfFilter:     bpfFilter,
		captureMode:   initialMode,
		nodesFilePath: nodesFilePath,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	// Load remote nodes if in remote mode
	if m.captureMode == components.CaptureModeRemote && m.nodesFilePath != "" {
		return tea.Batch(tickCmd(), cleanupProcessorsCmd(), loadNodesFile(m.nodesFilePath))
	}
	return tea.Batch(tickCmd(), cleanupProcessorsCmd())
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// If settings tab is active and editing interface, pass messages to settings
	// (this is needed for list filtering to work properly)
	// BUT: Don't intercept PacketMsg, TickMsg, or RestartCaptureMsg - those need to be handled by the main model
	if m.uiState.Tabs.GetActive() == 3 && m.uiState.SettingsView.IsEditingInterface() {
		switch msg.(type) {
		case PacketMsg, TickMsg, components.RestartCaptureMsg:
			// Let these fall through to normal handling
		default:
			// Handle quit/suspend keys
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.String() {
				case "q", "ctrl+c":
					m.uiState.Quitting = true
					return m, tea.Quit
				case "ctrl+z":
					// Suspend the process
					return m, tea.Suspend
				}
			}
			// Pass all other messages to settings view
			cmd := m.uiState.SettingsView.Update(msg)
			return m, cmd
		}
	}

	// Handle toast messages FIRST (even when modals are active)
	// This ensures toast auto-dismiss timer continues working
	var toastCmd tea.Cmd
	if m.uiState.Toast.IsActive() {
		toastCmd = m.uiState.Toast.Update(msg)
	}

	// Handle modals BEFORE type switch so they can receive ALL message types
	// (including internal messages from Init() commands like readDirMsg)

	// Protocol selector modal
	if m.uiState.ProtocolSelector.IsActive() {
		cmd := m.uiState.ProtocolSelector.Update(msg)
		return m, tea.Batch(toastCmd, cmd)
	}

	// Hunter selector modal
	if m.uiState.HunterSelector.IsActive() {
		// Only intercept user input (KeyMsg, MouseMsg), let internal messages pass through
		switch msg.(type) {
		case tea.KeyMsg, tea.MouseMsg:
			cmd := m.uiState.HunterSelector.Update(msg)
			return m, tea.Batch(toastCmd, cmd)
		}
		// Fall through for internal messages (HuntersLoadedMsg, LoadHuntersFromProcessorMsg, etc.)
	}

	// Filter manager modal
	if m.uiState.FilterManager.IsActive() {
		// Only intercept user input (KeyMsg, MouseMsg), let internal messages pass through
		switch msg.(type) {
		case tea.KeyMsg, tea.MouseMsg:
			cmd := m.uiState.FilterManager.Update(msg)
			return m, tea.Batch(toastCmd, cmd)
		}
		// Fall through for internal messages (FiltersLoadedMsg, FilterOperationMsg, etc.)
	}

	// Settings file dialog modal (for opening PCAP files)
	if m.uiState.SettingsView.IsFileDialogActive() {
		cmd := m.uiState.SettingsView.Update(msg)
		return m, tea.Batch(toastCmd, cmd)
	}

	// File dialog modal (for saving packets)
	if m.uiState.FileDialog.IsActive() {
		cmd := m.uiState.FileDialog.Update(msg)
		return m, tea.Batch(toastCmd, cmd)
	}

	// Confirm dialog modal
	if m.uiState.ConfirmDialog.IsActive() {
		cmd := m.uiState.ConfirmDialog.Update(msg)
		return m, tea.Batch(toastCmd, cmd)
	}

	// Add node modal
	if m.uiState.NodesView.IsModalOpen() {
		cmd := m.uiState.NodesView.Update(msg)
		return m, tea.Batch(toastCmd, cmd)
	}

	switch msg := msg.(type) {
	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tea.KeyMsg:
		return m.handleKeyboard(msg)

	case tea.WindowSizeMsg:
		m.uiState.Width = msg.Width
		m.uiState.Height = msg.Height

		// Update all component sizes
		m.uiState.Header.SetWidth(msg.Width)
		m.uiState.Footer.SetWidth(msg.Width)
		m.uiState.Tabs.SetWidth(msg.Width)
		m.uiState.FilterInput.SetWidth(msg.Width)
		m.uiState.FileDialog.SetSize(msg.Width, msg.Height)
		m.uiState.ConfirmDialog.SetSize(msg.Width, msg.Height)
		m.uiState.Toast.SetSize(msg.Width, msg.Height)

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

		return m, nil

	case tea.ResumeMsg:
		// Handle resume after suspend (ctrl+z / fg)
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

	case TickMsg:
		// Only run tick when capturing and not paused
		if !m.uiState.Paused && m.uiState.Capturing {
			// Periodic UI refresh (10 times per second)
			if m.uiState.NeedsUIUpdate {
				// Update packet list component with filtered packets
				// No need to reapply filters - they're applied per-packet now
				if !m.packetStore.HasFilter() {
					m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
				} else {
					m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
				}

				// Update details panel if showing details
				if m.uiState.ShowDetails {
					m.updateDetailsPanel()
				}

				m.uiState.NeedsUIUpdate = false
			}
			return m, tickCmd()
		}
		// When paused, stop ticking to save CPU
		return m, nil

	case PacketBatchMsg:
		return m.handlePacketBatchMsg(msg)

	case CallUpdateMsg:
		return m.handleCallUpdateMsg(msg)

	case PacketMsg:
		return m.handlePacketMsg(msg)

	case HunterStatusMsg:
		return m.handleHunterStatusMsg(msg)

	case components.UpdateBufferSizeMsg:
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

	case components.RestartCaptureMsg:
		return m.handleRestartCaptureMsg(msg)

	case components.AddNodeMsg:
		// User wants to add a remote node
		if msg.Address != "" {
			// Add processor to tracking if not already present
			if _, exists := m.connectionMgr.Processors[msg.Address]; !exists {
				m.connectionMgr.Processors[msg.Address] = &store.ProcessorConnection{
					Address:      msg.Address,
					State:        store.ProcessorStateDisconnected,
					FailureCount: 0,
				}

				// Update nodes view to show the new processor immediately
				// Merge all hunters from all processors for display
				allHunters := make([]components.HunterInfo, 0)
				for _, hunters := range m.connectionMgr.HuntersByProcessor {
					allHunters = append(allHunters, hunters...)
				}
				m.uiState.NodesView.SetHuntersAndProcessors(allHunters, m.getConnectedProcessors())

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

	case components.LoadNodesMsg:
		// Load nodes from YAML file and connect to them
		if msg.FilePath != "" {
			return m, loadNodesFile(msg.FilePath)
		}
		return m, nil

	case NodesLoadedMsg:
		// Nodes loaded successfully from YAML file
		return m, m.uiState.Toast.Show(
			fmt.Sprintf("Loaded %d node(s) from %s", msg.NodeCount, filepath.Base(msg.FilePath)),
			components.ToastSuccess,
			components.ToastDurationShort,
		)

	case NodesLoadFailedMsg:
		// Failed to load nodes from YAML file
		return m, m.uiState.Toast.Show(
			fmt.Sprintf("Failed to load %s: %s", filepath.Base(msg.FilePath), msg.Error.Error()),
			components.ToastError,
			components.ToastDurationLong,
		)

	case components.ProtocolSelectedMsg:
		// User selected a protocol from the protocol selector
		m.uiState.SelectedProtocol = msg.Protocol

		// Apply BPF filter if protocol has one
		var filterErrorCmd tea.Cmd
		if msg.Protocol.BPFFilter != "" {
			filterErrorCmd = m.parseAndApplyFilter(msg.Protocol.BPFFilter)
		} else {
			// "All" protocol - clear filters
			m.packetStore.ClearFilter()
			m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
			m.packetStore.MatchedPackets = m.packetStore.PacketsCount
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		}

		// Switch to calls view if VoIP protocol selected
		if msg.Protocol.Name == "VoIP (SIP/RTP)" {
			m.uiState.ViewMode = "calls"
		} else {
			m.uiState.ViewMode = "packets"
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

	case components.FileSelectedMsg:
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
			m.pendingSavePath = filePath
			cmd := m.uiState.ConfirmDialog.Activate(
				fmt.Sprintf("File '%s' already exists. Overwrite?", filepath.Base(filePath)),
			)
			return m, cmd
		}

		// File doesn't exist, proceed with save
		return m, m.proceedWithSave(filePath)

	case components.ConfirmDialogResult:
		// User responded to file overwrite confirmation
		if msg.Confirmed && m.pendingSavePath != "" {
			// User confirmed overwrite, proceed with save
			filePath := m.pendingSavePath
			m.pendingSavePath = "" // Clear pending path
			return m, m.proceedWithSave(filePath)
		} else {
			// User cancelled or no pending path
			m.pendingSavePath = "" // Clear pending path
			return m, nil
		}

	case SaveCompleteMsg:
		// Save operation completed
		m.uiState.SaveInProgress = false

		// If this was a streaming save completion, update footer
		if msg.Streaming {
			m.uiState.Footer.SetStreamingSave(false)
		}

		if msg.Success {
			// Show success toast
			toastMsg := fmt.Sprintf("Saved %d packets to %s", msg.PacketsSaved, filepath.Base(msg.Path))
			cmd := m.uiState.Toast.Show(
				toastMsg,
				components.ToastSuccess,
				components.ToastDurationLong,
			)
			return m, cmd
		} else {
			// Show error toast
			toastMsg := fmt.Sprintf("Failed to save: %s", msg.Error.Error())
			cmd := m.uiState.Toast.Show(
				toastMsg,
				components.ToastError,
				components.ToastDurationLong,
			)
			return m, cmd
		}

	case components.FilterOperationResultMsg:
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
		return m, nil

	case ProcessorReconnectMsg:
		return m.handleProcessorReconnectMsg(msg)

	case ProcessorConnectedMsg:
		return m.handleProcessorConnectedMsg(msg)

	case ProcessorDisconnectedMsg:
		return m.handleProcessorDisconnectedMsg(msg)

	case CleanupOldProcessorsMsg:
		return m.handleCleanupOldProcessorsMsg(msg)

	case components.HunterSelectionConfirmedMsg:
		// User confirmed hunter selection - reconnect with new hunter filter
		return m, m.handleHunterSelectionConfirmed(msg)

	case components.LoadHuntersFromProcessorMsg:
		// Load hunters from processor for hunter selector
		return m, m.loadHuntersFromProcessor(msg.ProcessorAddr)

	case components.HuntersLoadedMsg:
		// Hunters loaded - update hunter selector
		m.uiState.HunterSelector.SetHunters(msg.Hunters)
		return m, nil

	case components.FiltersLoadedMsg:
		// Filters loaded from processor - update filter manager
		if msg.Err != nil {
			logger.Error("Failed to load filters", "error", msg.Err)
			m.uiState.FilterManager.SetFilters([]*management.Filter{})
		} else {
			m.uiState.FilterManager.SetFilters(msg.Filters)
		}
		return m, nil

	case components.FilterOperationMsg:
		// Execute filter operation via gRPC
		return m, m.executeFilterOperation(msg)
	}

	// Return toast command if active
	if toastCmd != nil {
		return m, toastCmd
	}
	return m, nil
}

// handleMouse handles mouse click and scroll events

// View renders the TUI
// View is implemented in view_renderer.go
// handleFilterInput is implemented in filter_operations.go
// saveThemePreference is implemented in preferences.go
// loadFilterHistory is implemented in preferences.go
// saveFilterHistory is implemented in preferences.go
// handleOpenFilterManager is implemented in filter_operations.go
// loadFiltersFromProcessor is implemented in filter_operations.go
// executeFilterOperation is implemented in filter_operations.go

// determineSaveMode determines whether to use one-shot or streaming save

// mapCallState converts string state to components.CallState
func mapCallState(state string) components.CallState {
	switch state {
	case "RINGING":
		return components.CallStateRinging
	case "ACTIVE":
		return components.CallStateActive
	case "ENDED":
		return components.CallStateEnded
	case "FAILED":
		return components.CallStateFailed
	default:
		return components.CallStateRinging
	}
}
