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
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/config"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pcap"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
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
		// Stop any active streaming save before switching modes
		if m.activeWriter != nil {
			// Close writer synchronously (must complete before mode switch)
			if err := m.activeWriter.Close(); err != nil {
				// Log error but continue with mode switch
				logger.Warn("Failed to close streaming writer during mode switch",
					"error", err,
					"path", m.savePath)
			}
			// Clear streaming save state
			m.activeWriter = nil
			m.savePath = ""
			m.uiState.StreamingSave = false
			m.uiState.Footer.SetStreamingSave(false) // Update footer hint
		}

		// Stop current capture and wait for it to finish
		if currentCaptureHandle != nil {
			// Cancel the old capture and wait for completion
			// This ensures old and new captures don't run simultaneously
			handle := currentCaptureHandle
			currentCaptureHandle = nil // Clear immediately to prevent double-cancellation

			handle.cancel()
			// Wait for capture goroutine to finish (deterministic, no race conditions)
			<-handle.done
		}

		// Keep all remote clients connected regardless of mode
		// Users can switch between modes without losing node connections

		// Update settings based on mode and show toast
		var toastCmd tea.Cmd
		switch msg.Mode {
		case components.CaptureModeLive:
			m.interfaceName = msg.Interface
			m.uiState.Tabs.UpdateTab(0, "Live Capture", "📡")
			toastCmd = m.uiState.Toast.Show(
				fmt.Sprintf("Switched to live capture on %s", msg.Interface),
				components.ToastInfo,
				components.ToastDurationShort,
			)
		case components.CaptureModeOffline:
			m.interfaceName = msg.PCAPFile
			m.uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
			toastCmd = m.uiState.Toast.Show(
				fmt.Sprintf("Opening %s...", filepath.Base(msg.PCAPFile)),
				components.ToastInfo,
				components.ToastDurationShort,
			)
		case components.CaptureModeRemote:
			m.interfaceName = msg.NodesFile
			m.uiState.Tabs.UpdateTab(0, "Remote Capture", "🌐")
			toastCmd = m.uiState.Toast.Show(
				"Switched to remote capture mode",
				components.ToastInfo,
				components.ToastDurationShort,
			)
		}
		m.bpfFilter = msg.Filter

		// Update mode BEFORE starting new capture so packet handlers check the right mode
		m.captureMode = msg.Mode
		m.packetStore.MaxPackets = msg.BufferSize // Apply the new buffer size
		m.uiState.Paused = false                  // Unpause when restarting capture

		// Clear old packets with new buffer size
		m.packetStore.Packets = make([]components.PacketDisplay, m.packetStore.MaxPackets)
		m.packetStore.PacketsHead = 0
		m.packetStore.PacketsCount = 0
		m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
		m.packetStore.TotalPackets = 0
		m.packetStore.MatchedPackets = 0
		m.uiState.PacketList.Reset() // Reset packet list including autoscroll state

		// Reset statistics (bounded counters)
		m.statistics.ProtocolCounts.Clear()
		m.statistics.SourceCounts.Clear()
		m.statistics.DestCounts.Clear()
		m.statistics.TotalBytes = 0
		m.statistics.TotalPackets = 0
		m.statistics.MinPacketSize = 999999
		m.statistics.MaxPacketSize = 0
		m.uiState.StatisticsView.SetStatistics(m.statistics)

		// Start new capture in background using global program reference
		if currentProgram != nil {
			// Only create new capture context for live/offline modes
			// Remote mode doesn't need a capture context since it uses gRPC clients
			if msg.Mode == components.CaptureModeLive || msg.Mode == components.CaptureModeOffline {
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				currentCaptureHandle = &captureHandle{cancel: cancel, done: done}

				switch msg.Mode {
				case components.CaptureModeLive:
					go startLiveCapture(ctx, msg.Interface, m.bpfFilter, currentProgram, done)
				case components.CaptureModeOffline:
					go startOfflineCapture(ctx, msg.PCAPFile, m.bpfFilter, currentProgram, done)
				}

				// Mark capture as active for live/offline modes
				m.uiState.SetCapturing(true)
			} else if msg.Mode == components.CaptureModeRemote {
				// Remote mode: set capture handle to nil since we're not running local capture
				currentCaptureHandle = nil

				// Load and connect to nodes from YAML file (if provided)
				if msg.NodesFile != "" {
					m.nodesFilePath = msg.NodesFile
					return m, tea.Batch(toastCmd, loadNodesFile(msg.NodesFile))
				}
				// If no nodes file, remote mode is active but no nodes connected yet
				// User can add nodes via Nodes tab
				// Capturing will be marked active when nodes connect successfully
			}
		}

		return m, toastCmd

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
func (m Model) View() string {
	if m.uiState.Quitting {
		return "Goodbye!\n"
	}

	// Update header state
	m.uiState.Header.SetState(m.uiState.Capturing, m.uiState.Paused)
	m.uiState.Header.SetPacketCount(m.packetStore.TotalPackets)
	m.uiState.Header.SetInterface(m.interfaceName)
	m.uiState.Header.SetCaptureMode(m.captureMode)
	// Use hunter count (not remote client count) for accurate node display
	m.uiState.Header.SetNodeCount(m.uiState.NodesView.GetHunterCount())
	m.uiState.Header.SetProcessorCount(m.uiState.NodesView.GetProcessorCount())

	// Update footer state
	m.uiState.Footer.SetFilterMode(m.uiState.FilterMode)
	m.uiState.Footer.SetHasFilter(m.packetStore.HasFilter())
	m.uiState.Footer.SetFilterCount(m.packetStore.FilterChain.Count())

	// Render components
	headerView := m.uiState.Header.View()
	tabsView := m.uiState.Tabs.View()
	footerView := m.uiState.Footer.View()

	var mainContent string

	// Calculate content dimensions
	headerHeight := 2
	tabsHeight := 4
	bottomHeight := 4
	contentHeight := m.uiState.Height - headerHeight - tabsHeight - bottomHeight

	// Render main content based on active tab
	switch m.uiState.Tabs.GetActive() {
	case 0: // Live/Remote/Offline Capture
		// Check if we should display calls view or packets view
		if m.uiState.ViewMode == "calls" {
			// Render calls view
			m.uiState.CallsView.SetSize(m.uiState.Width, contentHeight)
			mainContent = m.uiState.CallsView.View()
		} else {
			// Render packets view
			minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
			detailsVisible := m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails
			if detailsVisible {
				// Split pane layout
				leftFocused := m.uiState.FocusedPane == "left"
				rightFocused := m.uiState.FocusedPane == "right"

				detailsWidth := 77 // Hex dump (72) + borders/padding (5)

				// Ensure details panel has the right size set
				m.uiState.DetailsPanel.SetSize(detailsWidth, contentHeight)

				packetListView := m.uiState.PacketList.View(leftFocused, true)
				detailsPanelView := m.uiState.DetailsPanel.View(rightFocused)

				mainContent = lipgloss.JoinHorizontal(lipgloss.Top, packetListView, detailsPanelView)
			} else {
				// Full width packet list - always show unfocused when details are hidden
				mainContent = m.uiState.PacketList.View(false, false)
			}
		}
	case 1: // Nodes
		// Render nodes view
		mainContent = m.uiState.NodesView.View()

	case 2: // Statistics
		// Render statistics view (content is updated via updateStatistics)
		mainContent = m.uiState.StatisticsView.View()
	case 3: // Settings
		// Render settings view
		mainContent = m.uiState.SettingsView.View()
	}

	// Combine main views (header + tabs + content)
	mainViews := []string{
		headerView,
		tabsView,
		mainContent,
	}
	mainView := lipgloss.JoinVertical(lipgloss.Left, mainViews...)

	// Create the bottom area (always 4 lines for consistent spacing)
	var bottomArea string

	// Check if any modal is active (hide toast when modal is open)
	modalActive := m.uiState.ProtocolSelector.IsActive() ||
		m.uiState.HunterSelector.IsActive() ||
		m.uiState.FilterManager.IsActive() ||
		m.uiState.SettingsView.IsFileDialogActive() ||
		m.uiState.FileDialog.IsActive() ||
		m.uiState.ConfirmDialog.IsActive() ||
		m.uiState.NodesView.IsModalOpen()

	if m.uiState.FilterMode {
		// Filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.uiState.FilterInput.View()
		bottomArea = filterView + "\n" + footerView
	} else if m.uiState.Toast.IsActive() && !modalActive {
		// Toast notification (3 lines with padding) + footer (1 line) = 4 lines
		// Hidden when modal is active
		toastView := m.uiState.Toast.View()
		bottomArea = toastView + "\n" + footerView
	} else {
		// All tabs: 3 blank lines + footer (1 line) = 4 lines
		// (Nodes tab hints bar is part of mainContent, not bottomArea)
		bottomArea = "\n\n\n" + footerView
	}

	fullView := lipgloss.JoinVertical(lipgloss.Left, mainView, bottomArea)

	// Overlay protocol selector if active - render it centered over a semi-transparent background
	if m.uiState.ProtocolSelector.IsActive() {
		selectorView := m.uiState.ProtocolSelector.View()

		// Simply place the selector in the center with background filling
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			selectorView,
		)
	}

	// Overlay hunter selector modal if active
	if m.uiState.HunterSelector.IsActive() {
		selectorView := m.uiState.HunterSelector.View()

		// Place the selector in the center
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			selectorView,
		)
	}

	// Overlay filter manager modal if active
	if m.uiState.FilterManager.IsActive() {
		filterManagerView := m.uiState.FilterManager.View()

		// Place the filter manager in the center
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			filterManagerView,
		)
	}

	// Overlay settings file dialogs (for opening PCAP or nodes files) if active
	if m.uiState.SettingsView.IsFileDialogActive() {
		// Set full window dimensions for proper centering (not just content area)
		// Check which dialog is active and render it
		if m.uiState.SettingsView.GetPcapFileDialog().IsActive() {
			pcapDialog := m.uiState.SettingsView.GetPcapFileDialog()
			pcapDialog.SetSize(m.uiState.Width, m.uiState.Height)
			return pcapDialog.View()
		} else if m.uiState.SettingsView.GetNodesFileDialog().IsActive() {
			nodesDialog := m.uiState.SettingsView.GetNodesFileDialog()
			nodesDialog.SetSize(m.uiState.Width, m.uiState.Height)
			return nodesDialog.View()
		}
	}

	// Overlay file dialog modal (for saving packets) if active
	if m.uiState.FileDialog.IsActive() {
		fileDialogView := m.uiState.FileDialog.View()
		// FileDialog uses RenderModal internally which centers it
		return fileDialogView
	}

	// Overlay confirm dialog modal if active
	if m.uiState.ConfirmDialog.IsActive() {
		confirmDialogView := m.uiState.ConfirmDialog.View()
		// ConfirmDialog uses RenderModal internally which centers it
		return confirmDialogView
	}

	// Overlay add node modal if active
	if m.uiState.NodesView.IsModalOpen() {
		modalView := m.uiState.NodesView.RenderModal(m.uiState.Width, m.uiState.Height)
		return modalView
	}

	return fullView
}

// updateStatistics updates statistics with new packet data

// handleFilterInput handles key input when in filter mode
func (m Model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Apply the filter
		filterValue := m.uiState.FilterInput.Value()
		var filterCmd tea.Cmd
		if filterValue != "" {
			filterCmd = m.parseAndApplyFilter(filterValue)
			m.uiState.FilterInput.AddToHistory(filterValue)
			// Save filter history to config
			saveFilterHistory(&m.uiState.FilterInput)
		} else {
			// Empty filter = clear all filters
			m.packetStore.ClearFilter()
			m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
			m.packetStore.MatchedPackets = m.packetStore.PacketsCount
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		}
		m.uiState.FilterMode = false
		m.uiState.FilterInput.Deactivate()
		return m, filterCmd

	case "esc", "ctrl+c":
		// Cancel filter input
		m.uiState.FilterMode = false
		m.uiState.FilterInput.Deactivate()
		return m, nil

	case "up", "ctrl+p":
		m.uiState.FilterInput.HistoryUp()
		return m, nil

	case "down", "ctrl+n":
		m.uiState.FilterInput.HistoryDown()
		return m, nil

	case "left", "ctrl+b":
		m.uiState.FilterInput.CursorLeft()
		return m, nil

	case "right", "ctrl+f":
		m.uiState.FilterInput.CursorRight()
		return m, nil

	case "home", "ctrl+a":
		m.uiState.FilterInput.CursorHome()
		return m, nil

	case "end", "ctrl+e":
		m.uiState.FilterInput.CursorEnd()
		return m, nil

	case "backspace":
		m.uiState.FilterInput.Backspace()
		return m, nil

	case "delete", "ctrl+d":
		m.uiState.FilterInput.Delete()
		return m, nil

	case "ctrl+u":
		m.uiState.FilterInput.DeleteToBeginning()
		return m, nil

	case "ctrl+k":
		m.uiState.FilterInput.DeleteToEnd()
		return m, nil

	default:
		// Insert character(s) - handles both single keypress and paste
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.uiState.FilterInput.InsertRune(r)
			}
		}
		return m, nil
	}
}

// parseAndApplyFilter parses a filter string and adds it to the filter chain
// This enables progressive/stacked filtering - each new filter narrows down the results
// Returns a tea.Cmd for showing toast notifications on error
func (m *Model) getConnectedProcessors() []string {
	processors := make([]string, 0, len(m.connectionMgr.Processors))
	for addr := range m.connectionMgr.Processors {
		processors = append(processors, addr)
	}
	return processors
}

// getProcessorInfoList returns ProcessorInfo for all configured processors
func (m *Model) getProcessorInfoList() []components.ProcessorInfo {
	procInfos := make([]components.ProcessorInfo, 0, len(m.connectionMgr.Processors))
	for addr, proc := range m.connectionMgr.Processors {
		// Convert model store.ProcessorState to components.ProcessorConnectionState
		var connState components.ProcessorConnectionState
		switch proc.State {
		case store.ProcessorStateDisconnected:
			connState = components.ProcessorConnectionStateDisconnected
		case store.ProcessorStateConnecting:
			connState = components.ProcessorConnectionStateConnecting
		case store.ProcessorStateConnected:
			connState = components.ProcessorConnectionStateConnected
		case store.ProcessorStateFailed:
			connState = components.ProcessorConnectionStateFailed
		default:
			connState = components.ProcessorConnectionStateDisconnected
		}

		// Filter hunters based on subscription list
		// - nil = never configured, show all hunters (default)
		// - empty slice [] = explicitly subscribed to none, show no hunters
		// - non-empty slice = show only subscribed hunters
		allHunters := m.connectionMgr.HuntersByProcessor[addr]
		var displayHunters []components.HunterInfo

		if proc.SubscribedHunters == nil {
			// Never configured - show all hunters (default behavior)
			displayHunters = allHunters
		} else if len(proc.SubscribedHunters) == 0 {
			// Explicitly subscribed to no hunters - show nothing
			displayHunters = []components.HunterInfo{}
		} else {
			// Filter to show only subscribed hunters
			subscribedSet := make(map[string]bool)
			for _, hunterID := range proc.SubscribedHunters {
				subscribedSet[hunterID] = true
			}

			displayHunters = make([]components.HunterInfo, 0)
			for _, hunter := range allHunters {
				if subscribedSet[hunter.ID] {
					displayHunters = append(displayHunters, hunter)
				}
			}
		}

		procInfos = append(procInfos, components.ProcessorInfo{
			Address:         addr,
			ProcessorID:     proc.ProcessorID,
			Status:          proc.Status,
			ConnectionState: connState,
			Hunters:         displayHunters,
		})
	}
	return procInfos
}

// NodesLoadedMsg is sent when nodes are loaded successfully from YAML
type NodesLoadedMsg struct {
	NodeCount int
	FilePath  string
}

// NodesLoadFailedMsg is sent when loading nodes from YAML fails
type NodesLoadFailedMsg struct {
	Error    error
	FilePath string
}

// loadNodesFile loads processors from a YAML file and adds them for connection
// This is the single consolidated function for loading nodes from YAML
func loadNodesFile(filePath string) tea.Cmd {
	return func() tea.Msg {
		// Load nodes in background
		nodes, err := config.LoadNodesFromYAML(filePath)
		if err != nil {
			return NodesLoadFailedMsg{
				Error:    err,
				FilePath: filePath,
			}
		}

		// Create AddNodeMsg commands for each node
		cmds := make([]tea.Cmd, len(nodes)+1) // +1 for success message
		for i, node := range nodes {
			addr := node.Address
			cmds[i] = func() tea.Msg {
				return components.AddNodeMsg{Address: addr}
			}
		}
		// Add success message
		cmds[len(nodes)] = func() tea.Msg {
			return NodesLoadedMsg{
				NodeCount: len(nodes),
				FilePath:  filePath,
			}
		}

		return tea.Batch(cmds...)()
	}
}

// applyFilters applies the filter chain to all packets
// This is only called when filters change, not on every packet

// saveThemePreference saves the current theme preference to config file
func saveThemePreference(theme themes.Theme) {
	var themeName string
	if theme.Name == "Solarized Light" {
		themeName = "light"
	} else {
		themeName = "dark"
	}

	// Set in viper
	viper.Set("tui.theme", themeName)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it in ~/.config/lippycat/config.yaml
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - theme will still work for this session
				return
			}
		}
	}
}

// startLiveCapture starts packet capture on the specified interface
func startLiveCapture(ctx context.Context, interfaceName string, filter string, program *tea.Program, done chan struct{}) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartLiveSniffer(interfaceName, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program)
	})
}

// startOfflineCapture starts packet capture from a PCAP file
func startOfflineCapture(ctx context.Context, pcapFile string, filter string, program *tea.Program, done chan struct{}) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartOfflineSniffer(pcapFile, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program)
	})
}

// loadFilterHistory loads filter history from config
func loadFilterHistory(filterInput *components.FilterInput) {
	history := viper.GetStringSlice("tui.filter_history")
	if len(history) > 0 {
		filterInput.SetHistory(history)
	}
}

// saveFilterHistory saves filter history to config
func saveFilterHistory(filterInput *components.FilterInput) {
	history := filterInput.GetHistory()
	viper.Set("tui.filter_history", history)

	// Write to config file
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}

			// Use ~/.config/lippycat/config.yaml as primary location
			configDir := filepath.Join(home, ".config", "lippycat")
			if err := os.MkdirAll(configDir, 0750); err != nil {
				return
			}

			configPath := filepath.Join(configDir, "config.yaml")
			viper.SetConfigFile(configPath)

			if err := viper.SafeWriteConfig(); err != nil {
				// Silently ignore errors - history will still work for this session
				return
			}
		}
	}
}

// handleDeleteNode handles deletion/unsubscription of a selected node
func (m *Model) handleDeleteNode() tea.Cmd {
	// Check what's selected in the nodes view
	selectedHunter := m.uiState.NodesView.GetSelectedHunter()
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()

	if selectedProcessorAddr != "" {
		// Processor is selected - fully disconnect and remove
		if proc, exists := m.connectionMgr.Processors[selectedProcessorAddr]; exists {
			// Close client connection
			if proc.Client != nil {
				proc.Client.Close()
			}
			// Remove from connection manager (also removes hunters)
			m.connectionMgr.RemoveProcessor(selectedProcessorAddr)

			// Update NodesView to reflect removal
			procInfos := m.getProcessorInfoList()
			m.uiState.NodesView.SetProcessors(procInfos)

			// Show success toast
			return m.uiState.Toast.Show(
				fmt.Sprintf("Removed %s", selectedProcessorAddr),
				components.ToastSuccess,
				components.ToastDurationShort,
			)
		}
		return nil
	} else if selectedHunter != nil {
		// Hunter is selected - unsubscribe from it
		processorAddr := selectedHunter.ProcessorAddr

		if processorAddr == "" {
			return nil
		}

		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists {
			return nil
		}

		// Get current subscription list (not all available hunters!)
		// - nil = subscribed to all hunters (never configured)
		// - empty [] = subscribed to no hunters
		// - non-empty = subscribed to specific hunters
		var currentSubscription []string
		if proc.SubscribedHunters == nil {
			// Never configured - currently subscribed to all hunters
			// Get list of all hunters and remove the selected one
			allHunters := m.connectionMgr.GetHunters(processorAddr)
			currentSubscription = make([]string, 0, len(allHunters))
			for _, h := range allHunters {
				currentSubscription = append(currentSubscription, h.ID)
			}
		} else {
			// Already configured - use existing subscription list
			currentSubscription = proc.SubscribedHunters
		}

		// Build new list excluding the hunter to remove
		newHunterIDs := make([]string, 0)
		for _, hunterID := range currentSubscription {
			if hunterID != selectedHunter.ID {
				newHunterIDs = append(newHunterIDs, hunterID)
			}
		}

		// Show toast notification
		toastCmd := m.uiState.Toast.Show(
			fmt.Sprintf("Unsubscribed from %s", selectedHunter.ID),
			components.ToastInfo,
			components.ToastDurationShort,
		)

		// Reconnect with new subscription list
		reconnectCmd := m.reconnectWithHunterFilter(processorAddr, newHunterIDs)
		return tea.Batch(toastCmd, reconnectCmd)
	}
	return nil
}

// handleOpenHunterSelector opens the hunter selector modal for the selected processor
func (m *Model) handleOpenHunterSelector() tea.Cmd {
	// Get selected processor from nodes view
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()

	if selectedProcessorAddr == "" {
		// Check if a hunter is selected, and get its processor
		if hunter := m.uiState.NodesView.GetSelectedHunter(); hunter != nil {
			selectedProcessorAddr = hunter.ProcessorAddr
		}
	}

	if selectedProcessorAddr != "" {
		// Open hunter selector and load hunters
		m.uiState.HunterSelector.Activate(selectedProcessorAddr)
		m.uiState.HunterSelector.SetSize(m.uiState.Width, m.uiState.Height)

		// Trigger loading hunters from processor
		return func() tea.Msg {
			return components.LoadHuntersFromProcessorMsg{ProcessorAddr: selectedProcessorAddr}
		}
	}
	return nil
}

// handleOpenFilterManager opens the filter manager modal for the selected node
func (m *Model) handleOpenFilterManager() tea.Cmd {
	// Get selected processor or hunter from nodes view
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()
	selectedHunter := m.uiState.NodesView.GetSelectedHunter()

	if selectedProcessorAddr != "" {
		// Open for processor (affects all hunters)
		m.uiState.FilterManager.Activate(selectedProcessorAddr, selectedProcessorAddr, components.NodeTypeProcessor)
		m.uiState.FilterManager.SetSize(m.uiState.Width, m.uiState.Height)

		// Set available hunters from the processor
		hunters := m.uiState.NodesView.GetHuntersForProcessor(selectedProcessorAddr)
		hunterItems := make([]components.HunterSelectorItem, 0, len(hunters))
		for _, h := range hunters {
			hunterItems = append(hunterItems, components.HunterSelectorItem{
				HunterID:   h.ID,
				Hostname:   h.Hostname,
				Interfaces: h.Interfaces,
				Status:     h.Status,
				RemoteAddr: h.RemoteAddr,
			})
		}
		m.uiState.FilterManager.SetAvailableHunters(hunterItems)

		// Load filters from processor via gRPC
		return m.loadFiltersFromProcessor(selectedProcessorAddr, "")
	} else if selectedHunter != nil {
		// Open for specific hunter
		m.uiState.FilterManager.Activate(selectedHunter.ID, selectedHunter.ProcessorAddr, components.NodeTypeHunter)
		m.uiState.FilterManager.SetSize(m.uiState.Width, m.uiState.Height)

		// Set available hunters from the processor
		hunters := m.uiState.NodesView.GetHuntersForProcessor(selectedHunter.ProcessorAddr)
		hunterItems := make([]components.HunterSelectorItem, 0, len(hunters))
		for _, h := range hunters {
			hunterItems = append(hunterItems, components.HunterSelectorItem{
				HunterID:   h.ID,
				Hostname:   h.Hostname,
				Interfaces: h.Interfaces,
				Status:     h.Status,
				RemoteAddr: h.RemoteAddr,
			})
		}
		m.uiState.FilterManager.SetAvailableHunters(hunterItems)

		// Load filters from processor (filtered by hunter ID) via gRPC
		// Note: selectedHunter.ProcessorAddr contains the processor address
		return m.loadFiltersFromProcessor(selectedHunter.ProcessorAddr, selectedHunter.ID)
	}
	return nil
}

// loadFiltersFromProcessor loads filters from a processor via gRPC
func (m *Model) loadFiltersFromProcessor(processorAddr string, hunterID string) tea.Cmd {
	return func() tea.Msg {
		// Get processor from connection manager
		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists || proc.Client == nil {
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           fmt.Errorf("processor not connected"),
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           fmt.Errorf("invalid client type"),
			}
		}

		// Call GetFilters RPC
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := mgmtClient.GetFilters(ctx, &management.FilterRequest{
			HunterId: hunterID, // Empty string means all filters
		})
		if err != nil {
			logger.Error("Failed to load filters from processor",
				"error", err,
				"processor", processorAddr,
				"hunter_id", hunterID)
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           err,
			}
		}

		return components.FiltersLoadedMsg{
			ProcessorAddr: processorAddr,
			Filters:       resp.Filters,
			Err:           nil,
		}
	}
}

// executeFilterOperation executes a filter create/update/delete operation via gRPC
func (m *Model) executeFilterOperation(msg components.FilterOperationMsg) tea.Cmd {
	return func() tea.Msg {
		// Get processor from connection manager
		proc, exists := m.connectionMgr.Processors[msg.ProcessorAddr]
		if !exists || proc.Client == nil {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         "processor not connected",
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         "invalid client type",
			}
		}

		// Create management client
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var result *management.FilterUpdateResult
		var err error
		var filterPattern string

		switch msg.Operation {
		case "create", "update", "toggle":
			// UpdateFilter handles both create and update
			if msg.Filter == nil {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter is nil",
				}
			}
			filterPattern = msg.Filter.Pattern
			result, err = mgmtClient.UpdateFilter(ctx, msg.Filter)

		case "delete":
			// DeleteFilter
			if msg.FilterID == "" {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter ID is empty",
				}
			}
			filterPattern = msg.FilterID
			result, err = mgmtClient.DeleteFilter(ctx, &management.FilterDeleteRequest{
				FilterId: msg.FilterID,
			})

		default:
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         fmt.Sprintf("unknown operation: %s", msg.Operation),
			}
		}

		if err != nil {
			logger.Error("Filter operation failed",
				"operation", msg.Operation,
				"error", err,
				"processor", msg.ProcessorAddr)
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: filterPattern,
				Error:         err.Error(),
			}
		}

		if !result.Success {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: filterPattern,
				Error:         result.Error,
			}
		}

		return components.FilterOperationResultMsg{
			Success:        true,
			Operation:      msg.Operation,
			FilterPattern:  filterPattern,
			Error:          "",
			HuntersUpdated: result.HuntersUpdated,
		}
	}
}

// handleHunterSelectionConfirmed handles confirmed hunter selection from modal
func (m *Model) handleHunterSelectionConfirmed(msg components.HunterSelectionConfirmedMsg) tea.Cmd {
	// Show toast notification
	var toastMsg string
	if len(msg.SelectedHunterIDs) == 0 {
		toastMsg = "Subscribed to all hunters"
	} else if len(msg.SelectedHunterIDs) == 1 {
		toastMsg = "Subscribed to 1 hunter"
	} else {
		toastMsg = fmt.Sprintf("Subscribed to %d hunters", len(msg.SelectedHunterIDs))
	}
	toastCmd := m.uiState.Toast.Show(
		toastMsg,
		components.ToastSuccess,
		components.ToastDurationShort,
	)

	// Reconnect with new hunter filter
	reconnectCmd := m.reconnectWithHunterFilter(msg.ProcessorAddr, msg.SelectedHunterIDs)
	return tea.Batch(toastCmd, reconnectCmd)
}

// reconnectWithHunterFilter reconnects to a processor with a new hunter subscription filter
func (m *Model) reconnectWithHunterFilter(processorAddr string, hunterIDs []string) tea.Cmd {
	// Close existing connection
	if proc, exists := m.connectionMgr.Processors[processorAddr]; exists {
		if proc.Client != nil {
			proc.Client.Close()
		}
		proc.State = store.ProcessorStateDisconnected
		// Store the subscription list so we can restore it after reconnection
		proc.SubscribedHunters = hunterIDs
	}

	// Reconnect with new hunter filter
	return func() tea.Msg {
		return ProcessorReconnectMsg{
			Address:   processorAddr,
			HunterIDs: hunterIDs,
		}
	}
}

// loadHuntersFromProcessor loads the list of hunters from a processor
func (m *Model) loadHuntersFromProcessor(processorAddr string) tea.Cmd {
	return func() tea.Msg {
		// Get the client for this processor
		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists || proc.Client == nil {
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Call ListAvailableHunters RPC
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := mgmtClient.ListAvailableHunters(ctx, &management.ListHuntersRequest{})
		if err != nil {
			logger.Error("Failed to load hunters from processor",
				"error", err,
				"processor", processorAddr,
				"error_type", fmt.Sprintf("%T", err))
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Convert to HunterSelectorItem and mark currently subscribed hunters as selected
		// Use the stored subscription list, not the connected hunters list
		// - nil = never configured, all hunters selected (default)
		// - empty slice [] = explicitly subscribed to none, no hunters selected
		// - non-empty slice = only those hunters selected
		subscribedIDs := make(map[string]bool)
		if proc.SubscribedHunters == nil {
			// Never configured - pre-select all hunters (default)
			for _, h := range resp.Hunters {
				subscribedIDs[h.HunterId] = true
			}
		} else if len(proc.SubscribedHunters) == 0 {
			// Explicitly subscribed to no hunters - select none
			// subscribedIDs remains empty
		} else {
			// We have a specific subscription list - only these are selected
			for _, hunterID := range proc.SubscribedHunters {
				subscribedIDs[hunterID] = true
			}
		}

		items := make([]components.HunterSelectorItem, len(resp.Hunters))
		for i, h := range resp.Hunters {
			items[i] = components.HunterSelectorItem{
				HunterID:   h.HunterId,
				Hostname:   h.Hostname,
				Interfaces: h.Interfaces,
				Status:     h.Status,
				RemoteAddr: h.RemoteAddr,
				Selected:   subscribedIDs[h.HunterId], // Pre-select currently subscribed hunters
			}
		}

		return components.HuntersLoadedMsg{
			ProcessorAddr: processorAddr,
			Hunters:       items,
		}
	}
}

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
