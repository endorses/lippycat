//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/cmd/tui/themes"
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

	// Performance optimization - throttle details panel updates during high packet rate
	lastDetailsPanelUpdate     time.Time     // Last time details panel was updated
	detailsPanelUpdateInterval time.Duration // Minimum interval between updates (e.g., 50ms = 20 Hz)

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
		packetStore:                packetStore,
		connectionMgr:              connectionMgr,
		uiState:                    uiState,
		statistics:                 uiState.Statistics, // Reference to same statistics
		interfaceName:              initialInterfaceName,
		bpfFilter:                  bpfFilter,
		captureMode:                initialMode,
		nodesFilePath:              nodesFilePath,
		detailsPanelUpdateInterval: 50 * time.Millisecond, // 20 Hz throttle (imperceptible to user)
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
	// Handle toast messages FIRST (even when modals are active)
	// This ensures toast auto-dismiss timer continues working
	var toastCmd tea.Cmd
	if m.uiState.Toast.IsActive() {
		toastCmd = m.uiState.Toast.Update(msg)
	}

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
			// Pass all other messages to settings view, but batch with toast command
			cmd := m.uiState.SettingsView.Update(msg)
			return m, tea.Batch(toastCmd, cmd)
		}
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
		case tea.KeyMsg, tea.MouseMsg, components.ConfirmDialogResult:
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

	// Route messages to appropriate handlers
	switch msg := msg.(type) {
	case tea.MouseMsg:
		return m.handleMouse(msg)
	case tea.KeyMsg:
		return m.handleKeyboard(msg)
	case tea.WindowSizeMsg:
		return m.handleWindowSizeMsg(msg)
	case tea.ResumeMsg:
		return m.handleResumeMsg(msg)
	case TickMsg:
		return m.handleTickMsg(msg)
	case PacketBatchMsg:
		return m.handlePacketBatchMsg(msg)
	case CallUpdateMsg:
		return m.handleCallUpdateMsg(msg)
	case PacketMsg:
		return m.handlePacketMsg(msg)
	case HunterStatusMsg:
		return m.handleHunterStatusMsg(msg)
	case components.UpdateBufferSizeMsg:
		return m.handleUpdateBufferSizeMsg(msg)
	case components.RestartCaptureMsg:
		return m.handleRestartCaptureMsg(msg)
	case components.AddNodeMsg:
		return m.handleAddNodeMsg(msg)
	case components.LoadNodesMsg:
		return m.handleLoadNodesMsg(msg)
	case NodesLoadedMsg:
		return m.handleNodesLoadedMsg(msg)
	case NodesLoadFailedMsg:
		return m.handleNodesLoadFailedMsg(msg)
	case components.ProtocolSelectedMsg:
		return m.handleProtocolSelectedMsg(msg)
	case components.FileSelectedMsg:
		return m.handleFileSelectedMsg(msg)
	case components.ConfirmDialogResult:
		return m.handleConfirmDialogResult(msg)
	case SaveCompleteMsg:
		return m.handleSaveCompleteMsg(msg)
	case components.FilterOperationResultMsg:
		return m.handleFilterOperationResultMsg(msg)
	case ProcessorReconnectMsg:
		return m.handleProcessorReconnectMsg(msg)
	case ProcessorConnectedMsg:
		return m.handleProcessorConnectedMsg(msg)
	case ProcessorDisconnectedMsg:
		return m.handleProcessorDisconnectedMsg(msg)
	case CleanupOldProcessorsMsg:
		return m.handleCleanupOldProcessorsMsg(msg)
	case components.HunterSelectionConfirmedMsg:
		return m.handleHunterSelectionConfirmedMsg(msg)
	case components.LoadHuntersFromProcessorMsg:
		return m.handleLoadHuntersFromProcessorMsg(msg)
	case components.HuntersLoadedMsg:
		return m.handleHuntersLoadedMsg(msg)
	case components.FiltersLoadedMsg:
		return m.handleFiltersLoadedMsg(msg)
	case components.FilterOperationMsg:
		return m.handleFilterOperationMsg(msg)
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
