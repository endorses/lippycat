//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/config"
	"github.com/endorses/lippycat/cmd/tui/filters"
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
func (m *Model) getPacketsInOrder() []components.PacketDisplay {
	return m.packetStore.GetPacketsInOrder()
}

// NewModel creates a new TUI model
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

		// Handle filter input mode
		if m.uiState.FilterMode {
			return m.handleFilterInput(msg)
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
				// For future: add theme cycling logic here
				// Currently only Solarized theme available
				m.uiState.Theme = themes.Solarized()
				// Update all components with new theme
				m.uiState.PacketList.SetTheme(m.uiState.Theme)
				m.uiState.DetailsPanel.SetTheme(m.uiState.Theme)
				m.uiState.HexDumpView.SetTheme(m.uiState.Theme)
				m.uiState.Header.SetTheme(m.uiState.Theme)
				m.uiState.Footer.SetTheme(m.uiState.Theme)
				m.uiState.Tabs.SetTheme(m.uiState.Theme)
				m.uiState.StatisticsView.SetTheme(m.uiState.Theme)
				m.uiState.SettingsView.SetTheme(m.uiState.Theme)
				m.uiState.FilterInput.SetTheme(m.uiState.Theme)
				saveThemePreference(m.uiState.Theme)
				return m, nil
			case "tab", "shift+tab", "alt+1", "alt+2", "alt+3", "alt+4", "n":
				// Let these fall through to normal tab switching and global key handling
			default:
				// Forward everything else to settings view
				cmd := m.uiState.SettingsView.Update(msg)
				// Update interface name in header when it changes (for display only)
				// Actual capture interface doesn't change until restart
				return m, cmd
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

		case "/": // Enter filter mode
			m.uiState.FilterMode = true
			m.uiState.FilterInput.Activate()
			m.uiState.FilterInput.Clear()
			return m, nil

		case "c": // Clear filters
			if m.packetStore.HasFilter() {
				m.packetStore.ClearFilter()
				m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
				m.packetStore.MatchedPackets = m.packetStore.PacketsCount
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())

				// Show toast notification
				return m, m.uiState.Toast.Show(
					"Filter cleared",
					components.ToastInfo,
					components.ToastDurationShort,
				)
			}
			return m, nil

		case "x": // Clear/flush packets
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

		case " ": // Space to pause/resume
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

		case "d":
			// Context-sensitive: toggle details on Capture tab, delete node on Nodes tab
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				return m, m.handleDeleteNode()
			} else { // Other tabs: toggle details panel
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

		case "p": // Open protocol selector
			m.uiState.ProtocolSelector.Activate()
			m.uiState.ProtocolSelector.SetSize(m.uiState.Width, m.uiState.Height)
			return m, nil

		case "v": // Toggle view mode
			// On capture tab: toggle between packets and calls for VoIP
			if m.uiState.Tabs.GetActive() == 0 {
				if m.uiState.SelectedProtocol.Name == "VoIP (SIP/RTP)" {
					if m.uiState.ViewMode == "packets" {
						m.uiState.ViewMode = "calls"
					} else {
						m.uiState.ViewMode = "packets"
					}
				}
			} else if m.uiState.Tabs.GetActive() == 1 {
				// On nodes tab: toggle between table and graph view
				m.uiState.NodesView.ToggleView()
			}
			return m, nil

		case "w": // Save packets to file (or stop streaming save)
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
				// Open file dialog to start new save
				cmd := m.uiState.FileDialog.Activate()
				return m, cmd
			}
			return m, nil

		case "T": // TEST: Show test toast notification (cycles through types)
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

		case "h", "left": // Focus left pane (packet list)
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Use spatial navigation in graph mode
				if m.uiState.NodesView.GetViewMode() == "graph" {
					m.uiState.NodesView.SelectLeft()
					return m, nil
				}
			}
			m.uiState.FocusedPane = "left"
			return m, nil

		case "l", "right": // Focus right pane (details/hex)
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Use spatial navigation in graph mode
				if m.uiState.NodesView.GetViewMode() == "graph" {
					m.uiState.NodesView.SelectRight()
					return m, nil
				}
			}
			if m.uiState.ShowDetails {
				m.uiState.FocusedPane = "right"
			}
			return m, nil

		case "tab": // Switch tabs
			m.uiState.Tabs.Next()
			return m, nil

		case "shift+tab": // Switch tabs backward
			m.uiState.Tabs.Previous()
			return m, nil

		case "alt+1": // Switch to Capture tab
			m.uiState.Tabs.SetActive(0)
			return m, nil

		case "alt+2": // Switch to Nodes tab
			m.uiState.Tabs.SetActive(1)
			return m, nil

		case "alt+3": // Switch to Statistics tab
			m.uiState.Tabs.SetActive(2)
			return m, nil

		case "alt+4": // Switch to Settings tab
			m.uiState.Tabs.SetActive(3)
			return m, nil

		case "n": // Add node (open modal)
			m.uiState.NodesView.ShowAddNodeModal()
			return m, nil

		case "s": // Subscribe to hunters (on nodes tab)
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				return m, m.handleOpenHunterSelector()
			}
			return m, nil

		case "f": // Manage filters (on nodes tab)
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				return m, m.handleOpenFilterManager()
			}
			return m, nil

		case "t": // Toggle theme
			// For future: add theme cycling logic here
			// Currently only Solarized theme available
			m.uiState.Theme = themes.Solarized()
			// Update all components with new theme
			m.uiState.PacketList.SetTheme(m.uiState.Theme)
			m.uiState.DetailsPanel.SetTheme(m.uiState.Theme)
			m.uiState.HexDumpView.SetTheme(m.uiState.Theme)
			m.uiState.Header.SetTheme(m.uiState.Theme)
			m.uiState.Footer.SetTheme(m.uiState.Theme)
			m.uiState.Tabs.SetTheme(m.uiState.Theme)
			m.uiState.StatisticsView.SetTheme(m.uiState.Theme)
			m.uiState.SettingsView.SetTheme(m.uiState.Theme)
			m.uiState.CallsView.SetTheme(m.uiState.Theme)
			m.uiState.ProtocolSelector.SetTheme(m.uiState.Theme)
			m.uiState.HunterSelector.SetTheme(m.uiState.Theme)
			m.uiState.FilterManager.SetTheme(m.uiState.Theme)
			m.uiState.FilterInput.SetTheme(m.uiState.Theme)
			// Save theme preference
			saveThemePreference(m.uiState.Theme)
			return m, nil

		case "g": // Vim-style navigation: gg to go to top
			now := time.Now()
			// Check if this is the second 'g' within 500ms
			if m.uiState.LastKeyPress == "g" && now.Sub(m.uiState.LastKeyPressTime) < 500*time.Millisecond {
				// This is 'gg' - jump to top
				if m.uiState.Tabs.GetActive() == 0 { // Capture tab
					if m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
						// Jump to top of details panel
						cmd := m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyHome})
						return m, cmd
					} else {
						// Jump to top of packet list
						m.uiState.PacketList.GotoTop()
						m.updateDetailsPanel()
						return m, nil
					}
				} else if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
					cmd := m.uiState.StatisticsView.Update(tea.KeyMsg{Type: tea.KeyHome})
					return m, cmd
				}
				// Clear the last key press after handling gg
				m.uiState.LastKeyPress = ""
				return m, nil
			}
			// First 'g' - just record it
			m.uiState.LastKeyPress = "g"
			m.uiState.LastKeyPressTime = now
			return m, nil

		case "G": // Vim-style navigation: G to go to bottom (shift+g)
			if m.uiState.Tabs.GetActive() == 0 { // Capture tab
				if m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
					// Jump to bottom of details panel
					cmd := m.uiState.DetailsPanel.Update(tea.KeyMsg{Type: tea.KeyEnd})
					return m, cmd
				} else {
					// Jump to bottom of packet list
					m.uiState.PacketList.GotoBottom()
					m.updateDetailsPanel()
					return m, nil
				}
			} else if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(tea.KeyMsg{Type: tea.KeyEnd})
				return m, cmd
			}
			return m, nil

		case "shift+up":
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Manual viewport scrolling
				cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyUp})
				return m, cmd
			}
			// Fall through to other tabs

		case "shift+down":
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Manual viewport scrolling
				cmd := m.uiState.NodesView.Update(tea.KeyMsg{Type: tea.KeyDown})
				return m, cmd
			}
			// Fall through to other tabs

		case "up", "k":
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Use spatial navigation for graph mode, tree navigation for table mode
				if m.uiState.NodesView.GetViewMode() == "graph" {
					m.uiState.NodesView.SelectUp()
				} else {
					m.uiState.NodesView.SelectPrevious()
				}
				return m, nil
			}
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.CursorUp()
			m.updateDetailsPanel()
			return m, nil

		case "down", "j":
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// Use spatial navigation for graph mode, tree navigation for table mode
				if m.uiState.NodesView.GetViewMode() == "graph" {
					m.uiState.NodesView.SelectDown()
				} else {
					m.uiState.NodesView.SelectNext()
				}
				return m, nil
			}
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.CursorDown()
			m.updateDetailsPanel()
			return m, nil

		case "home":
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.GotoTop()
			m.updateDetailsPanel()
			return m, nil

		case "end":
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.GotoBottom()
			m.updateDetailsPanel()
			return m, nil

		case "pgup":
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.PageUp()
			m.updateDetailsPanel()
			return m, nil

		case "pgdown":
			if m.uiState.Tabs.GetActive() == 2 { // Statistics tab
				cmd := m.uiState.StatisticsView.Update(msg)
				return m, cmd
			}
			if m.uiState.Tabs.GetActive() == 0 && m.uiState.FocusedPane == "right" && m.uiState.ShowDetails {
				// Scroll details panel
				cmd := m.uiState.DetailsPanel.Update(msg)
				return m, cmd
			}
			m.uiState.PacketList.PageDown()
			m.updateDetailsPanel()
			return m, nil
		}

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
		// Handle batch of packets more efficiently
		if !m.uiState.Paused {
			for _, packet := range msg.Packets {
				// Set NodeID to "Local" if not already set (for local/offline capture)
				if packet.NodeID == "" {
					packet.NodeID = "Local"
				}

				// Only process packets that match current capture mode
				// Live/Offline mode: only accept local packets
				// Remote mode: only accept remote packets
				if m.captureMode == components.CaptureModeRemote {
					// In remote mode, skip local packets
					if packet.NodeID == "Local" {
						continue
					}
				} else {
					// In live/offline mode, skip remote packets
					if packet.NodeID != "Local" {
						continue
					}
				}

				// Add packet using PacketStore method
				m.packetStore.AddPacket(packet)

				// Update statistics (lightweight)
				m.updateStatistics(packet)
			}

			// Update packet list immediately for smooth streaming
			if !m.packetStore.HasFilter() {
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			} else {
				m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
			}

			// Update details panel if showing details
			if m.uiState.ShowDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case PacketMsg:
		if !m.uiState.Paused {
			// Set NodeID to "Local" if not already set (for local/offline capture)
			packet := msg.Packet
			if packet.NodeID == "" {
				packet.NodeID = "Local"
			}

			// Only process packets that match current capture mode
			// Live/Offline mode: only accept local packets
			// Remote mode: only accept remote packets
			if m.captureMode == components.CaptureModeRemote {
				// In remote mode, skip local packets
				if packet.NodeID == "Local" {
					return m, nil
				}
			} else {
				// In live/offline mode, skip remote packets
				if packet.NodeID != "Local" {
					return m, nil
				}
			}

			// Add packet using PacketStore method
			m.packetStore.AddPacket(packet)

			// Write to streaming save if active
			if m.activeWriter != nil {
				// WritePacket will apply filter internally if configured (best-effort)
				_ = m.activeWriter.WritePacket(packet)
			}

			// Update statistics (lightweight)
			m.updateStatistics(packet)

			// Update packet list immediately for smooth streaming
			if !m.packetStore.HasFilter() {
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			} else {
				m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
			}

			// Update details panel if showing details
			if m.uiState.ShowDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case HunterStatusMsg:
		// Handle hunter status from remote capture client
		// Determine processor address from hunters or from the message source
		var processorAddr string
		if len(msg.Hunters) > 0 {
			// Extract processor address from first hunter (all hunters in msg have same processor)
			processorAddr = msg.Hunters[0].ProcessorAddr
		} else {
			// Empty hunter list - need to determine processor from remoteClients
			// For now, we'll skip updating if we can't determine the processor
			// This is a limitation but prevents incorrect state
			// TODO: Add ProcessorAddr to HunterStatusMsg to handle empty hunter lists
			return m, nil
		}

		// Update processor ID and status if provided
		if msg.ProcessorID != "" && processorAddr != "" && processorAddr != "Direct" {
			if proc, exists := m.connectionMgr.Processors[processorAddr]; exists {
				proc.ProcessorID = msg.ProcessorID
				proc.Status = msg.ProcessorStatus
			}
		}

		// Update hunters for this processor
		m.connectionMgr.HuntersByProcessor[processorAddr] = msg.Hunters

		// Update NodesView with processor info (includes processor IDs and status)
		m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
		return m, nil

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
		// Attempt to connect/reconnect to a processor
		proc, exists := m.connectionMgr.Processors[msg.Address]
		if !exists {
			return m, nil
		}

		// Don't reconnect if already connecting or connected
		if proc.State == store.ProcessorStateConnecting || proc.State == store.ProcessorStateConnected {
			return m, nil
		}

		// Update state to connecting
		proc.State = store.ProcessorStateConnecting
		proc.LastAttempt = time.Now()

		// Show connecting toast (distinguish reconnection from initial connection)
		var toastMsg string
		if proc.FailureCount > 0 {
			toastMsg = fmt.Sprintf("Reconnecting to %s...", msg.Address)
		} else {
			toastMsg = fmt.Sprintf("Connecting to %s...", msg.Address)
		}
		toastCmd := m.uiState.Toast.Show(
			toastMsg,
			components.ToastInfo,
			components.ToastDurationShort,
		)

		// Attempt connection in background
		go func() {
			// Create TUI event handler adapter
			handler := NewTUIEventHandler(currentProgram)

			// Build client config with TLS settings from viper
			clientConfig := &remotecapture.ClientConfig{
				Address:               msg.Address,
				TLSEnabled:            viper.GetBool("tui.tls.enabled"),
				TLSCAFile:             viper.GetString("tui.tls.ca_file"),
				TLSCertFile:           viper.GetString("tui.tls.cert_file"),
				TLSKeyFile:            viper.GetString("tui.tls.key_file"),
				TLSSkipVerify:         viper.GetBool("tui.tls.skip_verify"),
				TLSServerNameOverride: viper.GetString("tui.tls.server_name_override"),
			}

			client, err := remotecapture.NewClientWithConfig(clientConfig, handler)
			if err != nil {
				// Connection failed
				logger.Error("Failed to connect to processor", "address", msg.Address, "error", err)
				currentProgram.Send(ProcessorDisconnectedMsg{
					Address: msg.Address,
					Error:   err,
				})
				return
			}

			// Start packet stream with hunter filter (if specified)
			if err := client.StreamPacketsWithFilter(msg.HunterIDs); err != nil {
				client.Close()
				currentProgram.Send(ProcessorDisconnectedMsg{
					Address: msg.Address,
					Error:   err,
				})
				return
			}

			// Start hunter status subscription
			if err := client.SubscribeHunterStatus(); err != nil {
				// Non-fatal - continue anyway
			}

			// Connection successful
			currentProgram.Send(ProcessorConnectedMsg{
				Address: msg.Address,
				Client:  client,
			})
		}()

		return m, toastCmd

	case ProcessorConnectedMsg:
		// Processor connection established successfully
		if proc, exists := m.connectionMgr.Processors[msg.Address]; exists {
			proc.State = store.ProcessorStateConnected
			proc.Client = msg.Client
			proc.FailureCount = 0
			// Also store in deprecated map for compatibility
			m.connectionMgr.RemoteClients[msg.Address] = msg.Client

			// Update NodesView to reflect connection state change
			procInfos := m.getProcessorInfoList()
			m.uiState.NodesView.SetProcessors(procInfos)

			// If in remote mode, mark capturing as active when we have at least one connected processor
			if m.captureMode == components.CaptureModeRemote {
				m.uiState.SetCapturing(true)
			}

			// Show success toast
			return m, m.uiState.Toast.Show(
				fmt.Sprintf("Connected to %s", msg.Address),
				components.ToastSuccess,
				components.ToastDurationShort,
			)
		}
		return m, nil

	case ProcessorDisconnectedMsg:
		// Processor connection lost or failed
		if proc, exists := m.connectionMgr.Processors[msg.Address]; exists {
			proc.State = store.ProcessorStateFailed
			proc.FailureCount++
			proc.LastDisconnectedAt = time.Now() // Track when disconnected for cleanup

			// Clean up old client
			if proc.Client != nil {
				proc.Client.Close()
				proc.Client = nil
			}
			delete(m.connectionMgr.RemoteClients, msg.Address)

			// Update NodesView to reflect disconnection
			procInfos := m.getProcessorInfoList()
			m.uiState.NodesView.SetProcessors(procInfos)

			// If in remote mode, check if all processors are now disconnected
			var allDisconnectedToast tea.Cmd
			if m.captureMode == components.CaptureModeRemote {
				allDisconnected := true
				for _, p := range m.connectionMgr.Processors {
					if p.State == store.ProcessorStateConnected {
						allDisconnected = false
						break
					}
				}
				// If all processors are disconnected, mark capturing as inactive
				if allDisconnected {
					m.uiState.SetCapturing(false)
					// Show warning toast for all processors disconnected
					allDisconnectedToast = m.uiState.Toast.Show(
						"All processors disconnected",
						components.ToastWarning,
						components.ToastDurationNormal,
					)
				}
			}

			// Show error toast
			toastCmd := m.uiState.Toast.Show(
				fmt.Sprintf("Disconnected from %s", msg.Address),
				components.ToastError,
				components.ToastDurationNormal,
			)

			// Schedule reconnection with exponential backoff
			backoff := time.Duration(1<<uint(min(proc.FailureCount-1, 6))) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}

			reconnectCmd := tea.Tick(backoff, func(t time.Time) tea.Msg {
				return ProcessorReconnectMsg{Address: msg.Address}
			})

			// Batch commands (including allDisconnectedToast if set)
			if allDisconnectedToast != nil {
				return m, tea.Batch(toastCmd, allDisconnectedToast, reconnectCmd)
			}
			return m, tea.Batch(toastCmd, reconnectCmd)
		}
		return m, nil

	case CleanupOldProcessorsMsg:
		// Clean up disconnected processors that have been offline for > 30 minutes
		const cleanupTimeout = 30 * time.Minute
		now := time.Now()

		for addr, proc := range m.connectionMgr.Processors {
			// Only clean up processors that are:
			// 1. In failed/disconnected state
			// 2. Have been disconnected for > 30 minutes
			// 3. Have a non-zero LastDisconnectedAt time
			if (proc.State == store.ProcessorStateFailed || proc.State == store.ProcessorStateDisconnected) &&
				!proc.LastDisconnectedAt.IsZero() &&
				now.Sub(proc.LastDisconnectedAt) > cleanupTimeout {

				// Clean up any remaining client
				if proc.Client != nil {
					proc.Client.Close()
				}

				// Remove from maps
				delete(m.connectionMgr.Processors, addr)
				delete(m.connectionMgr.RemoteClients, addr)
				delete(m.connectionMgr.HuntersByProcessor, addr)
			}
		}

		// Schedule next cleanup
		return m, cleanupProcessorsCmd()

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
					}
				}
			}
		}
		return m, nil
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
func (m *Model) updateStatistics(pkt components.PacketDisplay) {
	// Update protocol counts (bounded - evicts lowest count when full)
	m.statistics.ProtocolCounts.Increment(pkt.Protocol)

	// Update source counts (bounded - evicts lowest count when full)
	m.statistics.SourceCounts.Increment(pkt.SrcIP)

	// Update destination counts (bounded - evicts lowest count when full)
	m.statistics.DestCounts.Increment(pkt.DstIP)

	// Update total bytes and packets
	m.statistics.TotalBytes += int64(pkt.Length)
	m.statistics.TotalPackets++

	// Update min/max packet size
	if pkt.Length < m.statistics.MinPacketSize {
		m.statistics.MinPacketSize = pkt.Length
	}
	if pkt.Length > m.statistics.MaxPacketSize {
		m.statistics.MaxPacketSize = pkt.Length
	}

	// Update statistics view with new data
	m.uiState.StatisticsView.SetStatistics(m.statistics)
}

// updateDetailsPanel updates the details panel with the currently selected packet
func (m *Model) updateDetailsPanel() {
	// Use the packet list that's already loaded in the PacketList component
	// This ensures we're working with the exact same list that's displayed
	packets := m.uiState.PacketList.GetPackets()

	if len(packets) == 0 {
		m.uiState.DetailsPanel.SetPacket(nil)
		return
	}

	selectedIdx := m.uiState.PacketList.GetCursor()
	if selectedIdx >= 0 && selectedIdx < len(packets) {
		pkt := packets[selectedIdx]
		m.uiState.DetailsPanel.SetPacket(&pkt)
	} else {
		m.uiState.DetailsPanel.SetPacket(nil)
	}
}

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

// parseAndApplyFilter parses a filter string and applies it
// Returns a tea.Cmd for showing toast notifications on error
func (m *Model) parseAndApplyFilter(filterStr string) tea.Cmd {
	// Clear existing filters
	m.packetStore.ClearFilter()

	if filterStr == "" {
		return nil
	}

	// Try to parse as boolean expression first
	filter, err := filters.ParseBooleanExpression(filterStr, m.parseSimpleFilter)
	if err == nil && filter != nil {
		m.packetStore.AddFilter(filter)
	} else if err != nil {
		// Show error toast for invalid filter
		toastCmd := m.uiState.Toast.Show(
			fmt.Sprintf("Invalid filter: %s", err.Error()),
			components.ToastError,
			components.ToastDurationLong,
		)

		// Reapply filters to all packets (will show unfiltered since we cleared)
		m.applyFilters()

		// Update display
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())

		return toastCmd
	}

	// Reapply filters to all packets
	m.applyFilters()

	// Update display
	if !m.packetStore.HasFilter() {
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	} else {
		m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
	}

	return nil
}

// parseSimpleFilter parses a simple (non-boolean) filter expression
func (m *Model) parseSimpleFilter(filterStr string) filters.Filter {
	filterStr = strings.TrimSpace(filterStr)

	// Detect filter type based on syntax
	if strings.Contains(filterStr, "sip.") {
		// VoIP filter: sip.user:alice, sip.from:555*, etc.
		parts := strings.SplitN(filterStr, ":", 2)
		if len(parts) == 2 {
			field := strings.TrimPrefix(parts[0], "sip.")
			value := parts[1]
			return filters.NewVoIPFilter(field, value)
		}
	} else if isBPFExpression(filterStr) {
		// BPF filter: port 5060, host 192.168.1.1, tcp, udp, etc.
		filter, err := filters.NewBPFFilter(filterStr)
		if err == nil {
			return filter
		}
		// Fall back to text filter if BPF parse fails
	}

	// Simple text filter for anything else
	return filters.NewTextFilter(filterStr, []string{"all"})
}

// isBPFExpression checks if a string looks like a BPF expression
func isBPFExpression(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))

	// Protocol keywords
	if s == "tcp" || s == "udp" || s == "icmp" || s == "ip" {
		return true
	}

	// BPF keywords
	bpfKeywords := []string{"port", "host", "net", "src", "dst", "and", "or", "not"}
	for _, keyword := range bpfKeywords {
		if strings.Contains(s, keyword+" ") || strings.HasPrefix(s, keyword+" ") {
			return true
		}
	}

	return false
}

// getConnectedProcessors returns a list of all configured processor addresses
// This includes both connected and disconnected processors
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
func (m *Model) applyFilters() {
	if !m.packetStore.HasFilter() {
		m.packetStore.MatchedPackets = m.packetStore.PacketsCount
		m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
		return
	}

	orderedPackets := m.getPacketsInOrder()
	m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0, len(orderedPackets))
	for _, pkt := range orderedPackets {
		if m.packetStore.MatchFilter(pkt) {
			m.packetStore.FilteredPackets = append(m.packetStore.FilteredPackets, pkt)
		}
	}
	m.packetStore.MatchedPackets = len(m.packetStore.FilteredPackets)
}

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
func (m *Model) determineSaveMode() string {
	if m.captureMode == components.CaptureModeOffline {
		return "oneshot"
	}
	if m.uiState.IsPaused() {
		return "oneshot"
	}
	return "streaming"
}

// proceedWithSave starts the save operation for the given file path
func (m *Model) proceedWithSave(filePath string) tea.Cmd {
	// Determine save mode and start save
	mode := m.determineSaveMode()

	if mode == "oneshot" {
		// One-shot save (offline or paused)
		m.uiState.SaveInProgress = true
		// Show info toast
		toastCmd := m.uiState.Toast.Show(
			"Saving packets...",
			components.ToastInfo,
			0, // Will be replaced when complete
		)
		// Start save
		saveCmd := m.startOneShotSave(filePath)
		return tea.Batch(toastCmd, saveCmd)
	} else {
		// Streaming save (live/remote)
		return m.startStreamingSave(filePath)
	}
}

// getPacketsToSave returns packets to save based on filter state
func (m *Model) getPacketsToSave() []components.PacketDisplay {
	if m.packetStore.HasFilter() {
		return m.packetStore.GetFilteredPackets()
	}
	return m.packetStore.GetPacketsInOrder()
}

// getFilterFunction returns a filter function for the streaming writer
func (m *Model) getFilterFunction() func(components.PacketDisplay) bool {
	if !m.packetStore.HasFilter() {
		return nil // No filter, save everything
	}

	// Return filter function that checks if packet matches
	filterChain := m.packetStore.FilterChain
	return func(pkt components.PacketDisplay) bool {
		if filterChain == nil {
			return true
		}
		return filterChain.Match(pkt)
	}
}

// startOneShotSave starts a one-shot save operation (offline/paused mode)
func (m *Model) startOneShotSave(filePath string) tea.Cmd {
	return func() tea.Msg {
		// Get packets to save
		packets := m.getPacketsToSave()

		if len(packets) == 0 {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("no packets to save"),
			}
		}

		// Get link type from first packet (default to Ethernet if not set)
		linkType := layers.LinkTypeEthernet
		if packets[0].LinkType != 0 {
			linkType = packets[0].LinkType
		}

		// Create one-shot writer
		writer, err := pcap.NewOneShotWriter(pcap.Config{
			FilePath: filePath,
			LinkType: linkType,
			Snaplen:  65536,
		})
		if err != nil {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to create writer: %w", err),
			}
		}

		// Write all packets
		for _, pkt := range packets {
			if err := writer.WritePacket(pkt); err != nil {
				_ = writer.Close() // Best-effort cleanup on error path
				return SaveCompleteMsg{
					Success: false,
					Path:    filePath,
					Error:   fmt.Errorf("failed to write packet: %w", err),
				}
			}
		}

		// Close and get final count
		if err := writer.Close(); err != nil {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to close file: %w", err),
			}
		}

		return SaveCompleteMsg{
			Success:      true,
			Path:         filePath,
			PacketsSaved: writer.PacketCount(),
			Streaming:    false,
		}
	}
}

// startStreamingSave starts a streaming save operation (live/remote mode)
func (m *Model) startStreamingSave(filePath string) tea.Cmd {
	// Get filter function
	filterFunc := m.getFilterFunction()

	// Get link type from existing packets (default to Ethernet if not set)
	linkType := layers.LinkTypeEthernet
	packets := m.getPacketsToSave()
	if len(packets) > 0 && packets[0].LinkType != 0 {
		linkType = packets[0].LinkType
	}

	// Create streaming writer
	writer, err := pcap.NewStreamingWriter(pcap.Config{
		FilePath:     filePath,
		LinkType:     linkType,
		Snaplen:      65536,
		SyncInterval: 5 * time.Second,
	}, filterFunc)

	if err != nil {
		// Return error immediately
		return func() tea.Msg {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to create streaming writer: %w", err),
			}
		}
	}

	// Store writer in model
	m.activeWriter = writer
	m.savePath = filePath
	m.uiState.StreamingSave = true
	m.uiState.Footer.SetStreamingSave(true) // Update footer hint

	// Write existing packets immediately (reuse packets from link type check)
	for _, pkt := range packets {
		_ = writer.WritePacket(pkt) // Best-effort write, errors handled on subsequent writes
	}

	// Show toast notification
	return m.uiState.Toast.Show(
		fmt.Sprintf("Recording to %s...", filepath.Base(filePath)),
		components.ToastInfo,
		components.ToastDurationNormal, // Show for 3 seconds to notify user streaming has started
	)
}

// stopStreamingSave stops the active streaming save
func (m *Model) stopStreamingSave() tea.Cmd {
	if m.activeWriter == nil {
		return nil
	}

	writer := m.activeWriter
	path := m.savePath

	// Close writer in goroutine
	return func() tea.Msg {
		count := writer.PacketCount()
		err := writer.Close()

		if err != nil {
			return SaveCompleteMsg{
				Success:   false,
				Path:      path,
				Error:     fmt.Errorf("failed to close file: %w", err),
				Streaming: true,
			}
		}

		return SaveCompleteMsg{
			Success:      true,
			Path:         path,
			PacketsSaved: count,
			Streaming:    true,
		}
	}
}
