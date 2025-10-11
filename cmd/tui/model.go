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
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
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

	switch msg := msg.(type) {
	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tea.KeyMsg:
		// Handle protocol selector mode
		if m.uiState.ProtocolSelector.IsActive() {
			cmd := m.uiState.ProtocolSelector.Update(msg)
			return m, cmd
		}

		// Handle hunter selector modal
		if m.uiState.HunterSelector.IsActive() {
			cmd := m.uiState.HunterSelector.Update(msg)
			return m, cmd
		}

		// Handle add node modal (highest priority after protocol selector)
		if m.uiState.NodesView.IsModalOpen() {
			cmd := m.uiState.NodesView.Update(msg)
			return m, cmd
		}

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
				// Resume ticking when unpausing
				if !m.uiState.Paused {
					return m, tickCmd()
				}
				return m, nil
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
			}
			return m, nil

		case "x": // Clear/flush packets
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
			return m, nil

		case " ": // Space to pause/resume
			m.uiState.Paused = !m.uiState.Paused
			// Resume ticking when unpausing
			if !m.uiState.Paused {
				return m, tickCmd()
			}
			return m, nil

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

		case "h", "left": // Focus left pane (packet list)
			m.uiState.FocusedPane = "left"
			return m, nil

		case "l", "right": // Focus right pane (details/hex)
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

		case "up", "k":
			if m.uiState.Tabs.GetActive() == 1 { // Nodes tab
				// NodesView handles selection with SelectPrevious
				m.uiState.NodesView.SelectPrevious()
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
				// NodesView handles selection with SelectNext
				m.uiState.NodesView.SelectNext()
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

		// Calculate available space for main content
		headerHeight := 2 // header (2 lines: text + border)
		tabsHeight := 4   // tabs (4 lines: top border + content + bottom corners + bottom line)
		bottomHeight := 4 // Reserve 4 lines at bottom (footer + space for filter overlay)

		contentHeight := msg.Height - headerHeight - tabsHeight - bottomHeight

		// Set nodes view size
		m.uiState.NodesView.SetSize(msg.Width, contentHeight)

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

		// Update settings based on mode
		switch msg.Mode {
		case components.CaptureModeLive:
			m.interfaceName = msg.Interface
			m.uiState.Tabs.UpdateTab(0, "Live Capture", "📡")
		case components.CaptureModeOffline:
			m.interfaceName = msg.PCAPFile
			m.uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
		case components.CaptureModeRemote:
			m.interfaceName = msg.NodesFile
			m.uiState.Tabs.UpdateTab(0, "Remote Capture", "🌐")
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
					return m, loadNodesFile(msg.NodesFile)
				}
				// If no nodes file, remote mode is active but no nodes connected yet
				// User can add nodes via Nodes tab
				// Capturing will be marked active when nodes connect successfully
			}
		}

		return m, nil

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
			}
			// Trigger connection attempt
			return m, func() tea.Msg {
				return ProcessorReconnectMsg{Address: msg.Address}
			}
		}
		return m, nil

	case components.LoadNodesMsg:
		// Load nodes from YAML file and connect to them
		if msg.FilePath != "" {
			return m, loadNodesFile(msg.FilePath)
		}
		return m, nil

	case components.ProtocolSelectedMsg:
		// User selected a protocol from the protocol selector
		m.uiState.SelectedProtocol = msg.Protocol

		// Apply BPF filter if protocol has one
		if msg.Protocol.BPFFilter != "" {
			m.parseAndApplyFilter(msg.Protocol.BPFFilter)
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

		return m, nil

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
				}
			}

			// Schedule reconnection with exponential backoff
			backoff := time.Duration(1<<uint(min(proc.FailureCount-1, 6))) * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}

			return m, tea.Tick(backoff, func(t time.Time) tea.Msg {
				return ProcessorReconnectMsg{Address: msg.Address}
			})
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

	// Create the bottom area - always 4 lines total
	var bottomArea string
	if m.uiState.FilterMode {
		// Filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.uiState.FilterInput.View()
		bottomArea = filterView + "\n" + footerView
	} else {
		// 3 blank lines + footer (1 line) = 4 lines
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
		if filterValue != "" {
			m.parseAndApplyFilter(filterValue)
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
		return m, nil

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
func (m *Model) parseAndApplyFilter(filterStr string) {
	// Clear existing filters
	m.packetStore.ClearFilter()

	if filterStr == "" {
		return
	}

	// Try to parse as boolean expression first
	filter, err := filters.ParseBooleanExpression(filterStr, m.parseSimpleFilter)
	if err == nil && filter != nil {
		m.packetStore.AddFilter(filter)
	}

	// Reapply filters to all packets
	m.applyFilters()

	// Update display
	if !m.packetStore.HasFilter() {
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	} else {
		m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
	}
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

// loadNodesFile loads processors from a YAML file and adds them for connection
// This is the single consolidated function for loading nodes from YAML
func loadNodesFile(filePath string) tea.Cmd {
	return func() tea.Msg {
		// Load nodes in background
		nodes, err := config.LoadNodesFromYAML(filePath)
		if err != nil {
			// TODO: Show error in UI
			return nil
		}

		// Return a batch of AddNodeMsg for each node
		cmds := make([]tea.Cmd, len(nodes))
		for i, node := range nodes {
			addr := node.Address
			cmds[i] = func() tea.Msg {
				return components.AddNodeMsg{Address: addr}
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
			if err := os.MkdirAll(configDir, 0755); err != nil {
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
			if err := os.MkdirAll(configDir, 0755); err != nil {
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

		// Reconnect with new subscription list
		return m.reconnectWithHunterFilter(processorAddr, newHunterIDs)
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

// handleHunterSelectionConfirmed handles confirmed hunter selection from modal
func (m *Model) handleHunterSelectionConfirmed(msg components.HunterSelectionConfirmedMsg) tea.Cmd {
	// Reconnect with new hunter filter
	return m.reconnectWithHunterFilter(msg.ProcessorAddr, msg.SelectedHunterIDs)
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
