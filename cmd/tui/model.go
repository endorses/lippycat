package tui

import (
	"context"
	// "fmt" // Only needed for debug logging - uncomment if enabling DEBUG logs
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/config"
	"github.com/endorses/lippycat/cmd/tui/filters"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/spf13/viper"
)

// Global state for capture management (shared with tui.go)
var (
	currentCaptureCancel context.CancelFunc
	currentProgram       *tea.Program
)

// PacketMsg is sent when a new packet is captured
type PacketMsg struct {
	Packet components.PacketDisplay
}

// PacketBatchMsg is sent when multiple packets are captured
type PacketBatchMsg struct {
	Packets []components.PacketDisplay
}

// HunterStatusMsg is sent with hunter status updates from remote processor
type HunterStatusMsg struct {
	Hunters []components.HunterInfo
}

// ProcessorConnectedMsg is sent when a processor connection succeeds
type ProcessorConnectedMsg struct {
	Address string
	Client  interface{ Close() }
}

// ProcessorDisconnectedMsg is sent when a processor connection is lost
type ProcessorDisconnectedMsg struct {
	Address string
	Error   error
}

// ProcessorReconnectMsg is sent to trigger a reconnection attempt
type ProcessorReconnectMsg struct {
	Address string
}

// TickMsg is sent periodically to trigger UI updates
type TickMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg{}
	})
}

// ProcessorState represents the connection state of a processor
type ProcessorState int

const (
	ProcessorStateDisconnected ProcessorState = iota
	ProcessorStateConnecting
	ProcessorStateConnected
	ProcessorStateFailed
)

// ProcessorConnection tracks a configured processor and its connection state
type ProcessorConnection struct {
	Address         string
	State           ProcessorState
	Client          interface{ Close() }
	LastAttempt     time.Time
	FailureCount    int
	ReconnectTimer  *time.Timer
}

// Model represents the TUI application state
type Model struct {
	packets         []components.PacketDisplay // Ring buffer of packets (all captured)
	filteredPackets []components.PacketDisplay // Filtered packets for display
	maxPackets      int                        // Maximum packets to keep in memory
	packetList      components.PacketList      // Packet list component
	detailsPanel    components.DetailsPanel    // Details panel component
	remoteClients   map[string]interface{ Close() } // DEPRECATED: use processors instead
	processors      map[string]*ProcessorConnection // Configured processors and their connection state
	huntersByProcessor map[string][]components.HunterInfo // Hunters grouped by processor address
	hexDumpView     components.HexDumpView     // Hex dump component
	header          components.Header          // Header component
	footer          components.Footer          // Footer component
	tabs            components.Tabs              // Tabs component
	nodesView       *components.NodesView        // Nodes view component (pointer so View() changes persist)
	statisticsView  components.StatisticsView    // Statistics view component
	settingsView    components.SettingsView      // Settings view component
	callsView       components.CallsView         // VoIP calls view component
	protocolSelector components.ProtocolSelector // Protocol selector component
	statistics      *components.Statistics       // Statistics data
	capturing       bool                         // Whether capture is active
	paused          bool                       // Whether display is paused
	totalPackets    int                        // Total packets seen
	matchedPackets  int                        // Packets matching filter
	width           int                        // Terminal width
	height          int                        // Terminal height
	quitting        bool                       // Whether we're quitting
	theme           themes.Theme               // Current color theme
	filterInput     components.FilterInput     // Filter input component
	filterChain     *filters.FilterChain       // Active filters
	filterMode      bool                       // Whether in filter input mode
	showDetails     bool                       // Whether to show details pane
	focusedPane     string                     // "left" (packet list) or "right" (details/hex)
	interfaceName   string                     // Capture interface name
	needsUIUpdate   bool                       // Flag to indicate UI needs refresh
	bpfFilter       string                     // Current BPF filter
	captureMode     components.CaptureMode     // Current capture mode (live or offline)
	nodesFilePath   string                     // Path to nodes YAML file for remote mode
	selectedProtocol components.Protocol       // Currently selected protocol
	viewMode        string                     // "packets" or "calls" (for VoIP)
	lastClickTime   time.Time                  // Time of last mouse click for double-click detection
	lastClickPacket int                        // Index of packet clicked for double-click detection
}

// NewModel creates a new TUI model
func NewModel(bufferSize int, interfaceName string, bpfFilter string, pcapFile string, promiscuous bool, startInRemoteMode bool, nodesFilePath string) Model {
	// Load theme from config, default to Solarized Dark
	themeName := viper.GetString("tui.theme")
	if themeName == "" {
		themeName = "dark"
	}
	theme := themes.GetTheme(themeName)

	packetList := components.NewPacketList()
	packetList.SetTheme(theme)

	detailsPanel := components.NewDetailsPanel()
	detailsPanel.SetTheme(theme)

	hexDumpView := components.NewHexDumpView()
	hexDumpView.SetTheme(theme)

	header := components.NewHeader()
	header.SetTheme(theme)

	footer := components.NewFooter()
	footer.SetTheme(theme)

	tabs := components.NewTabs([]components.Tab{
		{Label: "Live Capture", Icon: "📡"},
		{Label: "Nodes", Icon: "🔗"},
		{Label: "Statistics", Icon: "📊"},
		{Label: "Settings", Icon: "⚙"},
	})
	tabs.SetTheme(theme)

	nodesView := components.NewNodesView()
	nodesView.SetTheme(theme)
	nodesViewPtr := &nodesView

	statisticsView := components.NewStatisticsView()
	statisticsView.SetTheme(theme)

	callsView := components.NewCallsView()
	callsView.SetTheme(theme)

	protocolSelector := components.NewProtocolSelector()
	protocolSelector.SetTheme(theme)

	// Initialize statistics
	statistics := &components.Statistics{
		ProtocolCounts: make(map[string]int),
		SourceCounts:   make(map[string]int),
		DestCounts:     make(map[string]int),
		MinPacketSize:  999999,
		MaxPacketSize:  0,
	}

	filterInput := components.NewFilterInput("/")
	filterInput.SetTheme(theme)
	// Load filter history from config
	loadFilterHistory(&filterInput)

	// Determine initial capture mode and interface name
	initialMode := components.CaptureModeLive
	initialInterfaceName := interfaceName
	initialPCAPFile := pcapFile
	if pcapFile != "" {
		initialMode = components.CaptureModeOffline
		initialInterfaceName = pcapFile
		// Update first tab for offline mode
		tabs.UpdateTab(0, "Offline Capture", "📄")
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
		tabs.UpdateTab(0, "Remote Capture", "🌐")
		// Switch to Nodes tab when starting in remote mode
		tabs.SetActive(1)
	}

	// Create settings view with correct initial mode
	settingsView := components.NewSettingsView(interfaceName, bufferSize, promiscuous, bpfFilter, initialPCAPFile)
	settingsView.SetTheme(theme)
	// Set the correct capture mode in settings
	settingsView.SetCaptureMode(initialMode)
	// Set nodes file if in remote mode
	if startInRemoteMode && nodesFilePath != "" {
		settingsView.SetNodesFile(nodesFilePath)
	}

	return Model{
		packets:         make([]components.PacketDisplay, 0, bufferSize),
		filteredPackets: make([]components.PacketDisplay, 0, bufferSize),
		maxPackets:      bufferSize,
		packetList:      packetList,
		detailsPanel:    detailsPanel,
		remoteClients:   make(map[string]interface{ Close() }), // DEPRECATED
		processors:      make(map[string]*ProcessorConnection),  // Track processors with state
		huntersByProcessor: make(map[string][]components.HunterInfo), // Initialize hunters map
		hexDumpView:     hexDumpView,
		header:          header,
		footer:          footer,
		tabs:            tabs,
		nodesView:       nodesViewPtr,
		statisticsView:  statisticsView,
		settingsView:    settingsView,
		callsView:       callsView,
		protocolSelector: protocolSelector,
		statistics:      statistics,
		capturing:       true,
		paused:          false,
		totalPackets:    0,
		matchedPackets:  0,
		width:           80,
		height:          24,
		quitting:        false,
		theme:           theme,
		filterInput:     filterInput,
		filterChain:     filters.NewFilterChain(),
		filterMode:      false,
		showDetails:     true,
		focusedPane:     "left", // Start with packet list focused
		interfaceName:   initialInterfaceName,
		bpfFilter:       bpfFilter,
		captureMode:     initialMode,
		nodesFilePath:   nodesFilePath,
		selectedProtocol: components.Protocol{Name: "All", BPFFilter: ""}, // Default to "All"
		viewMode:        "packets", // Default to packet view
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	// Load remote nodes if in remote mode
	if m.captureMode == components.CaptureModeRemote && m.nodesFilePath != "" {
		return tea.Batch(tickCmd(), loadNodesFile(m.nodesFilePath))
	}
	return tickCmd()
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// If settings tab is active and editing interface, pass messages to settings
	// (this is needed for list filtering to work properly)
	// BUT: Don't intercept PacketMsg, TickMsg, or RestartCaptureMsg - those need to be handled by the main model
	if m.tabs.GetActive() == 3 && m.settingsView.IsEditingInterface() {
		switch msg.(type) {
		case PacketMsg, TickMsg, components.RestartCaptureMsg:
			// Let these fall through to normal handling
		default:
			// Handle quit/suspend keys
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.String() {
				case "q", "ctrl+c":
					m.quitting = true
					return m, tea.Quit
				case "ctrl+z":
					// Suspend the process
					return m, tea.Suspend
				}
			}
			// Pass all other messages to settings view
			cmd := m.settingsView.Update(msg)
			return m, cmd
		}
	}

	switch msg := msg.(type) {
	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tea.KeyMsg:
		// Handle protocol selector mode
		if m.protocolSelector.IsActive() {
			cmd := m.protocolSelector.Update(msg)
			return m, cmd
		}

		// Handle filter input mode
		if m.filterMode {
			return m.handleFilterInput(msg)
		}

		// Settings tab gets priority for most keys (except q, ctrl+c, ctrl+z, space, tab/shift+tab)
		if m.tabs.GetActive() == 3 {
			// If actively editing ANY field, pass ALL keys to settings view
			// (except quit/suspend keys) to prevent global shortcuts from interfering with text input
			if m.settingsView.IsEditing() {
				switch msg.String() {
				case "q", "ctrl+c":
					m.quitting = true
					return m, tea.Quit
				case "ctrl+z":
					// Suspend the process
					return m, tea.Suspend
				default:
					// Pass everything to settings view including t, space, etc.
					cmd := m.settingsView.Update(msg)
					return m, cmd
				}
			}

			// Normal settings tab key handling (when NOT editing)
			switch msg.String() {
			case "q", "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			case "ctrl+z":
				// Suspend the process
				return m, tea.Suspend
			case " ": // Allow space to pause/resume capture
				m.paused = !m.paused
				// Resume ticking when unpausing
				if !m.paused {
					return m, tickCmd()
				}
				return m, nil
			case "t": // Allow theme toggle
				// For future: add theme cycling logic here
				// Currently only Solarized theme available
				m.theme = themes.Solarized()
				// Update all components with new theme
				m.packetList.SetTheme(m.theme)
				m.detailsPanel.SetTheme(m.theme)
				m.hexDumpView.SetTheme(m.theme)
				m.header.SetTheme(m.theme)
				m.footer.SetTheme(m.theme)
				m.tabs.SetTheme(m.theme)
				m.statisticsView.SetTheme(m.theme)
				m.settingsView.SetTheme(m.theme)
				m.filterInput.SetTheme(m.theme)
				saveThemePreference(m.theme)
				return m, nil
			case "tab", "shift+tab":
				// Let these fall through to normal tab switching logic
			default:
				// Forward everything else to settings view
				cmd := m.settingsView.Update(msg)
				// Update interface name in header when it changes (for display only)
				// Actual capture interface doesn't change until restart
				return m, cmd
			}
		}

		// Nodes tab gets priority for certain keys (add node, etc.)
		if m.tabs.GetActive() == 1 {
			// If editing node input, pass ALL keys to NodesView
			if m.nodesView.IsEditing() {
				cmd := m.nodesView.Update(msg)
				return m, cmd
			}
			// Not editing - forward message to NodesView
			if cmd := m.nodesView.Update(msg); cmd != nil {
				return m, cmd
			}
			// If NodesView didn't handle it, fall through to normal handling
		}

		// Normal mode key handling
		switch msg.String() {
		case "ctrl+z":
			// Suspend the process - Bubbletea will automatically handle resume
			return m, tea.Suspend

		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "/": // Enter filter mode
			m.filterMode = true
			m.filterInput.Activate()
			m.filterInput.Clear()
			return m, nil

		case "c": // Clear filters
			if !m.filterChain.IsEmpty() {
				m.filterChain.Clear()
				m.filteredPackets = make([]components.PacketDisplay, 0)
				m.matchedPackets = len(m.packets)
				m.packetList.SetPackets(m.packets)
			}
			return m, nil

		case "x": // Clear/flush packets
			m.packets = make([]components.PacketDisplay, 0, m.maxPackets)
			m.filteredPackets = make([]components.PacketDisplay, 0)
			m.totalPackets = 0
			m.matchedPackets = 0
			m.packetList.SetPackets(m.packets)
			// Reuse maps instead of reallocating (Go 1.21+)
			clear(m.statistics.ProtocolCounts)
			clear(m.statistics.SourceCounts)
			clear(m.statistics.DestCounts)
			m.statistics.TotalBytes = 0
			m.statistics.TotalPackets = 0
			m.statistics.MinPacketSize = 999999
			m.statistics.MaxPacketSize = 0
			m.statisticsView.SetStatistics(m.statistics)
			return m, nil

		case " ": // Space to pause/resume
			m.paused = !m.paused
			// Resume ticking when unpausing
			if !m.paused {
				return m, tickCmd()
			}
			return m, nil

		case "d": // Toggle details panel
			m.showDetails = !m.showDetails
			// Recalculate packet list size based on new showDetails state
			headerHeight := 2
			tabsHeight := 4
			bottomHeight := 4
			contentHeight := m.height - headerHeight - tabsHeight - bottomHeight
			minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
			if m.showDetails && m.width >= minWidthForDetails {
				// Details panel gets exactly what it needs for hex dump, packet list gets the rest
				detailsWidth := 77 // Hex dump (72) + borders/padding (5)
				listWidth := m.width - detailsWidth
				m.packetList.SetSize(listWidth, contentHeight)
				m.detailsPanel.SetSize(detailsWidth, contentHeight)
			} else {
				// Full width for packet list
				m.packetList.SetSize(m.width, contentHeight)
				m.detailsPanel.SetSize(0, contentHeight)
			}
			return m, nil

		case "p": // Open protocol selector
			m.protocolSelector.Activate()
			m.protocolSelector.SetSize(m.width, m.height)
			return m, nil

		case "v": // Toggle view mode (packets vs calls for VoIP)
			if m.selectedProtocol.Name == "VoIP (SIP/RTP)" {
				if m.viewMode == "packets" {
					m.viewMode = "calls"
				} else {
					m.viewMode = "packets"
				}
			}
			return m, nil

		case "h", "left": // Focus left pane (packet list)
			m.focusedPane = "left"
			return m, nil

		case "l", "right": // Focus right pane (details/hex)
			if m.showDetails {
				m.focusedPane = "right"
			}
			return m, nil

		case "tab": // Switch tabs
			m.tabs.Next()
			return m, nil

		case "shift+tab": // Switch tabs backward
			m.tabs.Previous()
			return m, nil

		case "t": // Toggle theme
			// For future: add theme cycling logic here
			// Currently only Solarized theme available
			m.theme = themes.Solarized()
			// Update all components with new theme
			m.packetList.SetTheme(m.theme)
			m.detailsPanel.SetTheme(m.theme)
			m.hexDumpView.SetTheme(m.theme)
			m.header.SetTheme(m.theme)
			m.footer.SetTheme(m.theme)
			m.tabs.SetTheme(m.theme)
			m.statisticsView.SetTheme(m.theme)
			m.settingsView.SetTheme(m.theme)
			m.callsView.SetTheme(m.theme)
			m.protocolSelector.SetTheme(m.theme)
			m.filterInput.SetTheme(m.theme)
			// Save theme preference
			saveThemePreference(m.theme)
			return m, nil

		case "up", "k":
			if m.tabs.GetActive() == 1 { // Nodes tab
				m.nodesView.SelectPrevious()
				return m, nil
			}
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.CursorUp()
			m.updateDetailsPanel()
			return m, nil

		case "down", "j":
			if m.tabs.GetActive() == 1 { // Nodes tab
				m.nodesView.SelectNext()
				return m, nil
			}
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.CursorDown()
			m.updateDetailsPanel()
			return m, nil

		case "home":
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.GotoTop()
			m.updateDetailsPanel()
			return m, nil

		case "end":
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.GotoBottom()
			m.updateDetailsPanel()
			return m, nil

		case "pgup":
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.PageUp()
			m.updateDetailsPanel()
			return m, nil

		case "pgdown":
			if m.tabs.GetActive() == 2 { // Statistics tab
				cmd := m.statisticsView.Update(msg)
				return m, cmd
			}
			if m.tabs.GetActive() == 0 && m.focusedPane == "right" && m.showDetails {
				// Scroll details panel
				cmd := m.detailsPanel.Update(msg)
				return m, cmd
			}
			m.packetList.PageDown()
			m.updateDetailsPanel()
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Update all component sizes
		m.header.SetWidth(msg.Width)
		m.footer.SetWidth(msg.Width)
		m.tabs.SetWidth(msg.Width)
		m.filterInput.SetWidth(msg.Width)

		// Calculate available space for main content
		headerHeight := 2 // header (2 lines: text + border)
		tabsHeight := 4   // tabs (4 lines: top border + content + bottom corners + bottom line)
		bottomHeight := 4 // Reserve 4 lines at bottom (footer + space for filter overlay)

		contentHeight := msg.Height - headerHeight - tabsHeight - bottomHeight

		// Set nodes view size
		m.nodesView.SetSize(msg.Width, contentHeight)

		// Set statistics view size
		m.statisticsView.SetSize(msg.Width, contentHeight)

		// Set settings view size
		m.settingsView.SetSize(msg.Width, contentHeight)

		// Auto-hide details panel if terminal is too narrow or if details are toggled off
		minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
		if m.showDetails && msg.Width >= minWidthForDetails {
			// Details panel gets exactly what it needs for hex dump, packet list gets the rest
			detailsWidth := 77 // Hex dump (72) + borders/padding (5)
			listWidth := msg.Width - detailsWidth
			m.packetList.SetSize(listWidth, contentHeight)
			m.detailsPanel.SetSize(detailsWidth, contentHeight)
		} else {
			// Full width for packet list (details hidden or terminal too narrow)
			m.packetList.SetSize(msg.Width, contentHeight)
			m.detailsPanel.SetSize(0, contentHeight) // Set to 0 when hidden
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
		if !m.paused && m.capturing {
			cmd = tea.Batch(cmd, tickCmd())
		}
		return m, cmd

	case TickMsg:
		// Only run tick when capturing and not paused
		if !m.paused && m.capturing {
			// Periodic UI refresh (10 times per second)
			if m.needsUIUpdate {
				// Update packet list component with filtered packets
				// No need to reapply filters - they're applied per-packet now
				if m.filterChain.IsEmpty() {
					m.packetList.SetPackets(m.packets)
				} else {
					m.packetList.SetPackets(m.filteredPackets)
				}

				// Update details panel if showing details
				if m.showDetails {
					m.updateDetailsPanel()
				}

				m.needsUIUpdate = false
			}
			return m, tickCmd()
		}
		// When paused, stop ticking to save CPU
		return m, nil

	case PacketBatchMsg:
		// Handle batch of packets more efficiently
		if !m.paused {
			for _, packet := range msg.Packets {
				// Set NodeID to "Local" if not already set (for local/offline capture)
				if packet.NodeID == "" {
					packet.NodeID = "Local"
				}

				// Add packet to ring buffer
				if len(m.packets) >= m.maxPackets {
					// Remove oldest packet
					m.packets = m.packets[1:]
					// Also remove from filtered if needed
					if len(m.filteredPackets) > 0 {
						m.filteredPackets = m.filteredPackets[1:]
					}
				}
				m.packets = append(m.packets, packet)
				m.totalPackets++

				// Update statistics (lightweight)
				m.updateStatistics(packet)

				// Apply filter to this single packet immediately
				if !m.filterChain.IsEmpty() {
					if m.filterChain.Match(packet) {
						m.filteredPackets = append(m.filteredPackets, packet)
					}
				}
			}

			// Update matched count once per batch
			if m.filterChain.IsEmpty() {
				m.matchedPackets = len(m.packets)
			} else {
				m.matchedPackets = len(m.filteredPackets)
			}

			// Update packet list immediately for smooth streaming
			if m.filterChain.IsEmpty() {
				m.packetList.SetPackets(m.packets)
			} else {
				m.packetList.SetPackets(m.filteredPackets)
			}

			// Update details panel if showing details
			if m.showDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case PacketMsg:
		if !m.paused {
			// Set NodeID to "Local" if not already set (for local/offline capture)
			packet := msg.Packet
			if packet.NodeID == "" {
				packet.NodeID = "Local"
			}

			// Add packet to ring buffer
			if len(m.packets) >= m.maxPackets {
				// Remove oldest packet
				m.packets = m.packets[1:]
				// Also remove from filtered if needed
				if len(m.filteredPackets) > 0 {
					m.filteredPackets = m.filteredPackets[1:]
				}
			}
			m.packets = append(m.packets, packet)
			m.totalPackets++

			// Update statistics (lightweight)
			m.updateStatistics(packet)

			// Apply filter to this single packet immediately to avoid race condition
			if !m.filterChain.IsEmpty() {
				if m.filterChain.Match(packet) {
					m.filteredPackets = append(m.filteredPackets, packet)
					m.matchedPackets = len(m.filteredPackets)
				}
			} else {
				m.matchedPackets = len(m.packets)
			}

			// Update packet list immediately for smooth streaming
			if m.filterChain.IsEmpty() {
				m.packetList.SetPackets(m.packets)
			} else {
				m.packetList.SetPackets(m.filteredPackets)
			}

			// Update details panel if showing details
			if m.showDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case remotecapture.PacketMsg:
		// Handle packets from remote capture client
		// Only process if we're in remote capture mode and not paused
		if m.captureMode == components.CaptureModeRemote && !m.paused {
			packet := msg.Packet
			// NodeID should already be set by remotecapture client

			// Add packet to ring buffer
			if len(m.packets) >= m.maxPackets {
				m.packets = m.packets[1:]
				if len(m.filteredPackets) > 0 {
					m.filteredPackets = m.filteredPackets[1:]
				}
			}
			m.packets = append(m.packets, packet)
			m.totalPackets++

			m.updateStatistics(packet)

			if !m.filterChain.IsEmpty() {
				if m.filterChain.Match(packet) {
					m.filteredPackets = append(m.filteredPackets, packet)
					m.matchedPackets = len(m.filteredPackets)
				}
			} else {
				m.matchedPackets = len(m.packets)
			}

			// Update packet list immediately for smooth streaming
			if m.filterChain.IsEmpty() {
				m.packetList.SetPackets(m.packets)
			} else {
				m.packetList.SetPackets(m.filteredPackets)
			}

			// Update details panel if showing details
			if m.showDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case remotecapture.PacketBatchMsg:
		// Handle batch of packets from remote capture client
		// Only process if we're in remote capture mode and not paused
		if m.captureMode == components.CaptureModeRemote && !m.paused {
			for _, packet := range msg.Packets {
				// Add packet to ring buffer
				if len(m.packets) >= m.maxPackets {
					m.packets = m.packets[1:]
					if len(m.filteredPackets) > 0 {
						m.filteredPackets = m.filteredPackets[1:]
					}
				}
				m.packets = append(m.packets, packet)
				m.totalPackets++

				m.updateStatistics(packet)

				// Apply filter to this single packet immediately
				if !m.filterChain.IsEmpty() {
					if m.filterChain.Match(packet) {
						m.filteredPackets = append(m.filteredPackets, packet)
					}
				}
			}

			// Update matched count once per batch
			if m.filterChain.IsEmpty() {
				m.matchedPackets = len(m.packets)
			} else {
				m.matchedPackets = len(m.filteredPackets)
			}

			// Update packet list immediately for smooth streaming
			if m.filterChain.IsEmpty() {
				m.packetList.SetPackets(m.packets)
			} else {
				m.packetList.SetPackets(m.filteredPackets)
			}

			// Update details panel if showing details
			if m.showDetails {
				m.updateDetailsPanel()
			}
		}
		return m, nil

	case remotecapture.HunterStatusMsg:
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

		// Update hunters for this processor
		m.huntersByProcessor[processorAddr] = msg.Hunters

		// Merge all hunters from all processors for display
		allHunters := make([]components.HunterInfo, 0)
		for _, hunters := range m.huntersByProcessor {
			allHunters = append(allHunters, hunters...)
		}

		// Update NodesView with merged hunters and list of all processors
		m.nodesView.SetHuntersAndProcessors(allHunters, m.getConnectedProcessors())
		return m, nil

	case components.UpdateBufferSizeMsg:
		// Update buffer size on-the-fly without restarting capture
		m.maxPackets = msg.Size

		// If current packets exceed new buffer size, trim them
		if len(m.packets) > m.maxPackets {
			m.packets = m.packets[len(m.packets)-m.maxPackets:]
		}

		// Save to config file
		m.settingsView.SaveBufferSize()

		return m, nil

	case components.RestartCaptureMsg:
		// Stop current capture using global cancel function
		if currentCaptureCancel != nil {
			// Cancel the old capture and wait briefly for cleanup
			// This prevents the old and new captures from running simultaneously
			cancelFunc := currentCaptureCancel
			currentCaptureCancel = nil // Clear immediately to prevent double-cancellation

			cancelFunc()
			// Give old capture a moment to stop sending packets
			// (most captures stop immediately, offline captures may take slightly longer)
			time.Sleep(100 * time.Millisecond)
		}

		// Keep all remote clients connected regardless of mode
		// Users can switch between modes without losing node connections

		// Update settings based on mode
		switch msg.Mode {
		case components.CaptureModeLive:
			m.interfaceName = msg.Interface
			m.tabs.UpdateTab(0, "Live Capture", "📡")
		case components.CaptureModeOffline:
			m.interfaceName = msg.PCAPFile
			m.tabs.UpdateTab(0, "Offline Capture", "📄")
		case components.CaptureModeRemote:
			m.interfaceName = msg.NodesFile
			m.tabs.UpdateTab(0, "Remote Capture", "🌐")
		}
		m.bpfFilter = msg.Filter

		// Clean up remote clients when switching away from remote mode
		if m.captureMode == components.CaptureModeRemote && msg.Mode != components.CaptureModeRemote {
			for addr, client := range m.remoteClients {
				client.Close()
				delete(m.remoteClients, addr)
			}
		}

		m.captureMode = msg.Mode
		m.maxPackets = msg.BufferSize // Apply the new buffer size
		m.paused = false              // Unpause when restarting capture

		// Clear old packets with new buffer size
		m.packets = make([]components.PacketDisplay, 0, m.maxPackets)
		m.filteredPackets = make([]components.PacketDisplay, 0)
		m.totalPackets = 0
		m.matchedPackets = 0
		m.packetList.Reset() // Reset packet list including autoscroll state

		// Reset statistics (reuse maps)
		clear(m.statistics.ProtocolCounts)
		clear(m.statistics.SourceCounts)
		clear(m.statistics.DestCounts)
		m.statistics.TotalBytes = 0
		m.statistics.TotalPackets = 0
		m.statistics.MinPacketSize = 999999
		m.statistics.MaxPacketSize = 0
		m.statisticsView.SetStatistics(m.statistics)

		// Start new capture in background using global program reference
		if currentProgram != nil {
			// Only create new capture context for live/offline modes
			// Remote mode doesn't need a capture context since it uses gRPC clients
			if msg.Mode == components.CaptureModeLive || msg.Mode == components.CaptureModeOffline {
				ctx, cancel := context.WithCancel(context.Background())
				currentCaptureCancel = cancel

				switch msg.Mode {
				case components.CaptureModeLive:
					go startLiveCapture(ctx, msg.Interface, m.bpfFilter, currentProgram)
				case components.CaptureModeOffline:
					go startOfflineCapture(ctx, msg.PCAPFile, m.bpfFilter, currentProgram)
				}
			} else if msg.Mode == components.CaptureModeRemote {
				// Remote mode: set capture cancel to nil since we're not running local capture
				currentCaptureCancel = nil

				// Load and connect to nodes from YAML file (if provided)
				if msg.NodesFile != "" {
					m.nodesFilePath = msg.NodesFile
					return m, loadNodesFile(msg.NodesFile)
				}
				// If no nodes file, remote mode is active but no nodes connected yet
				// User can add nodes via Nodes tab
			}
		}

		return m, nil

	case components.AddNodeMsg:
		// User wants to add a remote node
		if msg.Address != "" {
			// Add processor to tracking if not already present
			if _, exists := m.processors[msg.Address]; !exists {
				m.processors[msg.Address] = &ProcessorConnection{
					Address:      msg.Address,
					State:        ProcessorStateDisconnected,
					FailureCount: 0,
				}

				// Update nodes view to show the new processor immediately
				// Merge all hunters from all processors for display
				allHunters := make([]components.HunterInfo, 0)
				for _, hunters := range m.huntersByProcessor {
					allHunters = append(allHunters, hunters...)
				}
				m.nodesView.SetHuntersAndProcessors(allHunters, m.getConnectedProcessors())
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
		m.selectedProtocol = msg.Protocol

		// Apply BPF filter if protocol has one
		if msg.Protocol.BPFFilter != "" {
			m.parseAndApplyFilter(msg.Protocol.BPFFilter)
		} else {
			// "All" protocol - clear filters
			m.filterChain.Clear()
			m.filteredPackets = make([]components.PacketDisplay, 0)
			m.matchedPackets = len(m.packets)
			m.packetList.SetPackets(m.packets)
		}

		// Switch to calls view if VoIP protocol selected
		if msg.Protocol.Name == "VoIP (SIP/RTP)" {
			m.viewMode = "calls"
		} else {
			m.viewMode = "packets"
		}

		return m, nil

	case ProcessorReconnectMsg:
		// Attempt to connect/reconnect to a processor
		proc, exists := m.processors[msg.Address]
		if !exists {
			return m, nil
		}

		// Don't reconnect if already connecting or connected
		if proc.State == ProcessorStateConnecting || proc.State == ProcessorStateConnected {
			return m, nil
		}

		// Update state to connecting
		proc.State = ProcessorStateConnecting
		proc.LastAttempt = time.Now()

		// Attempt connection in background
		go func() {
			client, err := remotecapture.NewClient(msg.Address, currentProgram)
			if err != nil {
				// Connection failed
				currentProgram.Send(ProcessorDisconnectedMsg{
					Address: msg.Address,
					Error:   err,
				})
				return
			}

			// Start packet stream
			if err := client.StreamPackets(); err != nil {
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
		if proc, exists := m.processors[msg.Address]; exists {
			proc.State = ProcessorStateConnected
			proc.Client = msg.Client
			proc.FailureCount = 0
			// Also store in deprecated map for compatibility
			m.remoteClients[msg.Address] = msg.Client
		}
		return m, nil

	case ProcessorDisconnectedMsg:
		// Processor connection lost or failed
		if proc, exists := m.processors[msg.Address]; exists {
			proc.State = ProcessorStateFailed
			proc.FailureCount++

			// Clean up old client
			if proc.Client != nil {
				proc.Client.Close()
				proc.Client = nil
			}
			delete(m.remoteClients, msg.Address)

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
	}

	return m, nil
}

// handleMouse handles mouse click and scroll events
func (m Model) handleMouse(msg tea.MouseMsg) (Model, tea.Cmd) {
	// DEBUG: Uncomment to log mouse events to /tmp/lippycat-mouse-debug.log for troubleshooting
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "handleMouse: Y=%d Type=%v Action=%v Button=%v ActiveTab=%d\n",
	// 		msg.Y, msg.Type, msg.Action, msg.Button, m.tabs.GetActive())
	// 	f.Close()
	// }

	// Layout constants
	headerHeight := 2  // Header takes 2 lines (text + border)
	tabsHeight := 4    // Tabs take 4 lines
	bottomHeight := 4  // Footer/filter area
	contentStartY := headerHeight + tabsHeight // Y=6
	contentHeight := m.height - headerHeight - tabsHeight - bottomHeight

	// Handle mouse wheel scrolling
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonWheelUp {
		if m.tabs.GetActive() == 0 {
			// On capture tab - scroll packet list if focused on left
			if m.focusedPane == "left" {
				m.packetList.CursorUp()
				m.updateDetailsPanel()
			} else if m.focusedPane == "right" {
				// Scroll details panel viewport
				cmd := m.detailsPanel.Update(tea.KeyMsg{Type: tea.KeyUp})
				return m, cmd
			}
		}
		return m, nil
	}

	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonWheelDown {
		if m.tabs.GetActive() == 0 {
			// On capture tab - scroll packet list if focused on left
			if m.focusedPane == "left" {
				m.packetList.CursorDown()
				m.updateDetailsPanel()
			} else if m.focusedPane == "right" {
				// Scroll details panel viewport
				cmd := m.detailsPanel.Update(tea.KeyMsg{Type: tea.KeyDown})
				return m, cmd
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
		clickedTab := m.tabs.GetTabAtX(msg.X)
		if clickedTab >= 0 {
			m.tabs.SetActive(clickedTab)
		}
		return m, nil
	}

	// Only handle clicks in content area for capture tab
	// (Nodes and Settings tabs handle their own bounds checking)
	if m.tabs.GetActive() == 0 {
		if msg.Y < contentStartY || msg.Y >= contentStartY+contentHeight {
			return m, nil
		}
	}

	// Packet list clicks (only on first tab - capture tab)
	if m.tabs.GetActive() == 0 {
		minWidthForDetails := 120

		// Check if we're in split pane mode
		if m.showDetails && m.width >= minWidthForDetails {
			// Split pane: packet list on left (65%), details on right (35%)
			// Both panels have borders and padding, so calculate actual widths
			listWidth := m.width * 65 / 100

			// The packet list renders at full listWidth
			// The details panel starts immediately after the packet list
			// Packet list has border(1) + padding(2) = 3 chars on right side
			// So the actual packet list content ends at listWidth - 3
			// Clicks from listWidth - 2 onwards should focus the details panel

			detailsContentStart := listWidth - 2 // Move boundary left to account for packet list's right border/padding

			if msg.X < detailsContentStart {
				// Click in packet list area - switch focus to left pane
				m.focusedPane = "left"

				// First line of data is at contentStartY + 1 (after table header)
				tableHeaderY := contentStartY + 1
				if msg.Y > tableHeaderY {
					// Calculate which row was clicked (relative to visible area)
					visibleRow := msg.Y - tableHeaderY - 1 // -1 for separator line

					packets := m.packets
					if !m.filterChain.IsEmpty() {
						packets = m.filteredPackets
					}

					// Add scroll offset to get actual packet index
					actualPacketIndex := m.packetList.GetOffset() + visibleRow

					if actualPacketIndex >= 0 && actualPacketIndex < len(packets) {
						// Check for double-click (same packet clicked within 500ms)
						now := time.Now()
						isDoubleClick := actualPacketIndex == m.lastClickPacket &&
							now.Sub(m.lastClickTime) < 500*time.Millisecond

						// Update last click tracking
						m.lastClickTime = now
						m.lastClickPacket = actualPacketIndex

						// Set cursor directly without scrolling
						m.packetList.SetCursor(actualPacketIndex)
						m.detailsPanel.SetPacket(&packets[actualPacketIndex])

						// Toggle details panel on double-click
						if isDoubleClick {
							m.showDetails = !m.showDetails
							// Recalculate sizes when toggling details
							headerHeight := 2
							tabsHeight := 4
							bottomHeight := 4
							contentHeight := m.height - headerHeight - tabsHeight - bottomHeight
							minWidthForDetails := 160
							if m.showDetails && m.width >= minWidthForDetails {
								detailsWidth := 77
								listWidth := m.width - detailsWidth
								m.packetList.SetSize(listWidth, contentHeight)
								m.detailsPanel.SetSize(detailsWidth, contentHeight)
							} else {
								m.packetList.SetSize(m.width, contentHeight)
								m.detailsPanel.SetSize(0, contentHeight)
							}
						}
					}
				}
			} else {
				// Click inside details panel content - switch focus to right pane
				m.focusedPane = "right"
			}
		} else {
			// Full width packet list
			tableHeaderY := contentStartY + 1
			if msg.Y > tableHeaderY {
				// Calculate which row was clicked (relative to visible area)
				visibleRow := msg.Y - tableHeaderY - 1

				packets := m.packets
				if !m.filterChain.IsEmpty() {
					packets = m.filteredPackets
				}

				// Add scroll offset to get actual packet index
				actualPacketIndex := m.packetList.GetOffset() + visibleRow

				if actualPacketIndex >= 0 && actualPacketIndex < len(packets) {
					// Check for double-click (same packet clicked within 500ms)
					now := time.Now()
					isDoubleClick := actualPacketIndex == m.lastClickPacket &&
						now.Sub(m.lastClickTime) < 500*time.Millisecond

					// Update last click tracking
					m.lastClickTime = now
					m.lastClickPacket = actualPacketIndex

					// Set cursor directly without scrolling
					m.packetList.SetCursor(actualPacketIndex)
					m.detailsPanel.SetPacket(&packets[actualPacketIndex])
					m.focusedPane = "left"

					// Toggle details panel on double-click
					if isDoubleClick {
						m.showDetails = !m.showDetails
						// Recalculate sizes when toggling details
						headerHeight := 2
						tabsHeight := 4
						bottomHeight := 4
						contentHeight := m.height - headerHeight - tabsHeight - bottomHeight
						minWidthForDetails := 160
						if m.showDetails && m.width >= minWidthForDetails {
							detailsWidth := 77
							listWidth := m.width - detailsWidth
							m.packetList.SetSize(listWidth, contentHeight)
							m.detailsPanel.SetSize(detailsWidth, contentHeight)
						} else {
							m.packetList.SetSize(m.width, contentHeight)
							m.detailsPanel.SetSize(0, contentHeight)
						}
					}
				}
			}
		}
		return m, nil
	}

	// Nodes tab clicks (tab 1)
	if m.tabs.GetActive() == 1 {
		// DEBUG: Uncomment to trace mouse event forwarding
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "  -> Forwarding to NodesView.Update\n")
		// 	f.Close()
		// }
		// Forward mouse events to the nodes view (like settings tab, let it handle coordinate adjustment)
		cmd := m.nodesView.Update(msg)
		return m, cmd
	}

	// Settings tab clicks (tab 3)
	if m.tabs.GetActive() == 3 {
		// Forward mouse events to the settings view
		cmd := m.settingsView.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the TUI
func (m Model) View() string {
	if m.quitting {
		return "Goodbye!\n"
	}

	// Update header state
	m.header.SetState(m.capturing, m.paused)
	m.header.SetPacketCount(m.totalPackets)
	m.header.SetInterface(m.interfaceName)
	m.header.SetCaptureMode(m.captureMode)
	// Use hunter count (not remote client count) for accurate node display
	m.header.SetNodeCount(m.nodesView.GetHunterCount())
	m.header.SetProcessorCount(m.nodesView.GetProcessorCount())

	// Update footer state
	m.footer.SetFilterMode(m.filterMode)
	m.footer.SetHasFilter(!m.filterChain.IsEmpty())

	// Render components
	headerView := m.header.View()
	tabsView := m.tabs.View()
	footerView := m.footer.View()

	var mainContent string

	// Calculate content dimensions
	headerHeight := 2
	tabsHeight := 4
	bottomHeight := 4
	contentHeight := m.height - headerHeight - tabsHeight - bottomHeight

	// Render main content based on active tab
	switch m.tabs.GetActive() {
	case 0: // Live/Remote/Offline Capture
		// Check if we should display calls view or packets view
		if m.viewMode == "calls" {
			// Render calls view
			m.callsView.SetSize(m.width, contentHeight)
			mainContent = m.callsView.View()
		} else {
			// Render packets view
			minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
			if m.showDetails && m.width >= minWidthForDetails {
				// Split pane layout
				leftFocused := m.focusedPane == "left"
				rightFocused := m.focusedPane == "right"

				detailsWidth := 77 // Hex dump (72) + borders/padding (5)

				// Ensure details panel has the right size set
				m.detailsPanel.SetSize(detailsWidth, contentHeight)

				packetListView := m.packetList.View(leftFocused)
				detailsPanelView := m.detailsPanel.View(rightFocused)

				mainContent = lipgloss.JoinHorizontal(lipgloss.Top, packetListView, detailsPanelView)
			} else {
				// Full width packet list
				mainContent = m.packetList.View(m.focusedPane == "left")
			}
		}
	case 1: // Nodes
		// Render nodes view
		mainContent = m.nodesView.View()

	case 2: // Statistics
		// Render statistics view (content is updated via updateStatistics)
		mainContent = m.statisticsView.View()
	case 3: // Settings
		// Render settings view
		mainContent = m.settingsView.View()
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
	if m.filterMode {
		// Filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.filterInput.View()
		bottomArea = filterView + "\n" + footerView
	} else {
		// 3 blank lines + footer (1 line) = 4 lines
		bottomArea = "\n\n\n" + footerView
	}

	fullView := lipgloss.JoinVertical(lipgloss.Left, mainView, bottomArea)

	// Overlay protocol selector if active - render it centered over a semi-transparent background
	if m.protocolSelector.IsActive() {
		selectorView := m.protocolSelector.View()

		// Simply place the selector in the center with background filling
		return lipgloss.Place(
			m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			selectorView,
		)
	}

	return fullView
}

// updateStatistics updates statistics with new packet data
func (m *Model) updateStatistics(pkt components.PacketDisplay) {
	// Update protocol counts
	m.statistics.ProtocolCounts[pkt.Protocol]++

	// Update source counts
	m.statistics.SourceCounts[pkt.SrcIP]++

	// Update destination counts
	m.statistics.DestCounts[pkt.DstIP]++

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
	m.statisticsView.SetStatistics(m.statistics)
}

// updateDetailsPanel updates the details panel with the currently selected packet
func (m *Model) updateDetailsPanel() {
	packets := m.packets
	if !m.filterChain.IsEmpty() {
		packets = m.filteredPackets
	}

	if len(packets) == 0 {
		m.detailsPanel.SetPacket(nil)
		return
	}

	selectedIdx := m.packetList.GetCursor()
	if selectedIdx >= 0 && selectedIdx < len(packets) {
		pkt := packets[selectedIdx]
		m.detailsPanel.SetPacket(&pkt)
	} else {
		m.detailsPanel.SetPacket(nil)
	}
}

// handleFilterInput handles key input when in filter mode
func (m Model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Apply the filter
		filterValue := m.filterInput.Value()
		if filterValue != "" {
			m.parseAndApplyFilter(filterValue)
			m.filterInput.AddToHistory(filterValue)
			// Save filter history to config
			saveFilterHistory(&m.filterInput)
		} else {
			// Empty filter = clear all filters
			m.filterChain.Clear()
			m.filteredPackets = make([]components.PacketDisplay, 0)
			m.matchedPackets = len(m.packets)
			m.packetList.SetPackets(m.packets)
		}
		m.filterMode = false
		m.filterInput.Deactivate()
		return m, nil

	case "esc", "ctrl+c":
		// Cancel filter input
		m.filterMode = false
		m.filterInput.Deactivate()
		return m, nil

	case "up", "ctrl+p":
		m.filterInput.HistoryUp()
		return m, nil

	case "down", "ctrl+n":
		m.filterInput.HistoryDown()
		return m, nil

	case "left", "ctrl+b":
		m.filterInput.CursorLeft()
		return m, nil

	case "right", "ctrl+f":
		m.filterInput.CursorRight()
		return m, nil

	case "home", "ctrl+a":
		m.filterInput.CursorHome()
		return m, nil

	case "end", "ctrl+e":
		m.filterInput.CursorEnd()
		return m, nil

	case "backspace":
		m.filterInput.Backspace()
		return m, nil

	case "delete", "ctrl+d":
		m.filterInput.Delete()
		return m, nil

	case "ctrl+u":
		m.filterInput.DeleteToBeginning()
		return m, nil

	case "ctrl+k":
		m.filterInput.DeleteToEnd()
		return m, nil

	default:
		// Insert character(s) - handles both single keypress and paste
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.filterInput.InsertRune(r)
			}
		}
		return m, nil
	}
}

// parseAndApplyFilter parses a filter string and applies it
func (m *Model) parseAndApplyFilter(filterStr string) {
	// Clear existing filters
	m.filterChain.Clear()

	if filterStr == "" {
		return
	}

	// Try to parse as boolean expression first
	filter, err := filters.ParseBooleanExpression(filterStr, m.parseSimpleFilter)
	if err == nil && filter != nil {
		m.filterChain.Add(filter)
	}

	// Reapply filters to all packets
	m.applyFilters()

	// Update display
	if m.filterChain.IsEmpty() {
		m.packetList.SetPackets(m.packets)
	} else {
		m.packetList.SetPackets(m.filteredPackets)
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
	processors := make([]string, 0, len(m.processors))
	for addr := range m.processors {
		processors = append(processors, addr)
	}
	return processors
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
	if m.filterChain.IsEmpty() {
		m.matchedPackets = len(m.packets)
		m.filteredPackets = make([]components.PacketDisplay, 0)
		return
	}

	m.filteredPackets = make([]components.PacketDisplay, 0, len(m.packets))
	for _, pkt := range m.packets {
		if m.filterChain.Match(pkt) {
			m.filteredPackets = append(m.filteredPackets, pkt)
		}
	}
	m.matchedPackets = len(m.filteredPackets)
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
func startLiveCapture(ctx context.Context, interfaceName string, filter string, program *tea.Program) {
	capture.StartLiveSniffer(interfaceName, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program)
	})
}

// startOfflineCapture starts packet capture from a PCAP file
func startOfflineCapture(ctx context.Context, pcapFile string, filter string, program *tea.Program) {
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

