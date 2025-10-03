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

// TickMsg is sent periodically to trigger UI updates
type TickMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg{}
	})
}

// Model represents the TUI application state
type Model struct {
	packets         []components.PacketDisplay // Ring buffer of packets (all captured)
	filteredPackets []components.PacketDisplay // Filtered packets for display
	maxPackets      int                        // Maximum packets to keep in memory
	packetList      components.PacketList      // Packet list component
	detailsPanel    components.DetailsPanel    // Details panel component
	remoteClients   map[string]interface{ Close() } // Multiple remote capture clients (addr -> client)
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
		{Label: "Nodes", Icon: "🌐"},
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
		remoteClients:   make(map[string]interface{ Close() }), // Initialize remote clients map
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
	if m.captureMode == components.CaptureModeRemote && m.nodesFilePath != "" && currentProgram != nil {
		startRemoteCapture(m.nodesFilePath, m.remoteClients, currentProgram)
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
				if m.theme.Name == "Solarized Dark" {
					m.theme = themes.SolarizedLight()
				} else {
					m.theme = themes.SolarizedDark()
				}
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
			if m.theme.Name == "Solarized Dark" {
				m.theme = themes.SolarizedLight()
			} else {
				m.theme = themes.SolarizedDark()
			}
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

		// Auto-hide details panel if terminal is too narrow
		minWidthForDetails := 120 // Minimum terminal width to show details panel
		if m.showDetails && msg.Width >= minWidthForDetails {
			// Split between packet list and details panel
			listWidth := msg.Width * 65 / 100
			detailsWidth := msg.Width - listWidth
			m.packetList.SetSize(listWidth, contentHeight)
			m.detailsPanel.SetSize(detailsWidth, contentHeight)
		} else {
			// Full width for packet list (details hidden)
			m.packetList.SetSize(msg.Width, contentHeight)
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
		m.nodesView.SetHunters(msg.Hunters)
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
			// Cancel in a goroutine to avoid blocking the UI
			cancelFunc := currentCaptureCancel
			currentCaptureCancel = nil // Clear immediately to prevent double-cancellation

			go func() {
				// Call cancel and give it time to clean up
				cancelFunc()
				// The capture will clean up in the background (up to 2s drain timeout in InitWithContext)
			}()
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
					// Check if program is still valid before starting goroutine
					if currentProgram == nil {
						return m, nil
					}

					// Capture program reference for the goroutine
					prog := currentProgram

					go func() {
						// Recover from any panic in this goroutine to prevent crashing the TUI
						defer func() {
							if r := recover(); r != nil {
								// Panic occurred, log it but don't crash the TUI
								// In production, this should send an error message to the UI
								_ = r
							}
						}()

						nodes, err := config.LoadNodesFromYAML(msg.NodesFile)
						if err != nil {
							// TODO: Show error in UI
							return
						}

						// Connect to each node
						for _, node := range nodes {
							// Skip if already connected
							if _, exists := m.remoteClients[node.Address]; exists {
								continue
							}

							// Create client - use captured program reference
							client, err := remotecapture.NewClient(node.Address, prog)
							if err != nil {
								// TODO: Show error in UI (but continue with other nodes)
								continue
							}

							// Store client
							m.remoteClients[node.Address] = client

							// Start packet stream
							if err := client.StreamPackets(); err != nil {
								// TODO: Show error in UI
								client.Close()
								delete(m.remoteClients, node.Address)
								continue
							}

							// Start hunter status subscription
							if err := client.SubscribeHunterStatus(); err != nil {
								// TODO: Show error in UI (non-fatal)
							}
						}
					}()
				}
				// If no nodes file, remote mode is active but no nodes connected yet
				// User can add nodes via Nodes tab
			}
		}

		return m, nil

	case components.AddNodeMsg:
		// User wants to add a remote node
		if msg.Address != "" {
			// Just add the node - don't change capture mode
			// Start remote connection in background
			go func() {
				// Recover from any panic in this goroutine to prevent crashing the TUI
				defer func() {
					if r := recover(); r != nil {
						// Panic occurred, log it but don't crash the TUI
						_ = r
					}
				}()

				client, err := remotecapture.NewClient(msg.Address, currentProgram)
				if err != nil {
					// TODO: Show error in UI
					return
				}

				// Store client
				m.remoteClients[msg.Address] = client

				// Start packet stream
				if err := client.StreamPackets(); err != nil {
					// TODO: Show error in UI
					client.Close()
					delete(m.remoteClients, msg.Address)
					return
				}

				// Start hunter status subscription
				if err := client.SubscribeHunterStatus(); err != nil {
					// TODO: Show error in UI (non-fatal, packets still work)
				}
			}()
		}
		return m, nil

	case components.LoadNodesMsg:
		// Load nodes from YAML file and connect to them
		if msg.FilePath != "" {
			go func() {
				// Recover from any panic in this goroutine to prevent crashing the TUI
				defer func() {
					if r := recover(); r != nil {
						// Panic occurred, log it but don't crash the TUI
						_ = r
					}
				}()

				// Import the config package at the top of the file
				nodes, err := config.LoadNodesFromYAML(msg.FilePath)
				if err != nil {
					// TODO: Show error in UI
					return
				}

				// Connect to each node
				for _, node := range nodes {
					// Skip if already connected
					if _, exists := m.remoteClients[node.Address]; exists {
						continue
					}

					// Create client
					client, err := remotecapture.NewClient(node.Address, currentProgram)
					if err != nil {
						// TODO: Show error in UI (but continue with other nodes)
						continue
					}

					// Store client
					m.remoteClients[node.Address] = client

					// Start packet stream
					if err := client.StreamPackets(); err != nil {
						// TODO: Show error in UI
						client.Close()
						delete(m.remoteClients, node.Address)
						continue
					}

					// Start hunter status subscription
					if err := client.SubscribeHunterStatus(); err != nil {
						// TODO: Show error in UI (non-fatal)
					}
				}
			}()
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
						// Set cursor directly without scrolling
						m.packetList.SetCursor(actualPacketIndex)
						m.detailsPanel.SetPacket(&packets[actualPacketIndex])
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
					// Set cursor directly without scrolling
					m.packetList.SetCursor(actualPacketIndex)
					m.detailsPanel.SetPacket(&packets[actualPacketIndex])
					m.focusedPane = "left"
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
			minWidthForDetails := 120
			if m.showDetails && m.width >= minWidthForDetails {
				// Split pane layout
				leftFocused := m.focusedPane == "left"
				rightFocused := m.focusedPane == "right"

				listWidth := m.width * 65 / 100
				detailsWidth := m.width - listWidth

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
			lipgloss.WithWhitespaceBackground(m.theme.Background),
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
		// Insert character
		if len(msg.Runes) == 1 {
			m.filterInput.InsertRune(msg.Runes[0])
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

	// Detect filter type based on syntax
	if strings.Contains(filterStr, "sip.") {
		// VoIP filter: sip.user:alice, sip.from:555*, etc.
		parts := strings.SplitN(filterStr, ":", 2)
		if len(parts) == 2 {
			field := strings.TrimPrefix(parts[0], "sip.")
			value := parts[1]
			filter := filters.NewVoIPFilter(field, value)
			m.filterChain.Add(filter)
		}
	} else if isBPFExpression(filterStr) {
		// BPF filter: port 5060, host 192.168.1.1, tcp, udp, etc.
		filter, err := filters.NewBPFFilter(filterStr)
		if err == nil {
			m.filterChain.Add(filter)
		} else {
			// Fall back to text filter if BPF parse fails
			textFilter := filters.NewTextFilter(filterStr, []string{"all"})
			m.filterChain.Add(textFilter)
		}
	} else {
		// Simple text filter for anything else
		filter := filters.NewTextFilter(filterStr, []string{"all"})
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

// startRemoteCapture loads and connects to nodes from YAML file
func startRemoteCapture(nodesFile string, remoteClients map[string]interface{ Close() }, program *tea.Program) {
	if nodesFile == "" {
		return
	}

	go func() {
		// Recover from any panic in this goroutine to prevent crashing the TUI
		defer func() {
			if r := recover(); r != nil {
				// Panic occurred, log it but don't crash the TUI
				_ = r
			}
		}()

		nodes, err := config.LoadNodesFromYAML(nodesFile)
		if err != nil {
			// TODO: Show error in UI
			return
		}

		// Connect to each node
		for _, node := range nodes {
			// Skip if already connected
			if _, exists := remoteClients[node.Address]; exists {
				continue
			}

			// Create client
			client, err := remotecapture.NewClient(node.Address, program)
			if err != nil {
				// TODO: Show error in UI (but continue with other nodes)
				continue
			}

			// Store client
			remoteClients[node.Address] = client

			// Start packet stream
			if err := client.StreamPackets(); err != nil {
				// TODO: Show error in UI
				client.Close()
				delete(remoteClients, node.Address)
				continue
			}

			// Start hunter status subscription
			if err := client.SubscribeHunterStatus(); err != nil {
				// TODO: Show error in UI (non-fatal)
			}
		}
	}()
}

