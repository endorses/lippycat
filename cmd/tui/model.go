package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/filters"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
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
	hexDumpView     components.HexDumpView     // Hex dump component
	header          components.Header          // Header component
	footer          components.Footer          // Footer component
	tabs            components.Tabs              // Tabs component
	nodesView       components.NodesView         // Nodes view component
	statisticsView  components.StatisticsView    // Statistics view component
	settingsView    components.SettingsView      // Settings view component
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
}

// NewModel creates a new TUI model
func NewModel(bufferSize int, interfaceName string, bpfFilter string, pcapFile string, promiscuous bool) Model {
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

	statisticsView := components.NewStatisticsView()
	statisticsView.SetTheme(theme)

	settingsView := components.NewSettingsView(interfaceName, bufferSize, promiscuous, bpfFilter, pcapFile)
	settingsView.SetTheme(theme)

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

	// Determine initial capture mode
	initialMode := components.CaptureModeLive
	if pcapFile != "" {
		initialMode = components.CaptureModeOffline
		// Update first tab for offline mode
		tabs.UpdateTab(0, "Offline Capture", "📄")
	}

	return Model{
		packets:         make([]components.PacketDisplay, 0, bufferSize),
		filteredPackets: make([]components.PacketDisplay, 0, bufferSize),
		maxPackets:      bufferSize,
		packetList:      packetList,
		detailsPanel:    detailsPanel,
		hexDumpView:     hexDumpView,
		header:          header,
		footer:          footer,
		tabs:            tabs,
		nodesView:       nodesView,
		statisticsView:  statisticsView,
		settingsView:    settingsView,
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
		interfaceName:   interfaceName,
		bpfFilter:       bpfFilter,
		captureMode:     initialMode,
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
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
			// Handle quit keys
			if keyMsg, ok := msg.(tea.KeyMsg); ok {
				switch keyMsg.String() {
				case "q", "ctrl+c":
					m.quitting = true
					return m, tea.Quit
				}
			}
			// Pass all other messages to settings view
			cmd := m.settingsView.Update(msg)
			return m, cmd
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle filter input mode
		if m.filterMode {
			return m.handleFilterInput(msg)
		}

		// Settings tab gets priority for most keys (except q, ctrl+c, space, tab/shift+tab)
		if m.tabs.GetActive() == 3 {
			// If actively editing ANY field, pass ALL keys to settings view
			// (except quit keys) to prevent global shortcuts from interfering with text input
			if m.settingsView.IsEditing() {
				switch msg.String() {
				case "q", "ctrl+c":
					m.quitting = true
					return m, tea.Quit
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
			case " ": // Allow space to pause/resume capture
				m.paused = !m.paused
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

		// Normal mode key handling
		switch msg.String() {
		case "ctrl+z":
			// Suspend the process
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
			m.statistics.ProtocolCounts = make(map[string]int)
			m.statistics.SourceCounts = make(map[string]int)
			m.statistics.DestCounts = make(map[string]int)
			m.statistics.TotalBytes = 0
			m.statistics.TotalPackets = 0
			m.statistics.MinPacketSize = 999999
			m.statistics.MaxPacketSize = 0
			m.statisticsView.SetStatistics(m.statistics)
			return m, nil

		case " ": // Space to pause/resume
			m.paused = !m.paused
			return m, nil

		case "d": // Toggle details panel
			m.showDetails = !m.showDetails
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

	case TickMsg:
		// Periodic UI refresh (10 times per second)
		if m.needsUIUpdate && !m.paused {
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

	case PacketMsg:
		if !m.paused {
			// Add packet to ring buffer
			if len(m.packets) >= m.maxPackets {
				// Remove oldest packet
				m.packets = m.packets[1:]
				// Also remove from filtered if needed
				if len(m.filteredPackets) > 0 {
					m.filteredPackets = m.filteredPackets[1:]
				}
			}
			m.packets = append(m.packets, msg.Packet)
			m.totalPackets++

			// Update statistics (lightweight)
			m.updateStatistics(msg.Packet)

			// Apply filter to this single packet immediately to avoid race condition
			if !m.filterChain.IsEmpty() {
				if m.filterChain.Match(msg.Packet) {
					m.filteredPackets = append(m.filteredPackets, msg.Packet)
					m.matchedPackets = len(m.filteredPackets)
				}
			} else {
				m.matchedPackets = len(m.packets)
			}

			// Mark that UI needs update, but don't update immediately
			m.needsUIUpdate = true
		}
		return m, nil

	case components.RestartCaptureMsg:
		// Stop current capture using global cancel function
		if currentCaptureCancel != nil {
			currentCaptureCancel()
			// Give the old capture time to clean up (up to 2s drain timeout in InitWithContext)
			time.Sleep(500 * time.Millisecond)
		}

		// Update settings based on mode
		if msg.Mode == components.CaptureModeLive {
			m.interfaceName = msg.Interface
			// Update tab to Live Capture
			m.tabs.UpdateTab(0, "Live Capture", "📡")
		} else {
			m.interfaceName = msg.PCAPFile
			// Update tab to Offline Capture
			m.tabs.UpdateTab(0, "Offline Capture", "📄")
		}
		m.bpfFilter = msg.Filter
		m.captureMode = msg.Mode
		m.maxPackets = msg.BufferSize // Apply the new buffer size
		m.paused = false              // Unpause when restarting capture

		// Clear old packets with new buffer size
		m.packets = make([]components.PacketDisplay, 0, m.maxPackets)
		m.filteredPackets = make([]components.PacketDisplay, 0)
		m.totalPackets = 0
		m.matchedPackets = 0
		m.packetList.Reset() // Reset packet list including autoscroll state

		// Reset statistics
		m.statistics.ProtocolCounts = make(map[string]int)
		m.statistics.SourceCounts = make(map[string]int)
		m.statistics.DestCounts = make(map[string]int)
		m.statistics.TotalBytes = 0
		m.statistics.TotalPackets = 0
		m.statistics.MinPacketSize = 999999
		m.statistics.MaxPacketSize = 0
		m.statisticsView.SetStatistics(m.statistics)

		// Start new capture in background using global program reference
		if currentProgram != nil {
			ctx, cancel := context.WithCancel(context.Background())
			currentCaptureCancel = cancel

			if msg.Mode == components.CaptureModeLive {
				go startLiveCapture(ctx, msg.Interface, m.bpfFilter, currentProgram)
			} else {
				go startOfflineCapture(ctx, msg.PCAPFile, m.bpfFilter, currentProgram)
			}
		}

		return m, nil
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
	case 0: // Live Capture
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
		// If config file doesn't exist, create it in ~/.config/lippycat.yaml
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Ensure ~/.config directory exists
			home, err := os.UserHomeDir()
			if err != nil {
				return
			}
			configDir := filepath.Join(home, ".config")
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return
			}

			// Set the config file path
			configPath := filepath.Join(configDir, "lippycat.yaml")
			viper.SetConfigFile(configPath)

			// Try to write
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