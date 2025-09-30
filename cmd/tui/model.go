package tui

import (
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/filters"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/spf13/viper"
)

// PacketMsg is sent when a new packet is captured
type PacketMsg struct {
	Packet components.PacketDisplay
}

// Model represents the TUI application state
type Model struct {
	packets         []components.PacketDisplay // Ring buffer of packets (all captured)
	filteredPackets []components.PacketDisplay // Filtered packets for display
	maxPackets      int                        // Maximum packets to keep in memory
	packetList      components.PacketList      // Packet list component
	detailsPanel    components.DetailsPanel    // Details panel component
	header          components.Header          // Header component
	footer          components.Footer          // Footer component
	tabs            components.Tabs              // Tabs component
	statisticsView  components.StatisticsView    // Statistics view component
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
	interfaceName   string                     // Capture interface name
}

// NewModel creates a new TUI model
func NewModel(bufferSize int) Model {
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

	header := components.NewHeader()
	header.SetTheme(theme)

	footer := components.NewFooter()
	footer.SetTheme(theme)

	tabs := components.NewTabs([]components.Tab{
		{Label: "Live Capture", Icon: "📡"},
		{Label: "Nodes", Icon: "🌐"},
		{Label: "Statistics", Icon: "📊"},
	})
	tabs.SetTheme(theme)

	statisticsView := components.NewStatisticsView()
	statisticsView.SetTheme(theme)

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

	return Model{
		packets:         make([]components.PacketDisplay, 0, bufferSize),
		filteredPackets: make([]components.PacketDisplay, 0, bufferSize),
		maxPackets:      bufferSize,
		packetList:      packetList,
		detailsPanel:    detailsPanel,
		header:          header,
		footer:          footer,
		tabs:            tabs,
		statisticsView:  statisticsView,
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
		interfaceName:   "any",
	}
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle filter input mode
		if m.filterMode {
			return m.handleFilterInput(msg)
		}

		// Normal mode key handling
		switch msg.String() {
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

		case " ": // Space to pause/resume
			m.paused = !m.paused
			return m, nil

		case "d": // Toggle details panel
			m.showDetails = !m.showDetails
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
			m.header.SetTheme(m.theme)
			m.footer.SetTheme(m.theme)
			m.tabs.SetTheme(m.theme)
			m.statisticsView.SetTheme(m.theme)
			m.filterInput.SetTheme(m.theme)
			// Save theme preference
			saveThemePreference(m.theme)
			return m, nil

		case "up", "k":
			m.packetList.CursorUp()
			m.updateDetailsPanel()
			return m, nil

		case "down", "j":
			m.packetList.CursorDown()
			m.updateDetailsPanel()
			return m, nil

		case "home":
			m.packetList.GotoTop()
			m.updateDetailsPanel()
			return m, nil

		case "end":
			m.packetList.GotoBottom()
			m.updateDetailsPanel()
			return m, nil

		case "pgup":
			m.packetList.PageUp()
			m.updateDetailsPanel()
			return m, nil

		case "pgdown":
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

		// Set statistics view size
		m.statisticsView.SetSize(msg.Width, contentHeight)

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

			// Update statistics
			m.updateStatistics(msg.Packet)

			// Apply filters
			m.applyFilters()

			// Update packet list component with filtered packets
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

	// Update footer state
	m.footer.SetFilterMode(m.filterMode)
	m.footer.SetHasFilter(!m.filterChain.IsEmpty())

	// Render components
	headerView := m.header.View()
	tabsView := m.tabs.View()
	footerView := m.footer.View()

	var mainContent string

	// Render main content based on active tab
	switch m.tabs.GetActive() {
	case 0: // Live Capture
		minWidthForDetails := 120
		if m.showDetails && m.width >= minWidthForDetails {
			// Split pane layout
			packetListView := m.packetList.View()
			detailsPanelView := m.detailsPanel.View()
			mainContent = lipgloss.JoinHorizontal(lipgloss.Top, packetListView, detailsPanelView)
		} else {
			// Full width packet list
			mainContent = m.packetList.View()
		}
	case 1: // Nodes
		// Nodes view - placeholder
		headerHeight := 2
		tabsHeight := 4
		bottomHeight := 4
		contentHeight := m.height - headerHeight - tabsHeight - bottomHeight

		nodesStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center, lipgloss.Center).
			Width(m.width).
			Height(contentHeight)
		mainContent = nodesStyle.Render("No nodes connected")

	case 2: // Statistics
		// Update and render statistics view
		m.statisticsView.SetStatistics(m.statistics)
		mainContent = m.statisticsView.View()
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
func (m *Model) applyFilters() {
	if m.filterChain.IsEmpty() {
		m.matchedPackets = len(m.packets)
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