//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/viper"
)

// CaptureMode represents the capture mode
type CaptureMode int

const (
	CaptureModeLive CaptureMode = iota
	CaptureModeOffline
	CaptureModeRemote // Connect to processor/hunter node
)

// RestartCaptureMsg is sent when capture needs to be restarted
type RestartCaptureMsg struct {
	Mode        CaptureMode
	Interface   string
	PCAPFile    string
	NodesFile   string // For remote mode: path to nodes YAML file
	Filter      string
	BufferSize  int
	Promiscuous bool
}

// LoadNodesMsg is sent when nodes should be loaded from YAML file
type LoadNodesMsg struct {
	FilePath string
}

// UpdateBufferSizeMsg is sent when buffer size changes
type UpdateBufferSizeMsg struct {
	Size int
}

type settingItem struct {
	title, desc string
}

func (i settingItem) FilterValue() string { return i.title }
func (i settingItem) Title() string       { return i.title }
func (i settingItem) Description() string { return i.desc }

// interfaceDelegate is a custom delegate that shows checkboxes for selected items
type interfaceDelegate struct {
	list.DefaultDelegate
	selectedIfaces map[string]bool
	theme          themes.Theme
}

func newInterfaceDelegate(selectedIfaces map[string]bool, theme themes.Theme) interfaceDelegate {
	d := interfaceDelegate{
		DefaultDelegate: list.NewDefaultDelegate(),
		selectedIfaces:  selectedIfaces,
		theme:           theme,
	}
	return d
}

func (d interfaceDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	if settingItem, ok := item.(settingItem); ok {
		checkbox := "[ ]"
		if d.selectedIfaces[settingItem.title] {
			checkbox = "[✓]"
		}

		// Determine if this item is selected in the list
		isSelected := index == m.Index()

		var str string
		if isSelected {
			selectedStyle := lipgloss.NewStyle().
				Foreground(d.theme.InfoColor).
				Bold(true)
			str = selectedStyle.Render(fmt.Sprintf("%s %s - %s", checkbox, settingItem.title, settingItem.desc))
		} else {
			normalStyle := lipgloss.NewStyle().
				Foreground(d.theme.Foreground)
			str = normalStyle.Render(fmt.Sprintf("%s %s - %s", checkbox, settingItem.title, settingItem.desc))
		}

		fmt.Fprint(w, str)
	} else {
		d.DefaultDelegate.Render(w, m, index, item)
	}
}

// SettingsView displays settings configuration
type SettingsView struct {
	width                int
	height               int
	theme                themes.Theme
	interfaceList        list.Model
	inputs               []textinput.Model
	focusIndex           int
	promiscuous          bool
	availableIfaces      []string
	selectedIfaces       map[string]bool // Multiple selected interfaces
	editing              bool
	savedInterfaceIndex  int             // Save list position when entering editing mode
	savedInterfaceString string          // Save interface string when entering editing mode
	savedSelectedIfaces  map[string]bool // Save interface selection when entering editing mode
	captureMode          CaptureMode
	errorMessage         string // Error message to display
	viewport             viewport.Model
	viewportReady        bool
	pcapFileDialog       FileDialog // File dialog for PCAP file selection (offline mode)
	nodesFileDialog      FileDialog // File dialog for nodes YAML file selection (remote mode)
	lastClickField       int        // Track which field was last clicked for double-click detection
	lastClickTime        time.Time  // Track when field was last clicked
}

const (
	inputBufferSize = iota
	inputBPFFilter
	inputPCAPFile
	inputNodesFile // Path to nodes YAML file for remote mode
	inputCount
)

// NewSettingsView creates a new settings view component
func NewSettingsView(currentInterface string, currentBufferSize int, currentPromiscuous bool, currentFilter string, currentPCAPFile string) SettingsView {
	// Get available network interfaces
	ifaces, err := pcap.FindAllDevs()
	availableIfaces := []string{"any"}
	if err == nil {
		for _, iface := range ifaces {
			if iface.Name != "" {
				availableIfaces = append(availableIfaces, iface.Name)
			}
		}
	}

	// Parse comma-separated interfaces from current setting
	selectedIfaces := make(map[string]bool)
	for _, iface := range strings.Split(currentInterface, ",") {
		iface = strings.TrimSpace(iface)
		if iface != "" {
			selectedIfaces[iface] = true
		}
	}

	// Create list items for interfaces
	items := make([]list.Item, len(availableIfaces))
	selectedIdx := 0
	for i, iface := range availableIfaces {
		desc := "Capture from all interfaces"
		if iface != "any" {
			// Get description from pcap interface
			for _, pcapIface := range ifaces {
				if pcapIface.Name == iface {
					if pcapIface.Description != "" {
						desc = pcapIface.Description
					} else {
						desc = "Network interface"
					}
					break
				}
			}
		}
		items[i] = settingItem{title: iface, desc: desc}
		if selectedIfaces[iface] {
			selectedIdx = i
		}
	}

	delegate := newInterfaceDelegate(selectedIfaces, themes.Solarized())
	interfaceList := list.New(items, delegate, 80, 24)
	interfaceList.Title = "Network Interfaces (Space to toggle, Enter to confirm)"
	interfaceList.SetShowStatusBar(false)
	interfaceList.SetFilteringEnabled(true)
	interfaceList.SetShowFilter(true)
	interfaceList.DisableQuitKeybindings() // Prevent q from quitting the list
	interfaceList.Select(selectedIdx)

	// Create text inputs
	inputs := make([]textinput.Model, inputCount)

	// Buffer Size input
	inputs[inputBufferSize] = textinput.New()
	inputs[inputBufferSize].Placeholder = "10000"
	inputs[inputBufferSize].SetValue(strconv.Itoa(currentBufferSize))
	inputs[inputBufferSize].CharLimit = 10
	inputs[inputBufferSize].Width = 50 // Set explicit width for proper rendering

	// Capture Filter input (BPF)
	inputs[inputBPFFilter] = textinput.New()
	inputs[inputBPFFilter].Placeholder = "e.g., port 5060 or tcp"
	inputs[inputBPFFilter].SetValue(currentFilter)
	inputs[inputBPFFilter].CharLimit = 256
	inputs[inputBPFFilter].Width = 50 // Set explicit width for proper rendering

	// PCAP File input
	inputs[inputPCAPFile] = textinput.New()
	inputs[inputPCAPFile].Placeholder = "/path/to/file.pcap"
	inputs[inputPCAPFile].SetValue(currentPCAPFile)
	inputs[inputPCAPFile].CharLimit = 512
	inputs[inputPCAPFile].Width = 50 // Set explicit width for proper rendering

	// Nodes File input (for remote mode)
	inputs[inputNodesFile] = textinput.New()
	inputs[inputNodesFile].Placeholder = "nodes.yaml or ~/.config/lippycat/nodes.yaml"
	inputs[inputNodesFile].SetValue("")
	inputs[inputNodesFile].CharLimit = 512
	inputs[inputNodesFile].Width = 50 // Set explicit width for proper rendering

	// Determine initial mode based on whether pcap file was provided
	mode := CaptureModeLive
	if currentPCAPFile != "" {
		mode = CaptureModeOffline
	}

	vp := viewport.New(80, 24)
	vp.Style = lipgloss.NewStyle()

	// Initialize PCAP file dialog - start in ./captures if it exists, otherwise current dir
	pcapStartDir := "./captures"
	if _, err := os.Stat(pcapStartDir); os.IsNotExist(err) {
		pcapStartDir, _ = os.Getwd()
	}

	// Create file dialog for PCAP file selection (open mode)
	pcapFileDialog := NewOpenFileDialog(pcapStartDir, []string{".pcap", ".pcapng"}, false)

	// Initialize nodes file dialog - start in ~/.config/lippycat if it exists, otherwise current dir
	nodesStartDir, _ := os.UserHomeDir()
	if nodesStartDir != "" {
		nodesStartDir = filepath.Join(nodesStartDir, ".config", "lippycat")
		if _, err := os.Stat(nodesStartDir); os.IsNotExist(err) {
			nodesStartDir, _ = os.Getwd()
		}
	} else {
		nodesStartDir, _ = os.Getwd()
	}

	// Create file dialog for nodes YAML file selection (open mode)
	nodesFileDialog := NewOpenFileDialog(nodesStartDir, []string{".yaml", ".yml"}, false)

	return SettingsView{
		width:           80,
		height:          24,
		theme:           themes.Solarized(),
		interfaceList:   interfaceList,
		inputs:          inputs,
		focusIndex:      0,
		promiscuous:     currentPromiscuous,
		availableIfaces: availableIfaces,
		selectedIfaces:  selectedIfaces,
		editing:         false,
		captureMode:     mode,
		errorMessage:    "",
		viewport:        vp,
		viewportReady:   false,
		pcapFileDialog:  pcapFileDialog,
		nodesFileDialog: nodesFileDialog,
	}
}

// SetTheme updates the theme
func (s *SettingsView) SetTheme(theme themes.Theme) {
	s.theme = theme
	// Update list delegate with new theme
	delegate := newInterfaceDelegate(s.selectedIfaces, theme)
	s.interfaceList.SetDelegate(delegate)
	// Update file dialogs theme
	s.pcapFileDialog.SetTheme(theme)
	s.nodesFileDialog.SetTheme(theme)
}

// SetCaptureMode sets the capture mode
func (s *SettingsView) SetCaptureMode(mode CaptureMode) {
	s.captureMode = mode
}

// SetNodesFile sets the nodes file path for remote mode
func (s *SettingsView) SetNodesFile(path string) {
	s.inputs[inputNodesFile].SetValue(path)
}

// SetSize sets the view dimensions
func (s *SettingsView) SetSize(width, height int) {
	s.width = width
	s.height = height
	// Account for border and padding (4 for outer margin, 2 for border, 2 for padding)
	s.interfaceList.SetSize(width-8, height/3)

	// Update file dialogs size
	s.pcapFileDialog.SetSize(width, height)
	s.nodesFileDialog.SetSize(width, height)

	// Update viewport size
	s.viewport.Width = width
	s.viewport.Height = height
	s.viewportReady = true
}

// GetBufferSize returns the configured buffer size
func (s *SettingsView) GetBufferSize() int {
	val := s.inputs[inputBufferSize].Value()
	size, err := strconv.Atoi(val)
	if err != nil || size <= 0 {
		return 10000
	}
	return size
}

// GetBPFFilter returns the configured BPF filter
func (s *SettingsView) GetBPFFilter() string {
	return s.inputs[inputBPFFilter].Value()
}

// GetPCAPFile returns the configured PCAP file path
func (s *SettingsView) GetPCAPFile() string {
	return s.inputs[inputPCAPFile].Value()
}

// GetInterface returns the selected interfaces as comma-separated string
func (s *SettingsView) GetInterface() string {
	// If no interfaces selected, return "any"
	if len(s.selectedIfaces) == 0 {
		return "any"
	}

	// Build comma-separated list in sorted order to prevent flickering
	var ifaces []string
	for iface := range s.selectedIfaces {
		ifaces = append(ifaces, iface)
	}
	// Sort to maintain consistent order
	sortStrings(ifaces)
	return strings.Join(ifaces, ",")
}

// sortStrings sorts a slice of strings in place (simple bubble sort for small lists)
func sortStrings(arr []string) {
	n := len(arr)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if arr[j] > arr[j+1] {
				arr[j], arr[j+1] = arr[j+1], arr[j]
			}
		}
	}
}

// GetPromiscuous returns the promiscuous mode setting
func (s *SettingsView) GetPromiscuous() bool {
	return s.promiscuous
}

// GetCaptureMode returns the current capture mode
func (s *SettingsView) GetCaptureMode() CaptureMode {
	return s.captureMode
}

// IsEditing returns whether the settings view is in editing mode
func (s *SettingsView) IsEditing() bool {
	return s.editing
}

// IsEditingInterface returns whether the interface list is being edited
func (s *SettingsView) IsEditingInterface() bool {
	return s.editing && s.focusIndex == 1 && s.captureMode == CaptureModeLive
}

// HasChanges returns true if settings differ from initial values
func (s *SettingsView) HasChanges(currentInterface string) bool {
	return s.GetInterface() != currentInterface
}

// validateSettings validates the current settings before restart
func (s *SettingsView) validateSettings() error {
	switch s.captureMode {
	case CaptureModeOffline:
		pcapFile := s.GetPCAPFile()
		if pcapFile == "" {
			return fmt.Errorf("pcap file path required")
		}

		// Check if file exists
		info, err := os.Stat(pcapFile)
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", pcapFile)
		}
		if err != nil {
			return fmt.Errorf("cannot read file: %s", pcapFile)
		}

		// Check if it's a directory
		if info.IsDir() {
			return fmt.Errorf("path is a directory, not a file: %s", pcapFile)
		}
	case CaptureModeRemote:
		// Remote mode validation - nodes file is optional
		// Users can add nodes via the Nodes tab instead
		nodesFile := s.inputs[inputNodesFile].Value()
		if nodesFile != "" {
			// Expand tilde to home directory for validation
			expandedPath := nodesFile
			if strings.HasPrefix(nodesFile, "~/") {
				if home, err := os.UserHomeDir(); err == nil {
					expandedPath = filepath.Join(home, nodesFile[2:])
				}
			}
			// If a file is specified, check if it exists
			if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
				return fmt.Errorf("nodes file does not exist: %s", nodesFile)
			}
		}
		// If no file specified, that's OK - user can add nodes via Nodes tab
	default:
		// Live mode validation
		if len(s.selectedIfaces) == 0 {
			return fmt.Errorf("at least one interface required for live capture")
		}

		// Validate promiscuous mode with "any" interface
		if s.promiscuous && s.selectedIfaces["any"] {
			return fmt.Errorf("promiscuous mode cannot be used with 'any' interface")
		}
	}

	return nil
}

// restartCapture returns a command to restart capture with current settings
func (s *SettingsView) restartCapture() tea.Cmd {
	// Validate settings first
	if err := s.validateSettings(); err != nil {
		s.errorMessage = err.Error()
		return nil
	}

	// Clear error message on successful validation
	s.errorMessage = ""

	// Save buffer size to config
	s.SaveBufferSize()

	return func() tea.Msg {
		return RestartCaptureMsg{
			Mode:        s.captureMode,
			Interface:   s.GetInterface(),
			PCAPFile:    s.GetPCAPFile(),
			NodesFile:   s.inputs[inputNodesFile].Value(),
			Filter:      s.GetBPFFilter(),
			BufferSize:  s.GetBufferSize(),
			Promiscuous: s.promiscuous,
		}
	}
}

// SaveBufferSize persists the buffer size to config file
func (s *SettingsView) SaveBufferSize() {
	bufferSize := s.GetBufferSize()
	viper.Set("tui.buffer_size", bufferSize)

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
				return
			}
		}
	}
}

// getMaxFocusIndex returns the maximum focus index based on current mode
func (s *SettingsView) getMaxFocusIndex() int {
	// Mode selector (0) + mode-specific fields + buffer size + BPF filter (if applicable)
	switch s.captureMode {
	case CaptureModeLive:
		// 0: mode, 1: interface, 2: promiscuous, 3: buffer, 4: filter
		return 5
	case CaptureModeRemote:
		// 0: mode, 1: nodes file, 2: buffer (no filter in remote mode)
		return 3
	default:
		// 0: mode, 1: pcap file, 2: buffer, 3: filter
		return 4
	}
}

// Update handles messages
func (s *SettingsView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd

	// Handle FileSelectedMsg from file dialogs
	if fileMsg, ok := msg.(FileSelectedMsg); ok {
		fullPath := fileMsg.Path()
		s.errorMessage = ""

		// Determine which dialog sent this based on current capture mode
		if s.captureMode == CaptureModeOffline || s.pcapFileDialog.IsActive() {
			// PCAP file selected - switch to offline mode
			s.inputs[inputPCAPFile].SetValue(fullPath)
			s.captureMode = CaptureModeOffline
		} else if s.captureMode == CaptureModeRemote || s.nodesFileDialog.IsActive() {
			// Nodes YAML file selected - switch to remote mode
			s.inputs[inputNodesFile].SetValue(fullPath)
			s.captureMode = CaptureModeRemote
		}

		// Trigger restart with the new settings
		return s.restartCapture()
	}

	// Route messages to PCAP file dialog if active
	if s.pcapFileDialog.IsActive() {
		cmd = s.pcapFileDialog.Update(msg)
		return cmd
	}

	// Route messages to nodes file dialog if active
	if s.nodesFileDialog.IsActive() {
		cmd = s.nodesFileDialog.Update(msg)
		return cmd
	}

	// When editing interface list, pass ALL messages to it (including internal ones)
	// This is needed for filtering to work properly
	if s.editing && s.focusIndex == 1 && s.captureMode == CaptureModeLive {
		// For certain keys, we handle them ourselves first
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case " ": // Space to toggle interface selection
				if item, ok := s.interfaceList.SelectedItem().(settingItem); ok {
					iface := item.title
					// Toggle selection
					if iface == "any" {
						// If selecting "any", clear all other selections and disable promiscuous mode
						s.selectedIfaces = map[string]bool{"any": true}
						s.promiscuous = false
					} else {
						// If selecting specific interface, remove "any" if present
						delete(s.selectedIfaces, "any")
						// Toggle this interface
						if s.selectedIfaces[iface] {
							delete(s.selectedIfaces, iface)
						} else {
							s.selectedIfaces[iface] = true
						}
					}
					// Update delegate to reflect new selection
					delegate := newInterfaceDelegate(s.selectedIfaces, s.theme)
					s.interfaceList.SetDelegate(delegate)
				}
				return nil
			case "enter":
				// Commit the selection and exit editing mode
				s.editing = false

				// Always trigger restart when exiting interface editing
				// (the restart function will validate settings)
				return s.restartCapture()
			case "esc":
				// For interface list: first ESC clears filter, second ESC exits editing
				// Pass ESC to list first to see if it handles it (clearing filter)
				s.interfaceList, cmd = s.interfaceList.Update(msg)

				// Check if list is still filtering - if not, we can exit editing mode
				if !s.interfaceList.SettingFilter() && !s.interfaceList.IsFiltered() {
					s.editing = false
					// Revert interface selection to saved state
					s.interfaceList.Select(s.savedInterfaceIndex)
					s.selectedIfaces = s.savedSelectedIfaces
					// Update delegate to reflect reverted selection
					delegate := newInterfaceDelegate(s.selectedIfaces, s.theme)
					s.interfaceList.SetDelegate(delegate)
				}
				return cmd
			}
		}
		// Pass all other messages to the list
		s.interfaceList, cmd = s.interfaceList.Update(msg)
		return cmd
	}

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// Handle mouse clicks for focusing different settings
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			// Calculate which setting was clicked based on Y position
			// Need to account for: header (2) + tabs (4) = 6 lines before content
			relativeY := msg.Y - 6

			// Exit edit mode if clicking outside the currently editing field
			if s.editing && relativeY >= 0 {
				clickedField := -1
				switch s.captureMode {
				case CaptureModeLive:
					if relativeY >= 11 && relativeY <= 13 {
						clickedField = 3 // Buffer
					} else if relativeY >= 14 && relativeY <= 16 {
						clickedField = 4 // Filter
					}
				case CaptureModeOffline:
					if relativeY >= 5 && relativeY <= 7 {
						clickedField = 1 // PCAP File
					} else if relativeY >= 8 && relativeY <= 10 {
						clickedField = 2 // Buffer
					} else if relativeY >= 11 && relativeY <= 13 {
						clickedField = 3 // Filter
					}
				case CaptureModeRemote:
					if relativeY >= 5 && relativeY <= 7 {
						clickedField = 1 // Nodes File
					} else if relativeY >= 8 && relativeY <= 10 {
						clickedField = 2 // Buffer
					}
					// No filter field in remote mode
				}

				// If clicking on a different field (not empty space), exit edit mode
				if clickedField >= 0 && clickedField != s.focusIndex {
					s.editing = false
					s.inputs[inputBufferSize].Blur()
					s.inputs[inputBPFFilter].Blur()
					s.inputs[inputPCAPFile].Blur()
					s.inputs[inputNodesFile].Blur()
				}
			}

			if relativeY >= 0 { // Within settings area
				// Based on user feedback, the actual Y ranges are:
				// Mode: starts at line 2, ends at line 4 (3 lines total)
				// Interface: starts at line 5, ends at line 7 (3 lines total)
				// Promiscuous: starts at line 8, ends at line 10 (3 lines total)
				// Buffer: starts at line 11, ends at line 13 (3 lines total)
				// Filter: starts at line 14, ends at line 16 (3 lines total)

				switch s.captureMode {
				case CaptureModeLive:
					// Live mode: Mode(0), Interface(1), Promiscuous(2), Buffer(3), Filter(4)
					if relativeY >= 2 && relativeY <= 4 {
						// Click on capture mode tabs - check X position to determine which tab
						// "Live" is approximately at X 20-35, "Offline" at X 36-55, "Remote" at X 56-75
						if msg.X >= 21 && msg.X <= 31 {
							// Already in Live mode, do nothing
						} else if msg.X >= 32 && msg.X <= 42 {
							// Switch to Offline mode
							s.captureMode = CaptureModeOffline
							return s.restartCapture()
						} else if msg.X >= 43 && msg.X <= 50 {
							// Switch to Remote mode
							s.captureMode = CaptureModeRemote
							return s.restartCapture()
						}
						s.focusIndex = 0 // Mode
					} else if relativeY >= 5 && relativeY <= 7 {
						s.focusIndex = 1 // Interface
					} else if relativeY >= 8 && relativeY <= 10 {
						// Click on promiscuous mode - toggle it
						if !s.selectedIfaces["any"] {
							s.promiscuous = !s.promiscuous
							s.errorMessage = ""
						} else {
							s.errorMessage = "Cannot enable promiscuous mode with 'any' interface"
						}
						s.focusIndex = 2 // Promiscuous
					} else if relativeY >= 11 && relativeY <= 13 {
						s.focusIndex = 3 // Buffer
					} else if relativeY >= 14 && relativeY <= 16 {
						s.focusIndex = 4 // Filter
					}
				case CaptureModeOffline:
					// Offline mode: Mode(0), PCAP File(1), Buffer(2), Filter(3)
					if relativeY >= 2 && relativeY <= 4 {
						// Click on capture mode tabs
						if msg.X >= 20 && msg.X <= 31 {
							// Switch to Live mode
							s.captureMode = CaptureModeLive
							return s.restartCapture()
						} else if msg.X >= 32 && msg.X <= 42 {
							// Already in Offline mode, do nothing
						} else if msg.X >= 43 && msg.X <= 50 {
							// Switch to Remote mode
							s.captureMode = CaptureModeRemote
							return s.restartCapture()
						}
						s.focusIndex = 0 // Mode
					} else if relativeY >= 5 && relativeY <= 7 {
						s.focusIndex = 1 // PCAP File
					} else if relativeY >= 8 && relativeY <= 10 {
						s.focusIndex = 2 // Buffer
					} else if relativeY >= 11 && relativeY <= 13 {
						s.focusIndex = 3 // Filter
					}
				case CaptureModeRemote:
					// Remote mode: Mode(0), Nodes File(1), Buffer(2) - no filter
					if relativeY >= 2 && relativeY <= 4 {
						// Click on capture mode tabs
						if msg.X >= 20 && msg.X <= 31 {
							// Switch to Live mode
							s.captureMode = CaptureModeLive
							return s.restartCapture()
						} else if msg.X >= 32 && msg.X <= 42 {
							// Switch to Offline mode
							s.captureMode = CaptureModeOffline
							return s.restartCapture()
						} else if msg.X >= 43 && msg.X <= 50 {
							// Already in Remote mode, do nothing
						}
						s.focusIndex = 0 // Mode
					} else if relativeY >= 5 && relativeY <= 7 {
						s.focusIndex = 1 // Nodes File
					} else if relativeY >= 8 && relativeY <= 10 {
						s.focusIndex = 2 // Buffer
					}
					// No filter field in remote mode
				}
			}
		}

		// Handle double-click to enter edit mode on input fields
		// Check if this is a double-click (second click within 500ms on same field)
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			relativeY := msg.Y - 6
			now := time.Now()
			const doubleClickThreshold = 500 * time.Millisecond

			// Determine which field was clicked based on Y position
			clickedField := -1
			switch s.captureMode {
			case CaptureModeLive:
				if relativeY >= 11 && relativeY <= 13 {
					clickedField = 3 // Buffer
				} else if relativeY >= 14 && relativeY <= 16 {
					clickedField = 4 // Filter
				}
			case CaptureModeOffline:
				if relativeY >= 5 && relativeY <= 7 {
					clickedField = 1 // PCAP File
				} else if relativeY >= 8 && relativeY <= 10 {
					clickedField = 2 // Buffer
				} else if relativeY >= 11 && relativeY <= 13 {
					clickedField = 3 // Filter
				}
			case CaptureModeRemote:
				if relativeY >= 5 && relativeY <= 7 {
					clickedField = 1 // Nodes File
				} else if relativeY >= 8 && relativeY <= 10 {
					clickedField = 2 // Buffer
				}
				// No filter field in remote mode
			}

			// Check if this is a double-click on the same field
			if clickedField >= 0 && clickedField == s.lastClickField &&
				now.Sub(s.lastClickTime) < doubleClickThreshold && !s.editing {
				// Double-click detected - enter edit mode
				switch s.captureMode {
				case CaptureModeLive:
					if clickedField == 3 {
						s.editing = true
						s.inputs[inputBufferSize].Focus()
					} else if clickedField == 4 {
						s.editing = true
						s.inputs[inputBPFFilter].Focus()
					}
				case CaptureModeOffline:
					if clickedField == 1 {
						// Open file dialog modal for PCAP file selection
						s.pcapFileDialog.Activate()
						return nil
					} else if clickedField == 2 {
						s.editing = true
						s.inputs[inputBufferSize].Focus()
					} else if clickedField == 3 {
						s.editing = true
						s.inputs[inputBPFFilter].Focus()
					}
				case CaptureModeRemote:
					if clickedField == 1 {
						// Open file dialog modal for nodes YAML file selection
						s.nodesFileDialog.Activate()
						return nil
					} else if clickedField == 2 {
						s.editing = true
						s.inputs[inputBufferSize].Focus()
					}
					// No filter field in remote mode
				}
			}

			// Update last click tracking
			s.lastClickField = clickedField
			s.lastClickTime = now
		}
		return nil

	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			// Mode selector
			if s.focusIndex == 0 {
				// Cycle through modes: Live -> Offline -> Remote -> Live
				oldMode := s.captureMode
				switch s.captureMode {
				case CaptureModeLive:
					s.captureMode = CaptureModeOffline
				case CaptureModeOffline:
					s.captureMode = CaptureModeRemote
				case CaptureModeRemote:
					s.captureMode = CaptureModeLive
				}

				// Trigger restart if mode changed
				if oldMode != s.captureMode {
					return s.restartCapture()
				}
				return nil
			}

			// Promiscuous toggle (only visible in live mode)
			if s.captureMode == CaptureModeLive && s.focusIndex == 2 {
				// Only allow toggling promiscuous mode if "any" is not selected
				if s.selectedIfaces["any"] {
					// Show error message - cannot enable promiscuous with "any"
					s.errorMessage = "Cannot enable promiscuous mode with 'any' interface"
				} else {
					s.promiscuous = !s.promiscuous
					s.errorMessage = "" // Clear any previous error
				}
				return nil
			}

			// Interface field (only in live mode)
			if s.captureMode == CaptureModeLive && s.focusIndex == 1 {
				if !s.editing {
					s.savedInterfaceIndex = s.interfaceList.Index()
					s.savedInterfaceString = s.GetInterface() // Save current interface string
					// Deep copy the selected interfaces map
					s.savedSelectedIfaces = make(map[string]bool)
					for k, v := range s.selectedIfaces {
						s.savedSelectedIfaces[k] = v
					}
					s.editing = true
				}
				return nil
			}

			// Text inputs
			if s.captureMode == CaptureModeLive {
				// In live mode: buffer (3), filter (4)
				if s.focusIndex == 3 || s.focusIndex == 4 {
					s.editing = !s.editing
					if s.editing {
						if s.focusIndex == 3 {
							s.inputs[inputBufferSize].Focus()
						} else {
							s.inputs[inputBPFFilter].Focus()
						}
					} else {
						// Send buffer size update when exiting edit mode
						if s.focusIndex == 3 {
							s.inputs[inputBufferSize].Blur()
							return func() tea.Msg {
								return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
							}
						} else if s.focusIndex == 4 {
							// BPF filter changed - restart capture to apply it
							s.inputs[inputBPFFilter].Blur()
							return s.restartCapture()
						}
						s.inputs[inputBufferSize].Blur()
						s.inputs[inputBPFFilter].Blur()
					}
					return nil
				}
			} else if s.captureMode == CaptureModeRemote {
				// In remote mode: nodes file (1), buffer (2) - no filter
				switch s.focusIndex {
				case 1:
					// Open file dialog modal for nodes YAML file selection
					return s.nodesFileDialog.Activate()
				case 2:
					s.editing = !s.editing
					if s.editing {
						s.errorMessage = "" // Clear error when editing
						s.inputs[inputBufferSize].Focus()
					} else {
						// Send buffer size update when exiting edit mode
						s.inputs[inputBufferSize].Blur()
						return func() tea.Msg {
							return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
						}
					}
					return nil
				}
			} else {
				// In offline mode: pcap file (1), buffer (2), filter (3)
				switch s.focusIndex {
				case 1:
					// Open file dialog modal for PCAP file selection
					return s.pcapFileDialog.Activate()
				case 2, 3:
					inputIdx := s.focusIndex - 2 // Map to inputBufferSize or inputBPFFilter
					s.editing = !s.editing
					if s.editing {
						s.errorMessage = "" // Clear error when editing
						s.inputs[inputIdx].Focus()
					} else {
						s.inputs[inputIdx].Blur()
						// Send buffer size update when exiting buffer size edit
						if s.focusIndex == 2 {
							return func() tea.Msg {
								return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
							}
						} else if s.focusIndex == 3 {
							// BPF filter changed - restart capture to apply it
							return s.restartCapture()
						}
					}
				}
			}
			return nil

		case "j", "down":
			if s.editing {
				// When editing text input, pass to the input (for cursor movement)
				if s.captureMode == CaptureModeLive {
					if s.focusIndex == 3 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 4 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				} else if s.captureMode == CaptureModeRemote {
					if s.focusIndex == 1 {
						s.inputs[inputNodesFile], cmd = s.inputs[inputNodesFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					}
					// No filter field in remote mode
				} else {
					if s.focusIndex == 1 {
						s.inputs[inputPCAPFile], cmd = s.inputs[inputPCAPFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 3 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				}
			}

			// When not editing, navigate to next field
			if !s.editing {
				maxIdx := s.getMaxFocusIndex()
				s.focusIndex = (s.focusIndex + 1) % maxIdx
				// Auto-scroll viewport to keep focused field visible
				s.scrollToFocusedField()
			}
			return nil

		case "k", "up":
			if s.editing {
				// When editing text input, pass to the input (for cursor movement)
				if s.captureMode == CaptureModeLive {
					if s.focusIndex == 3 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 4 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				} else if s.captureMode == CaptureModeRemote {
					if s.focusIndex == 1 {
						s.inputs[inputNodesFile], cmd = s.inputs[inputNodesFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					}
					// No filter field in remote mode
				} else {
					if s.focusIndex == 1 {
						s.inputs[inputPCAPFile], cmd = s.inputs[inputPCAPFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 3 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				}
			}

			// When not editing, navigate to previous field
			if !s.editing {
				maxIdx := s.getMaxFocusIndex()
				s.focusIndex = (s.focusIndex - 1 + maxIdx) % maxIdx
				// Auto-scroll viewport to keep focused field visible
				s.scrollToFocusedField()
			}
			return nil

		case "left", "h":
			if s.editing {
				// When editing text input, pass to the input for cursor movement
				if s.captureMode == CaptureModeLive {
					if s.focusIndex == 3 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 4 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				} else if s.captureMode == CaptureModeRemote {
					if s.focusIndex == 1 {
						s.inputs[inputNodesFile], cmd = s.inputs[inputNodesFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					}
					// No filter field in remote mode
				} else {
					if s.focusIndex == 1 {
						s.inputs[inputPCAPFile], cmd = s.inputs[inputPCAPFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 3 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				}
			}

			// Previous mode when focused on mode selector (and not editing)
			if s.focusIndex == 0 && !s.editing {
				oldMode := s.captureMode
				switch s.captureMode {
				case CaptureModeLive:
					s.captureMode = CaptureModeRemote
				case CaptureModeOffline:
					s.captureMode = CaptureModeLive
				case CaptureModeRemote:
					s.captureMode = CaptureModeOffline
				}
				if oldMode != s.captureMode {
					return s.restartCapture()
				}
			}
			return nil

		case "right", "l":
			if s.editing {
				// When editing text input, pass to the input for cursor movement
				if s.captureMode == CaptureModeLive {
					if s.focusIndex == 3 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 4 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				} else if s.captureMode == CaptureModeRemote {
					if s.focusIndex == 1 {
						s.inputs[inputNodesFile], cmd = s.inputs[inputNodesFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					}
					// No filter field in remote mode
				} else {
					if s.focusIndex == 1 {
						s.inputs[inputPCAPFile], cmd = s.inputs[inputPCAPFile].Update(msg)
						return cmd
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
						return cmd
					} else if s.focusIndex == 3 {
						s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
						return cmd
					}
				}
			}

			// Next mode when focused on mode selector (and not editing)
			if s.focusIndex == 0 && !s.editing {
				oldMode := s.captureMode
				switch s.captureMode {
				case CaptureModeLive:
					s.captureMode = CaptureModeOffline
				case CaptureModeOffline:
					s.captureMode = CaptureModeRemote
				case CaptureModeRemote:
					s.captureMode = CaptureModeLive
				}
				if oldMode != s.captureMode {
					return s.restartCapture()
				}
			}
			return nil

		case "esc":
			if s.editing {
				// Blur text input
				if s.captureMode == CaptureModeLive {
					if s.focusIndex == 3 {
						s.inputs[inputBufferSize].Blur()
						// Save buffer size when exiting edit mode
						s.editing = false
						return func() tea.Msg {
							return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
						}
					} else if s.focusIndex == 4 {
						s.inputs[inputBPFFilter].Blur()
						s.editing = false
						// BPF filter changed - restart capture to apply it
						return s.restartCapture()
					}
				} else if s.captureMode == CaptureModeRemote {
					// Restore placeholder when blurring with Esc
					if s.focusIndex == 1 {
						s.inputs[inputNodesFile].Placeholder = "nodes.yaml or ~/.config/lippycat/nodes.yaml"
						s.inputs[inputNodesFile].Blur()
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize].Blur()
						// Save buffer size when exiting edit mode
						s.editing = false
						return func() tea.Msg {
							return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
						}
					}
					// No filter field in remote mode
				} else {
					if s.focusIndex == 1 {
						s.inputs[inputPCAPFile].Blur()
					} else if s.focusIndex == 2 {
						s.inputs[inputBufferSize].Blur()
						// Save buffer size when exiting edit mode
						s.editing = false
						return func() tea.Msg {
							return UpdateBufferSizeMsg{Size: s.GetBufferSize()}
						}
					} else if s.focusIndex == 3 {
						s.inputs[inputBPFFilter].Blur()
						s.editing = false
						// BPF filter changed - restart capture to apply it
						return s.restartCapture()
					}
				}
				s.editing = false
			}
			return nil
		}
	}

	// Pass other keys to text inputs when in editing mode
	if s.editing {
		if s.captureMode == CaptureModeLive {
			if s.focusIndex == 3 {
				s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
				return cmd
			} else if s.focusIndex == 4 {
				s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
				return cmd
			}
		} else if s.captureMode == CaptureModeRemote {
			if s.focusIndex == 1 {
				s.inputs[inputNodesFile], cmd = s.inputs[inputNodesFile].Update(msg)
				return cmd
			} else if s.focusIndex == 2 {
				s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
				return cmd
			}
			// No filter field in remote mode
		} else {
			if s.focusIndex == 1 {
				s.inputs[inputPCAPFile], cmd = s.inputs[inputPCAPFile].Update(msg)
				return cmd
			} else if s.focusIndex == 2 {
				s.inputs[inputBufferSize], cmd = s.inputs[inputBufferSize].Update(msg)
				return cmd
			} else if s.focusIndex == 3 {
				s.inputs[inputBPFFilter], cmd = s.inputs[inputBPFFilter].Update(msg)
				return cmd
			}
		}
	}

	// Handle tea.WindowSizeMsg
	if windowMsg, ok := msg.(tea.WindowSizeMsg); ok {
		s.width = windowMsg.Width
		s.height = windowMsg.Height
		s.interfaceList.SetWidth(windowMsg.Width - 4)
		s.interfaceList.SetHeight(windowMsg.Height - 10)
		s.pcapFileDialog.SetSize(windowMsg.Width, windowMsg.Height)
		s.nodesFileDialog.SetSize(windowMsg.Width, windowMsg.Height)
		s.viewport.Width = windowMsg.Width - 4
		s.viewport.Height = windowMsg.Height - 10
	}

	return nil
}

// View renders the settings view
func (s *SettingsView) View() string {
	titleStyle := lipgloss.NewStyle().
		Foreground(s.theme.InfoColor).
		Bold(true).
		Padding(1, 2)

	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.Foreground).
		Bold(true).
		Width(20)

	// Cyan border with heavy characters when selected but not editing
	selectedStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.SelectionBg).
		Padding(0, 1)

	// Red border with heavy characters when actively editing
	editingStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.FocusedBorderColor).
		Padding(0, 1)

	unfocusedStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(s.theme.BorderColor).
		Padding(0, 1)

	var sections []string

	// Title
	sections = append(sections, titleStyle.Render("⚙ Settings"))

	// Capture Mode Selector (tab-style)
	modeStyle := unfocusedStyle
	if s.focusIndex == 0 {
		if s.editing {
			modeStyle = editingStyle
		} else {
			modeStyle = selectedStyle
		}
	}

	liveTabStyle := lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(s.theme.Foreground)
	offlineTabStyle := lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(s.theme.Foreground)
	remoteTabStyle := lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(s.theme.Foreground)

	switch s.captureMode {
	case CaptureModeLive:
		liveTabStyle = liveTabStyle.
			Background(s.theme.SelectionBg).
			Foreground(lipgloss.Color("0")).
			Bold(true)
	case CaptureModeOffline:
		offlineTabStyle = offlineTabStyle.
			Background(s.theme.SelectionBg).
			Foreground(lipgloss.Color("0")).
			Bold(true)
	case CaptureModeRemote:
		remoteTabStyle = remoteTabStyle.
			Background(s.theme.SelectionBg).
			Foreground(lipgloss.Color("0")).
			Bold(true)
	}

	modeSelector := lipgloss.JoinHorizontal(lipgloss.Left,
		liveTabStyle.Render("Live"),
		lipgloss.NewStyle().Render(" "),
		offlineTabStyle.Render("Offline"),
		lipgloss.NewStyle().Render(" "),
		remoteTabStyle.Render("Remote"),
	)

	sections = append(sections, modeStyle.Width(s.width-4).Render(
		labelStyle.Render("Capture Mode:")+" "+modeSelector,
	))

	// Mode-specific fields
	if s.captureMode == CaptureModeLive {
		// Interface selection
		ifaceSection := ""
		if s.focusIndex == 1 && s.editing {
			// Show full list when editing
			ifaceSection = editingStyle.Width(s.width - 4).Render(s.interfaceList.View())
		} else if s.focusIndex == 1 && !s.editing {
			// Show selected interfaces when focused but not editing
			selectedIfacesStr := s.GetInterface()
			ifaceSection = selectedStyle.Width(s.width - 4).Render(
				labelStyle.Render("Interfaces:") + " " + selectedIfacesStr,
			)
		} else {
			// Show selected interfaces when not focused
			selectedIfacesStr := s.GetInterface()
			ifaceSection = unfocusedStyle.Width(s.width - 4).Render(
				labelStyle.Render("Interfaces:") + " " + selectedIfacesStr,
			)
		}
		sections = append(sections, ifaceSection)

		// Promiscuous Mode
		promiscStyle := unfocusedStyle
		if s.focusIndex == 2 {
			if s.editing {
				promiscStyle = editingStyle
			} else {
				promiscStyle = selectedStyle
			}
		}
		promiscValue := "[ ]"
		if s.promiscuous {
			promiscValue = "[✓]"
		}
		sections = append(sections, promiscStyle.Width(s.width-4).Render(
			labelStyle.Render("Promiscuous Mode:")+" "+promiscValue,
		))
	} else if s.captureMode == CaptureModeOffline {
		// PCAP File
		fileStyle := unfocusedStyle
		if s.focusIndex == 1 {
			if s.editing {
				fileStyle = editingStyle
			} else {
				fileStyle = selectedStyle
			}
		}

		// Show file path (file dialog opens as modal on Enter/double-click)
		displayValue := s.inputs[inputPCAPFile].Value()
		if displayValue == "" {
			displayValue = "Click or press Enter to select file..."
		}
		sections = append(sections, fileStyle.Width(s.width-4).Render(
			labelStyle.Render("PCAP File:")+" "+displayValue,
		))
	} else if s.captureMode == CaptureModeRemote {
		// Nodes File input
		fileStyle := unfocusedStyle
		if s.focusIndex == 1 {
			if s.editing {
				fileStyle = editingStyle
			} else {
				fileStyle = selectedStyle
			}
		}

		if s.editing && s.focusIndex == 1 {
			// Show input field when editing
			sections = append(sections, fileStyle.Width(s.width-4).Render(
				labelStyle.Render("Nodes File:")+" "+s.inputs[inputNodesFile].View(),
			))
		} else {
			// Show value when not editing
			displayValue := s.inputs[inputNodesFile].Value()
			if displayValue == "" {
				displayValue = s.inputs[inputNodesFile].Placeholder
			}
			sections = append(sections, fileStyle.Width(s.width-4).Render(
				labelStyle.Render("Nodes File:")+" "+displayValue,
			))
		}
	}

	// Buffer Size (always visible)
	bufferStyle := unfocusedStyle
	bufferFocusIdx := 3
	if s.captureMode == CaptureModeOffline {
		bufferFocusIdx = 2
	} else if s.captureMode == CaptureModeRemote {
		bufferFocusIdx = 2
	}
	if s.focusIndex == bufferFocusIdx {
		if s.editing {
			bufferStyle = editingStyle
		} else {
			bufferStyle = selectedStyle
		}
	}
	sections = append(sections, bufferStyle.Width(s.width-4).Render(
		labelStyle.Render("Buffer Size:")+" "+s.inputs[inputBufferSize].View(),
	))

	// Capture Filter (only visible in Live and Offline modes, not Remote)
	if s.captureMode != CaptureModeRemote {
		filterStyle := unfocusedStyle
		filterFocusIdx := 4
		if s.captureMode == CaptureModeOffline {
			filterFocusIdx = 3
		}
		if s.focusIndex == filterFocusIdx {
			if s.editing {
				filterStyle = editingStyle
			} else {
				filterStyle = selectedStyle
			}
		}
		sections = append(sections, filterStyle.Width(s.width-4).Render(
			labelStyle.Render("Capture Filter:")+" "+s.inputs[inputBPFFilter].View(),
		))
	}

	// Error message (if any)
	if s.errorMessage != "" {
		errorStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")). // Red
			Bold(true).
			Padding(0, 2)
		sections = append(sections, errorStyle.Render("⚠ "+s.errorMessage))
	}

	// Help text
	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Italic(true).
		Padding(1, 2)

	helpText := "j/k: navigate • h/l: switch mode • Enter: edit/toggle • Tab: switch tabs"
	if s.editing {
		if s.focusIndex == 1 && s.captureMode == CaptureModeLive {
			helpText = "Editing interfaces (/: filter, ↑↓: navigate, Space: toggle, Enter: confirm, Esc: cancel)"
		} else {
			helpText = "Editing field (Enter/Esc: finish)"
		}
	}
	sections = append(sections, helpStyle.Render(helpText))

	// Note about applying settings
	noteStyle := lipgloss.NewStyle().
		Foreground(s.theme.InfoColor).
		Padding(0, 2)

	noteText := "Note: Changes to mode, interface, PCAP file, or BPF filter trigger capture restart"
	sections = append(sections, noteStyle.Render(noteText))

	// Additional help text explaining filters
	helpTextStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Padding(0, 2)

	filterHelp := "Capture Filter (BPF): Kernel-level filtering, only matching packets captured\nDisplay Filter (/): Application-level filtering, all packets captured but filtered in view"
	sections = append(sections, helpTextStyle.Render(filterHelp))

	content := lipgloss.JoinVertical(lipgloss.Left, sections...)

	// Use viewport for scrolling if content is too tall
	if s.viewportReady {
		s.viewport.SetContent(content)
		return s.viewport.View()
	}

	return content
}

// IsFileDialogActive returns whether any file dialog is currently shown
func (s *SettingsView) IsFileDialogActive() bool {
	return s.pcapFileDialog.IsActive() || s.nodesFileDialog.IsActive()
}

// GetPcapFileDialog returns the PCAP file dialog for rendering at the top level
func (s *SettingsView) GetPcapFileDialog() *FileDialog {
	return &s.pcapFileDialog
}

// GetNodesFileDialog returns the nodes file dialog for rendering at the top level
func (s *SettingsView) GetNodesFileDialog() *FileDialog {
	return &s.nodesFileDialog
}

// scrollToFocusedField adjusts viewport to keep focused field visible
func (s *SettingsView) scrollToFocusedField() {
	if !s.viewportReady {
		return
	}

	// Rough estimate: each field is about 3-4 lines tall
	// Title (1) + Mode (3) + Interface (3) + Promiscuous (3) + Buffer (3) + Filter (3) + Help (2) + Note (2) = ~20 lines total
	// We'll approximate the Y position based on focusIndex
	linesPerField := 3
	estimatedY := s.focusIndex * linesPerField

	// Scroll to make sure the focused field is visible
	// If it's below the viewport, scroll down
	if estimatedY > s.viewport.YOffset+s.viewport.Height-3 {
		s.viewport.SetYOffset(estimatedY - s.viewport.Height + 3)
	}
	// If it's above the viewport, scroll up
	if estimatedY < s.viewport.YOffset {
		s.viewport.SetYOffset(estimatedY)
	}
}

// GetSettings returns all current settings as a formatted string
func (s *SettingsView) GetSettings() string {
	var settings []string
	modeStr := "Live"
	switch s.captureMode {
	case CaptureModeOffline:
		modeStr = "Offline"
	case CaptureModeRemote:
		modeStr = "Remote"
	}
	settings = append(settings, fmt.Sprintf("Mode: %s", modeStr))
	if s.captureMode == CaptureModeLive {
		settings = append(settings, fmt.Sprintf("Interface: %s", s.GetInterface()))
		settings = append(settings, fmt.Sprintf("Promiscuous: %t", s.GetPromiscuous()))
	} else if s.captureMode == CaptureModeRemote {
		settings = append(settings, fmt.Sprintf("Nodes File: %s", s.inputs[inputNodesFile].Value()))
	} else {
		settings = append(settings, fmt.Sprintf("PCAP File: %s", s.GetPCAPFile()))
	}
	settings = append(settings, fmt.Sprintf("Buffer Size: %d", s.GetBufferSize()))
	settings = append(settings, fmt.Sprintf("BPF Filter: %s", s.GetBPFFilter()))
	return strings.Join(settings, "\n")
}
