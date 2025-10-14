//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/components/settings"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/spf13/viper"
)

// Type aliases for backward compatibility with model.go and header.go
type CaptureMode = settings.CaptureMode

const (
	CaptureModeLive    = settings.CaptureModeLive
	CaptureModeOffline = settings.CaptureModeOffline
	CaptureModeRemote  = settings.CaptureModeRemote
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

// UpdateBufferSizeMsg is sent when buffer size changes
type UpdateBufferSizeMsg = settings.UpdateBufferSizeMsg

// LoadNodesMsg is sent when nodes should be loaded from YAML file
type LoadNodesMsg struct {
	FilePath string
}

// SettingsView displays settings configuration
type SettingsView struct {
	width           int
	height          int
	theme           themes.Theme
	currentMode     settings.ModeSettings
	modeType        settings.CaptureMode
	factory         *settings.ModeFactory
	focusIndex      int
	editing         bool
	errorMessage    string
	viewport        viewport.Model
	viewportReady   bool
	pcapFileDialog  FileDialog
	nodesFileDialog FileDialog
	lastClickField  int
	lastClickTime   time.Time
}

// NewSettingsView creates a new settings view component
func NewSettingsView(currentInterface string, currentBufferSize int, currentPromiscuous bool, currentFilter string, currentPCAPFile string) SettingsView {
	// Create factory with initial theme
	theme := themes.Solarized()
	factory := settings.NewModeFactory(theme)

	// Determine initial mode based on whether pcap file was provided
	modeType := settings.CaptureModeLive
	if currentPCAPFile != "" {
		modeType = settings.CaptureModeOffline
	}

	// Create initial mode using factory
	currentMode := factory.CreateMode(
		modeType,
		currentBufferSize,
		currentFilter,
		currentInterface,
		currentPromiscuous,
		currentPCAPFile,
		"", // nodesFile
	)

	// Initialize viewport
	vp := viewport.New(80, 24)
	vp.Style = lipgloss.NewStyle()

	// Initialize PCAP file dialog - start in ./captures if it exists, otherwise current dir
	pcapStartDir := "./captures"
	if _, err := os.Stat(pcapStartDir); os.IsNotExist(err) {
		pcapStartDir, _ = os.Getwd()
	}
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
	nodesFileDialog := NewOpenFileDialog(nodesStartDir, []string{".yaml", ".yml"}, false)

	return SettingsView{
		width:           80,
		height:          24,
		theme:           theme,
		currentMode:     currentMode,
		modeType:        modeType,
		factory:         factory,
		focusIndex:      0,
		editing:         false,
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
	if s.currentMode != nil {
		s.currentMode.UpdateTheme(theme)
	}
	if s.factory != nil {
		s.factory.UpdateTheme(theme)
	}
	s.pcapFileDialog.SetTheme(theme)
	s.nodesFileDialog.SetTheme(theme)
}

// SetCaptureMode sets the capture mode
func (s *SettingsView) SetCaptureMode(mode settings.CaptureMode) {
	if s.modeType != mode {
		s.modeType = mode
		s.currentMode = s.factory.SwitchMode(mode, s.currentMode)
	}
}

// SetNodesFile sets the nodes file path for remote mode
func (s *SettingsView) SetNodesFile(path string) {
	// Create a new remote mode with the specified file
	if s.modeType == settings.CaptureModeRemote {
		bufferSize := s.currentMode.GetBufferSize()
		s.currentMode = s.factory.CreateMode(
			settings.CaptureModeRemote,
			bufferSize,
			"",    // filter
			"",    // interface
			false, // promiscuous
			"",    // pcapFile
			path,  // nodesFile
		)
	}
}

// SetSize sets the view dimensions
func (s *SettingsView) SetSize(width, height int) {
	s.width = width
	s.height = height

	// Update file dialogs size
	s.pcapFileDialog.SetSize(width, height)
	s.nodesFileDialog.SetSize(width, height)

	// Update viewport size
	s.viewport.Width = width
	s.viewport.Height = height
	s.viewportReady = true

	// Update mode size
	s.currentMode.SetSize(width, height)
}

// GetBufferSize returns the configured buffer size
func (s *SettingsView) GetBufferSize() int {
	return s.currentMode.GetBufferSize()
}

// GetBPFFilter returns the configured BPF filter
func (s *SettingsView) GetBPFFilter() string {
	return s.currentMode.GetBPFFilter()
}

// GetPCAPFile returns the configured PCAP file path
func (s *SettingsView) GetPCAPFile() string {
	if s.modeType == settings.CaptureModeOffline {
		msg := s.currentMode.ToRestartMsg()
		return msg.PCAPFile
	}
	return ""
}

// GetInterface returns the selected interfaces as comma-separated string
func (s *SettingsView) GetInterface() string {
	if s.modeType == settings.CaptureModeLive {
		msg := s.currentMode.ToRestartMsg()
		return msg.Interface
	}
	return "any"
}

// GetPromiscuous returns the promiscuous mode setting
func (s *SettingsView) GetPromiscuous() bool {
	if s.modeType == settings.CaptureModeLive {
		msg := s.currentMode.ToRestartMsg()
		return msg.Promiscuous
	}
	return false
}

// GetCaptureMode returns the current capture mode
func (s *SettingsView) GetCaptureMode() settings.CaptureMode {
	return s.modeType
}

// IsEditing returns whether the settings view is in editing mode
func (s *SettingsView) IsEditing() bool {
	return s.editing
}

// IsEditingInterface returns whether the interface list is being edited
func (s *SettingsView) IsEditingInterface() bool {
	// Interface editing is when in live mode, focused on field 1 (interface), and editing
	return s.modeType == settings.CaptureModeLive && s.focusIndex == 1 && s.editing
}

// HasChanges returns true if settings differ from initial values
func (s *SettingsView) HasChanges(currentInterface string) bool {
	return s.GetInterface() != currentInterface
}

// validateSettings validates the current settings before restart
func (s *SettingsView) validateSettings() error {
	return s.currentMode.Validate()
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

	// Convert mode's settings.RestartCaptureMsg to components.RestartCaptureMsg
	modeMsg := s.currentMode.ToRestartMsg()
	return func() tea.Msg {
		return RestartCaptureMsg{
			Mode:        s.modeType,
			Interface:   modeMsg.Interface,
			PCAPFile:    modeMsg.PCAPFile,
			NodesFile:   modeMsg.NodesFile,
			Filter:      modeMsg.Filter,
			BufferSize:  modeMsg.BufferSize,
			Promiscuous: modeMsg.Promiscuous,
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
			if err := os.MkdirAll(configDir, 0750); err != nil {
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
	// Mode selector (0) + mode-specific fields
	return s.currentMode.GetFocusableFieldCount() + 1
}

// Update handles messages
func (s *SettingsView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd

	// Handle FileSelectedMsg from file dialogs
	if fileMsg, ok := msg.(FileSelectedMsg); ok {
		fullPath := fileMsg.Path()
		s.errorMessage = ""

		// Determine which dialog sent this based on current capture mode
		if s.modeType == settings.CaptureModeOffline || s.pcapFileDialog.IsActive() {
			// PCAP file selected - create new offline mode with file
			bufferSize := s.currentMode.GetBufferSize()
			filter := s.currentMode.GetBPFFilter()
			s.currentMode = s.factory.CreateMode(
				settings.CaptureModeOffline,
				bufferSize,
				filter,
				"",    // interface
				false, // promiscuous
				fullPath,
				"", // nodesFile
			)
			s.modeType = settings.CaptureModeOffline
		} else if s.modeType == settings.CaptureModeRemote || s.nodesFileDialog.IsActive() {
			// Nodes YAML file selected - create new remote mode with file
			bufferSize := s.currentMode.GetBufferSize()
			s.currentMode = s.factory.CreateMode(
				settings.CaptureModeRemote,
				bufferSize,
				"",    // filter
				"",    // interface
				false, // promiscuous
				"",    // pcapFile
				fullPath,
			)
			s.modeType = settings.CaptureModeRemote
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

	// Route to mode if it's editing (e.g., interface list, text inputs)
	if s.editing {
		// Special handling for LiveSettings interface list editing (focusIndex 1)
		if s.modeType == settings.CaptureModeLive && s.focusIndex == 1 {
			// Type assert to LiveSettings to call UpdateInterfaceList
			if liveMode, ok := s.currentMode.(*settings.LiveSettings); ok {
				shouldExit, cmd := liveMode.UpdateInterfaceList(msg, s.theme)
				if shouldExit {
					s.editing = false
					// Trigger restart when exiting interface editing
					return s.restartCapture()
				}
				return cmd
			}
		}

		// Check for Enter/Esc keys - these need special handling via HandleKey
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "enter", "esc":
				// Handle via mode's HandleKey method
				result := s.currentMode.HandleKey(keyMsg.String(), settings.KeyHandlerParams{
					FocusIndex: s.focusIndex,
					Editing:    s.editing,
				})

				// Update editing state
				s.editing = result.Editing

				// Handle special actions
				if result.TriggerRestart {
					return s.restartCapture()
				}
				if result.TriggerBufferUpdate {
					return func() tea.Msg {
						return settings.UpdateBufferSizeMsg{Size: s.GetBufferSize()}
					}
				}
				if result.ErrorMessage != "" {
					s.errorMessage = result.ErrorMessage
				}
				if result.Cmd != nil {
					return result.Cmd
				}
				return nil
			}
		}

		// For other keys, use standard Update to pass to text inputs
		cmd = s.currentMode.Update(msg, s.focusIndex)
		return cmd
	}

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// Handle mouse clicks for focusing different settings
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			// Calculate which setting was clicked based on Y position
			relativeY := msg.Y - 6

			// Exit edit mode if clicking outside the currently editing field
			if s.editing && relativeY >= 0 {
				clickedField := s.determineClickedField(relativeY, msg.X)

				// If clicking on a different field (not empty space), exit edit mode
				if clickedField >= 0 && clickedField != s.focusIndex {
					s.editing = false
				}
			}

			if relativeY >= 0 { // Within settings area
				// Handle mode tab clicks (relativeY 2-4)
				if relativeY >= 2 && relativeY <= 4 {
					newMode := s.determineClickedMode(msg.X)
					if newMode != s.modeType {
						s.modeType = newMode
						s.currentMode = s.factory.SwitchMode(newMode, s.currentMode)
						return s.restartCapture()
					}
					s.focusIndex = 0 // Mode selector
				} else {
					// Determine which field was clicked based on Y position
					// Delegate to mode-specific logic
					// For now, just set the focus index based on relative Y
					// Each mode has different field layouts
					// TODO: Move this logic into mode-specific methods
					if relativeY >= 5 && relativeY <= 7 {
						s.focusIndex = 1
					} else if relativeY >= 8 && relativeY <= 10 {
						s.focusIndex = 2
					} else if relativeY >= 11 && relativeY <= 13 {
						s.focusIndex = 3
					} else if relativeY >= 14 && relativeY <= 16 {
						s.focusIndex = 4
					}
				}
			}
		}

		// Handle double-click to enter edit mode on input fields
		if msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			relativeY := msg.Y - 6
			now := time.Now()
			const doubleClickThreshold = 500 * time.Millisecond

			clickedField := s.determineClickedField(relativeY, msg.X)

			// Check if this is a double-click on the same field
			if clickedField >= 0 && clickedField == s.lastClickField &&
				now.Sub(s.lastClickTime) < doubleClickThreshold && !s.editing {

				// Handle double-click based on mode and field
				// For offline/remote mode field 1 (file path), open file dialog
				if s.modeType == settings.CaptureModeOffline && clickedField == 1 {
					s.pcapFileDialog.Activate()
					return nil
				} else if s.modeType == settings.CaptureModeRemote && clickedField == 1 {
					s.nodesFileDialog.Activate()
					return nil
				} else {
					// For other fields, enter edit mode
					s.editing = true
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
				// Cycle through modes
				oldMode := s.modeType
				switch s.modeType {
				case settings.CaptureModeLive:
					s.modeType = settings.CaptureModeOffline
				case settings.CaptureModeOffline:
					s.modeType = settings.CaptureModeRemote
				case settings.CaptureModeRemote:
					s.modeType = settings.CaptureModeLive
				}

				// Trigger restart if mode changed
				if oldMode != s.modeType {
					s.currentMode = s.factory.SwitchMode(s.modeType, s.currentMode)
					return s.restartCapture()
				}
				return nil
			}

			// For mode-specific fields, delegate to mode's HandleKey
			result := s.currentMode.HandleKey("enter", settings.KeyHandlerParams{
				FocusIndex: s.focusIndex,
				Editing:    s.editing,
			})

			// Update editing state
			s.editing = result.Editing

			// Handle special actions
			if result.OpenFileDialog {
				if s.modeType == settings.CaptureModeOffline {
					return s.pcapFileDialog.Activate()
				} else if s.modeType == settings.CaptureModeRemote {
					return s.nodesFileDialog.Activate()
				}
			}
			if result.ErrorMessage != "" {
				s.errorMessage = result.ErrorMessage
			} else if result.ErrorMessage == "" {
				s.errorMessage = ""
			}
			if result.TriggerRestart {
				return s.restartCapture()
			}
			if result.TriggerBufferUpdate {
				return func() tea.Msg {
					return settings.UpdateBufferSizeMsg{Size: s.GetBufferSize()}
				}
			}
			if result.Cmd != nil {
				return result.Cmd
			}
			return nil

		case "j", "down":
			if s.editing {
				cmd = s.currentMode.Update(msg, s.focusIndex)
				return cmd
			}

			// When not editing, navigate to next field
			if !s.editing {
				maxIdx := s.getMaxFocusIndex()
				s.focusIndex = (s.focusIndex + 1) % maxIdx
				s.scrollToFocusedField()
			}
			return nil

		case "k", "up":
			if s.editing {
				cmd = s.currentMode.Update(msg, s.focusIndex)
				return cmd
			}

			// When not editing, navigate to previous field
			if !s.editing {
				maxIdx := s.getMaxFocusIndex()
				s.focusIndex = (s.focusIndex - 1 + maxIdx) % maxIdx
				s.scrollToFocusedField()
			}
			return nil

		case "left", "h":
			if s.editing {
				cmd = s.currentMode.Update(msg, s.focusIndex)
				return cmd
			}

			// Previous mode when focused on mode selector (and not editing)
			if s.focusIndex == 0 && !s.editing {
				oldMode := s.modeType
				switch s.modeType {
				case settings.CaptureModeLive:
					s.modeType = settings.CaptureModeRemote
				case settings.CaptureModeOffline:
					s.modeType = settings.CaptureModeLive
				case settings.CaptureModeRemote:
					s.modeType = settings.CaptureModeOffline
				}
				if oldMode != s.modeType {
					s.currentMode = s.factory.SwitchMode(s.modeType, s.currentMode)
					return s.restartCapture()
				}
			}
			return nil

		case "right", "l":
			if s.editing {
				cmd = s.currentMode.Update(msg, s.focusIndex)
				return cmd
			}

			// Next mode when focused on mode selector (and not editing)
			if s.focusIndex == 0 && !s.editing {
				oldMode := s.modeType
				switch s.modeType {
				case settings.CaptureModeLive:
					s.modeType = settings.CaptureModeOffline
				case settings.CaptureModeOffline:
					s.modeType = settings.CaptureModeRemote
				case settings.CaptureModeRemote:
					s.modeType = settings.CaptureModeLive
				}
				if oldMode != s.modeType {
					s.currentMode = s.factory.SwitchMode(s.modeType, s.currentMode)
					return s.restartCapture()
				}
			}
			return nil

		case "esc":
			// Delegate to mode's HandleKey
			result := s.currentMode.HandleKey("esc", settings.KeyHandlerParams{
				FocusIndex: s.focusIndex,
				Editing:    s.editing,
			})

			// Update editing state
			s.editing = result.Editing

			// Handle special actions
			if result.TriggerRestart {
				return s.restartCapture()
			}
			if result.TriggerBufferUpdate {
				return func() tea.Msg {
					return settings.UpdateBufferSizeMsg{Size: s.GetBufferSize()}
				}
			}
			if result.Cmd != nil {
				return result.Cmd
			}
			return nil
		}
	}

	// Pass other keys to mode when in editing mode
	if s.editing {
		cmd = s.currentMode.Update(msg, s.focusIndex)
		return cmd
	}

	// Handle tea.WindowSizeMsg
	if windowMsg, ok := msg.(tea.WindowSizeMsg); ok {
		s.SetSize(windowMsg.Width, windowMsg.Height)
	}

	return nil
}

// determineClickedMode returns the mode based on X position in mode tabs
func (s *SettingsView) determineClickedMode(x int) settings.CaptureMode {
	// "Live" is approximately at X 20-31, "Offline" at X 32-42, "Remote" at X 43-50
	if x >= 20 && x <= 31 {
		return settings.CaptureModeLive
	} else if x >= 32 && x <= 42 {
		return settings.CaptureModeOffline
	} else if x >= 43 && x <= 50 {
		return settings.CaptureModeRemote
	}
	return s.modeType // No change
}

// determineClickedField returns which field was clicked based on Y position
func (s *SettingsView) determineClickedField(relativeY, x int) int {
	// Mode tabs at relativeY 2-4
	if relativeY >= 2 && relativeY <= 4 {
		return 0
	}

	// Field-specific logic based on Y position
	// This is a simplified version - each mode may have different layouts
	if relativeY >= 5 && relativeY <= 7 {
		return 1
	} else if relativeY >= 8 && relativeY <= 10 {
		return 2
	} else if relativeY >= 11 && relativeY <= 13 {
		return 3
	} else if relativeY >= 14 && relativeY <= 16 {
		return 4
	}

	return -1
}

// View renders the settings view
func (s *SettingsView) View() string {
	noteStyle := lipgloss.NewStyle().
		Foreground(s.theme.InfoColor).
		Padding(1, 2)

	var sections []string

	// Note about changes triggering restart
	sections = append(sections, noteStyle.Render("Note: Changes to mode, interface, PCAP file, or BPF filter trigger capture restart"))

	// Capture Mode Selector (tab-style)
	sections = append(sections, s.renderModeSelector())

	// Create styles for mode rendering
	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.Foreground).
		Bold(true).
		Width(20)

	selectedStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.SelectionBg).
		Padding(0, 1)

	editingStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.FocusedBorderColor).
		Padding(0, 1)

	unfocusedStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(s.theme.BorderColor).
		Padding(0, 1)

	// Get mode-specific sections
	modeParams := settings.RenderParams{
		Width:          s.width,
		FocusIndex:     s.focusIndex,
		Editing:        s.editing,
		Theme:          s.theme,
		LabelStyle:     labelStyle,
		SelectedStyle:  selectedStyle,
		EditingStyle:   editingStyle,
		UnfocusedStyle: unfocusedStyle,
	}
	modeSections := s.currentMode.Render(modeParams)
	sections = append(sections, modeSections...)

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
	sections = append(sections, helpStyle.Render(helpText))

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

// renderModeSelector renders the mode selection tabs
func (s *SettingsView) renderModeSelector() string {
	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.Foreground).
		Bold(true).
		Width(20)

	// Border styles
	selectedStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.SelectionBg).
		Padding(0, 1)

	editingStyle := lipgloss.NewStyle().
		Border(lipgloss.ThickBorder()).
		BorderForeground(s.theme.FocusedBorderColor).
		Padding(0, 1)

	unfocusedStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(s.theme.BorderColor).
		Padding(0, 1)

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

	switch s.modeType {
	case settings.CaptureModeLive:
		liveTabStyle = liveTabStyle.
			Background(s.theme.SelectionBg).
			Foreground(lipgloss.Color("0")).
			Bold(true)
	case settings.CaptureModeOffline:
		offlineTabStyle = offlineTabStyle.
			Background(s.theme.SelectionBg).
			Foreground(lipgloss.Color("0")).
			Bold(true)
	case settings.CaptureModeRemote:
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

	return modeStyle.Width(s.width - 4).Render(
		labelStyle.Render("Capture Mode:") + " " + modeSelector,
	)
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
	modeStr := "Live"
	switch s.modeType {
	case settings.CaptureModeOffline:
		modeStr = "Offline"
	case settings.CaptureModeRemote:
		modeStr = "Remote"
	}

	// Get mode-specific details
	msg := s.currentMode.ToRestartMsg()
	details := ""
	if s.modeType == settings.CaptureModeLive {
		details = fmt.Sprintf("Interface: %s\nPromiscuous: %t", msg.Interface, msg.Promiscuous)
	} else if s.modeType == settings.CaptureModeOffline {
		details = fmt.Sprintf("PCAP File: %s", msg.PCAPFile)
	} else if s.modeType == settings.CaptureModeRemote {
		details = fmt.Sprintf("Nodes File: %s", msg.NodesFile)
	}

	return fmt.Sprintf("Mode: %s\n%s\nBuffer Size: %d\nBPF Filter: %s",
		modeStr,
		details,
		s.GetBufferSize(),
		s.GetBPFFilter(),
	)
}
