//go:build tui || all

package settings

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ModeSettings defines the interface that all capture mode settings must implement.
//
// This interface enables polymorphic handling of different capture modes (Live, Offline, Remote)
// without conditional logic in the parent SettingsView component. Each mode encapsulates its own:
// - State (fields, inputs, selections)
// - Validation rules
// - Rendering logic
// - Input handling
//
// Benefits:
// - Easy to test modes in isolation
// - Easy to add new capture modes
// - Eliminates mode-specific conditionals
// - Clear separation of concerns
type ModeSettings interface {
	// Validate checks if the current settings are valid.
	// Returns an error describing what's invalid, or nil if valid.
	Validate() error

	// ToRestartMsg converts the current settings to a RestartCaptureMsg.
	// This is called when the user confirms settings and wants to restart capture.
	ToRestartMsg() RestartCaptureMsg

	// Render renders the mode-specific UI fields.
	// Returns a slice of rendered section strings to be appended to the main view.
	// The parent SettingsView handles common UI (title, mode selector, help text).
	Render(params RenderParams) []string

	// HandleKey handles keyboard input for mode-specific fields.
	// The parent SettingsView handles mode switching and common navigation.
	// Returns a KeyHandlerResult indicating what actions to take.
	HandleKey(key string, params KeyHandlerParams) KeyHandlerResult

	// GetFocusableFieldCount returns the number of focusable fields for this mode.
	// Used to calculate the max focus index for navigation.
	// Does NOT include the mode selector itself (that's handled by parent).
	GetFocusableFieldCount() int

	// GetBufferSize returns the configured buffer size.
	// Used by the parent to access this common field across all modes.
	GetBufferSize() int

	// GetBPFFilter returns the configured BPF filter.
	// May return empty string for modes that don't support BPF filtering.
	GetBPFFilter() string

	// SetSize updates sizes for any UI components (lists, dialogs, etc.).
	// Called when the terminal window is resized.
	SetSize(width, height int)

	// UpdateTheme updates the theme for any themed components.
	// Called when the user switches themes.
	UpdateTheme(theme themes.Theme)

	// Update passes bubbletea messages to mode-specific components when editing.
	// Used to update text inputs, lists, etc.
	// Returns a tea.Cmd if the mode component needs to send commands.
	Update(msg tea.Msg, focusIndex int) tea.Cmd

	// FocusField focuses the text input at the given field index.
	// Used when entering edit mode via mouse double-click.
	// Does nothing for non-text-input fields (toggles, lists, etc.).
	FocusField(fieldIndex int)
}

// RestartCaptureMsg is sent when capture needs to be restarted with new settings.
type RestartCaptureMsg struct {
	Mode        int      // 0=Live, 1=Offline, 2=Remote
	Interface   string   // Comma-separated interface names (live mode)
	PCAPFiles   []string // Paths to PCAP files (offline mode)
	NodesFile   string   // Path to nodes YAML file (remote mode)
	Filter      string   // BPF filter expression
	BufferSize  int      // Packet buffer size
	Promiscuous bool     // Promiscuous mode enabled (live mode)
}

// RenderParams contains parameters needed for rendering mode-specific fields.
type RenderParams struct {
	Width          int            // Terminal width
	FocusIndex     int            // Current focus index (0=mode selector, 1+=mode fields)
	Editing        bool           // Whether currently editing a field
	Theme          themes.Theme   // Current theme
	LabelStyle     lipgloss.Style // Style for field labels
	SelectedStyle  lipgloss.Style // Style for focused (not editing) fields
	EditingStyle   lipgloss.Style // Style for actively editing fields
	UnfocusedStyle lipgloss.Style // Style for unfocused fields
}

// KeyHandlerParams contains parameters for handling keyboard input.
type KeyHandlerParams struct {
	FocusIndex int  // Current focus index (0=mode selector, 1+=mode fields)
	Editing    bool // Whether currently editing a field
}

// KeyHandlerResult contains the result of handling keyboard input.
type KeyHandlerResult struct {
	Editing             bool    // New editing state
	TriggerRestart      bool    // Should trigger capture restart
	TriggerBufferUpdate bool    // Should trigger buffer size update
	OpenFileDialog      bool    // Should open file dialog
	ErrorMessage        string  // Error message to display (empty = clear error)
	Cmd                 tea.Cmd // Optional bubbletea command to execute
}

// Focus index constants.
const (
	// FocusIndexModeSelector is the focus index for the mode selector.
	FocusIndexModeSelector = 0

	// FocusIndexFirstField is the focus index for the first mode-specific field.
	// Mode implementations should use 1, 2, 3, ... for their fields.
	FocusIndexFirstField = 1
)

// UpdateBufferSizeMsg is sent when buffer size changes.
// This is defined here to avoid import cycles.
type UpdateBufferSizeMsg struct {
	Size int
}
