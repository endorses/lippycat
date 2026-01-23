//go:build tui || all

package store

import (
	"os"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// UIState manages UI components and state
type UIState struct {
	mu sync.RWMutex

	// UI Components
	PacketList       components.PacketList
	DetailsPanel     components.DetailsPanel
	Header           components.Header
	Footer           components.Footer
	Tabs             components.Tabs
	NodesView        *components.NodesView
	StatisticsView   components.StatisticsView
	SettingsView     components.SettingsView
	HelpView         components.HelpView
	CallsView        *components.CallsView
	DNSQueriesView   *components.DNSQueriesView
	EmailView        *components.EmailView
	HTTPView         *components.HTTPView
	ProtocolSelector components.ProtocolSelector
	HunterSelector   components.HunterSelector
	FilterManager    components.FilterManager
	FilterInput      components.FilterInput
	FileDialog       components.FileDialog
	ConfirmDialog    components.ConfirmDialog
	Toast            components.Toast
	Statistics       *components.Statistics

	// UI State
	Capturing        bool
	Paused           bool
	Width            int
	Height           int
	Quitting         bool
	Theme            themes.Theme
	FilterMode       bool
	CallFilterMode   bool // Filter mode for calls view
	CallFilterInput  components.FilterInput
	ShowDetails      bool
	FocusedPane      string // "left" (packet list) or "right" (details/hex)
	NeedsUIUpdate    bool
	SelectedProtocol components.Protocol
	ViewMode         string // "packets" or "calls" (for VoIP)
	LastClickTime    time.Time
	LastClickPacket  int
	LastKeyPress     string    // Track last key for vim-style navigation (gg)
	LastKeyPressTime time.Time // Timestamp of last key press

	// Save State
	SaveInProgress bool // One-shot save in progress
	StreamingSave  bool // Streaming save active
}

// NewUIState creates a new UI state with default components
func NewUIState(theme themes.Theme) *UIState {
	packetList := components.NewPacketList()
	packetList.SetTheme(theme)

	detailsPanel := components.NewDetailsPanel()
	detailsPanel.SetTheme(theme)

	header := components.NewHeader()
	header.SetTheme(theme)

	footer := components.NewFooter()
	footer.SetTheme(theme)

	tabs := components.NewTabs([]components.Tab{
		{Label: "Live Capture", ShortLabel: "Capture", Icon: "📡"},
		{Label: "Nodes", ShortLabel: "Nodes", Icon: "🔗"},
		{Label: "Statistics", ShortLabel: "Stats", Icon: "📊"},
		{Label: "Settings", ShortLabel: "Settings", Icon: "🔧"},
		{Label: "Help", ShortLabel: "Help", Icon: "?"},
	})
	tabs.SetTheme(theme)

	nodesView := components.NewNodesView()
	nodesView.SetTheme(theme)

	statisticsView := components.NewStatisticsView()
	statisticsView.SetTheme(theme)

	helpView := components.NewHelpView()
	helpView.SetTheme(theme)

	// SettingsView will be initialized by caller with proper parameters
	// (interface, bufferSize, promiscuous, bpfFilter, pcapFile)
	settingsView := components.SettingsView{}
	settingsView.SetTheme(theme)

	callsView := components.NewCallsView()
	callsView.SetTheme(theme)

	dnsQueriesView := components.NewDNSQueriesView()
	dnsQueriesView.SetTheme(theme)

	emailView := components.NewEmailView()
	emailView.SetTheme(theme)

	httpView := components.NewHTTPView()
	httpView.SetTheme(theme)

	protocolSelector := components.NewProtocolSelector()
	protocolSelector.SetTheme(theme)

	hunterSelector := components.NewHunterSelector()
	hunterSelector.SetTheme(theme)

	filterManager := components.NewFilterManager()
	filterManager.SetTheme(theme)

	filterInput := components.NewFilterInput("/")
	filterInput.SetTheme(theme)

	callFilterInput := components.NewFilterInput("/")
	callFilterInput.SetTheme(theme)

	// Initialize FileDialog for saving PCAP files
	// Use current working directory
	var initialPath string
	if cwd, err := os.Getwd(); err == nil {
		initialPath = cwd
	} else {
		initialPath = "."
	}
	fileDialog := components.NewSaveFileDialog(initialPath, "", []string{".pcap", ".pcapng"})
	fileDialog.SetTheme(theme)

	toast := components.NewToast()
	toast.SetTheme(theme)

	confirmDialog := components.NewConfirmDialog()
	confirmDialog.SetTheme(theme)

	nodesViewPtr := &nodesView

	return &UIState{
		PacketList:       packetList,
		DetailsPanel:     detailsPanel,
		Header:           header,
		Footer:           footer,
		Tabs:             tabs,
		NodesView:        nodesViewPtr,
		StatisticsView:   statisticsView,
		SettingsView:     settingsView,
		HelpView:         helpView,
		CallsView:        &callsView, // Use pointer to avoid copying mutex
		DNSQueriesView:   dnsQueriesView,
		EmailView:        emailView,
		HTTPView:         httpView,
		ProtocolSelector: protocolSelector,
		HunterSelector:   hunterSelector,
		FilterManager:    filterManager,
		FilterInput:      filterInput,
		CallFilterInput:  callFilterInput,
		FileDialog:       fileDialog,
		ConfirmDialog:    confirmDialog,
		Toast:            toast,
		Statistics:       nil, // Initialized separately by caller
		Capturing:        false,
		Paused:           false,
		Width:            120, // Reasonable default until WindowSizeMsg arrives
		Height:           40,  // Reasonable default until WindowSizeMsg arrives
		Quitting:         false,
		Theme:            theme,
		FilterMode:       false,
		CallFilterMode:   false,
		ShowDetails:      false,
		FocusedPane:      "left",
		NeedsUIUpdate:    false,
		SelectedProtocol: components.Protocol{Name: "All", BPFFilter: ""}, // Default to "All"
		ViewMode:         "packets",
	}
}

// SetTheme updates the theme for all UI components
func (ui *UIState) SetTheme(theme themes.Theme) {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	ui.Theme = theme
	ui.PacketList.SetTheme(theme)
	ui.DetailsPanel.SetTheme(theme)
	ui.Header.SetTheme(theme)
	ui.Footer.SetTheme(theme)
	ui.Tabs.SetTheme(theme)
	ui.NodesView.SetTheme(theme)
	ui.StatisticsView.SetTheme(theme)
	ui.SettingsView.SetTheme(theme)
	ui.HelpView.SetTheme(theme)
	ui.CallsView.SetTheme(theme)
	ui.DNSQueriesView.SetTheme(theme)
	ui.EmailView.SetTheme(theme)
	ui.HTTPView.SetTheme(theme)
	ui.ProtocolSelector.SetTheme(theme)
	ui.FilterInput.SetTheme(theme)
	ui.CallFilterInput.SetTheme(theme)
	ui.Toast.SetTheme(theme)
}

// SetSize updates terminal dimensions
func (ui *UIState) SetSize(width, height int) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.Width = width
	ui.Height = height
}

// GetSize returns terminal dimensions
func (ui *UIState) GetSize() (width, height int) {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.Width, ui.Height
}

// TogglePause toggles the pause state
func (ui *UIState) TogglePause() bool {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.Paused = !ui.Paused
	return ui.Paused
}

// SetPaused sets the pause state
func (ui *UIState) SetPaused(paused bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.Paused = paused
}

// IsPaused returns whether display is paused
func (ui *UIState) IsPaused() bool {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.Paused
}

// SetCapturing sets the capturing state
func (ui *UIState) SetCapturing(capturing bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.Capturing = capturing
}

// IsCapturing returns whether capture is active
func (ui *UIState) IsCapturing() bool {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.Capturing
}

// SetQuitting sets the quitting flag
func (ui *UIState) SetQuitting(quitting bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.Quitting = quitting
}

// IsQuitting returns whether we're quitting
func (ui *UIState) IsQuitting() bool {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.Quitting
}

// ToggleDetails toggles the details pane visibility
func (ui *UIState) ToggleDetails() bool {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.ShowDetails = !ui.ShowDetails
	return ui.ShowDetails
}

// SetFilterMode sets filter input mode
func (ui *UIState) SetFilterMode(mode bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.FilterMode = mode
}

// IsFilterMode returns whether in filter input mode
func (ui *UIState) IsFilterMode() bool {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.FilterMode
}

// SetFocusedPane sets the focused pane
func (ui *UIState) SetFocusedPane(pane string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.FocusedPane = pane
}

// GetFocusedPane returns the focused pane
func (ui *UIState) GetFocusedPane() string {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.FocusedPane
}

// SetViewMode sets the view mode (packets/calls)
func (ui *UIState) SetViewMode(mode string) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.ViewMode = mode
}

// GetViewMode returns the current view mode
func (ui *UIState) GetViewMode() string {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.ViewMode
}

// MarkForUpdate marks UI as needing an update
func (ui *UIState) MarkForUpdate() {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.NeedsUIUpdate = true
}

// ClearUpdateFlag clears the UI update flag
func (ui *UIState) ClearUpdateFlag() {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.NeedsUIUpdate = false
}

// NeedsUpdate returns whether UI needs updating
func (ui *UIState) NeedsUpdate() bool {
	ui.mu.RLock()
	defer ui.mu.RUnlock()
	return ui.NeedsUIUpdate
}
