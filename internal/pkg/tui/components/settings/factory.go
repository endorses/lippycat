//go:build tui || all
// +build tui all

package settings

import (
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// CaptureMode represents the type of capture mode.
type CaptureMode int

const (
	// CaptureModeLive captures from network interfaces in real-time.
	CaptureModeLive CaptureMode = iota

	// CaptureModeOffline reads from a PCAP file.
	CaptureModeOffline

	// CaptureModeRemote connects to remote processor/hunter nodes.
	CaptureModeRemote
)

// ModeFactory creates mode instances based on mode type and initial settings.
//
// The factory pattern centralizes mode instantiation and makes it easy to:
// - Create modes with proper initialization
// - Switch between modes while preserving common settings (buffer size, theme)
// - Add new capture modes without changing client code
type ModeFactory struct {
	theme themes.Theme
	// Cached live mode settings to preserve across mode switches
	lastInterface   string
	lastPromiscuous bool
	lastFilter      string
}

// NewModeFactory creates a new mode factory with the given theme.
func NewModeFactory(theme themes.Theme) *ModeFactory {
	return &ModeFactory{
		theme:         theme,
		lastInterface: "any",
	}
}

// CreateMode creates a mode instance based on the given mode type and parameters.
//
// Parameters:
//   - mode: The type of capture mode to create
//   - bufferSize: Initial buffer size (common to all modes)
//   - filter: Initial BPF filter (used by live and offline modes)
//   - interfaceStr: Comma-separated interface names (live mode only)
//   - promiscuous: Promiscuous mode enabled (live mode only)
//   - pcapFile: Path to PCAP file (offline mode only)
//   - nodesFile: Path to nodes YAML file (remote mode only)
//
// Returns the created ModeSettings instance.
func (f *ModeFactory) CreateMode(
	mode CaptureMode,
	bufferSize int,
	filter string,
	interfaceStr string,
	promiscuous bool,
	pcapFile string,
	nodesFile string,
) ModeSettings {
	switch mode {
	case CaptureModeLive:
		// Cache live mode settings for later restoration
		if interfaceStr != "" {
			f.lastInterface = interfaceStr
		}
		f.lastPromiscuous = promiscuous
		f.lastFilter = filter
		return NewLiveSettings(interfaceStr, bufferSize, promiscuous, filter, f.theme)

	case CaptureModeOffline:
		return NewOfflineSettings(pcapFile, bufferSize, filter, f.theme)

	case CaptureModeRemote:
		return NewRemoteSettings(nodesFile, bufferSize, f.theme)

	default:
		// Default to live mode
		return NewLiveSettings(interfaceStr, bufferSize, promiscuous, filter, f.theme)
	}
}

// SwitchMode creates a new mode while preserving common settings.
//
// This is used when the user switches between capture modes. It:
// 1. Extracts common settings (buffer size) from the current mode
// 2. Caches live mode settings (interface, promiscuous) when switching away from live
// 3. Restores live mode settings when switching back to live
// 4. Creates a new mode instance with those settings
//
// Parameters:
//   - newMode: The mode type to switch to
//   - currentMode: The current mode instance (can be nil)
//
// Returns the new mode instance.
func (f *ModeFactory) SwitchMode(newMode CaptureMode, currentMode ModeSettings) ModeSettings {
	// Preserve buffer size across mode switches
	bufferSize := 10000 // default
	if currentMode != nil {
		bufferSize = currentMode.GetBufferSize()

		// Cache live mode settings when switching away from live mode
		msg := currentMode.ToRestartMsg()
		if msg.Mode == 0 { // CaptureModeLive
			if msg.Interface != "" {
				f.lastInterface = msg.Interface
			}
			f.lastPromiscuous = msg.Promiscuous
			if msg.Filter != "" {
				f.lastFilter = msg.Filter
			}
		}
	}

	// When switching to live mode, use cached settings
	// When switching to other modes, reset mode-specific fields
	interfaceStr := "any"
	promiscuous := false
	filter := ""

	if newMode == CaptureModeLive {
		// Restore cached live mode settings
		interfaceStr = f.lastInterface
		promiscuous = f.lastPromiscuous
		filter = f.lastFilter
	} else {
		// For offline mode, preserve filter from current mode if available
		if currentMode != nil {
			filter = currentMode.GetBPFFilter()
		}
	}

	// Create new mode with preserved settings
	return f.CreateMode(
		newMode,
		bufferSize,
		filter,       // preserved or reset depending on mode
		interfaceStr, // restored from cache for live mode
		promiscuous,  // restored from cache for live mode
		"",           // pcapFile (reset)
		"",           // nodesFile (reset)
	)
}

// UpdateTheme updates the theme for the factory.
// This should be called when the user switches themes, and then modes should
// be recreated or updated accordingly.
func (f *ModeFactory) UpdateTheme(theme themes.Theme) {
	f.theme = theme
}
