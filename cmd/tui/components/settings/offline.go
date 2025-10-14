//go:build tui || all
// +build tui all

package settings

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// OfflineSettings encapsulates all settings for offline (PCAP file) capture mode
type OfflineSettings struct {
	pcapFileInput textinput.Model
	bufferInput   textinput.Model
	filterInput   textinput.Model
}

// NewOfflineSettings creates a new OfflineSettings instance
func NewOfflineSettings(pcapFile string, bufferSize int, filter string, theme themes.Theme) *OfflineSettings {
	bufferInput, filterInput := CreateCommonInputs(bufferSize, filter)

	// PCAP file input
	pcapFileInput := textinput.New()
	pcapFileInput.Placeholder = "/path/to/file.pcap"
	pcapFileInput.CharLimit = 512
	pcapFileInput.Width = 50
	pcapFileInput.SetValue(pcapFile)

	return &OfflineSettings{
		pcapFileInput: pcapFileInput,
		bufferInput:   bufferInput,
		filterInput:   filterInput,
	}
}

// Validate checks if offline settings are valid
func (os *OfflineSettings) Validate() error {
	if os.pcapFileInput.Value() == "" {
		return fmt.Errorf("PCAP file path required for offline capture")
	}
	return nil
}

// ToRestartMsg converts offline settings to a restart message
func (os *OfflineSettings) ToRestartMsg() RestartCaptureMsg {
	return RestartCaptureMsg{
		Mode:       1, // CaptureModeOffline
		PCAPFile:   os.pcapFileInput.Value(),
		Filter:     os.GetBPFFilter(),
		BufferSize: os.GetBufferSize(),
	}
}

// GetBufferSize returns the configured buffer size
func (os *OfflineSettings) GetBufferSize() int {
	size, err := strconv.Atoi(os.bufferInput.Value())
	if err != nil || size <= 0 {
		return 10000
	}
	return size
}

// GetBPFFilter returns the configured BPF filter
func (os *OfflineSettings) GetBPFFilter() string {
	return os.filterInput.Value()
}

// GetFocusableFieldCount returns 3: pcapFile(1), buffer(2), filter(3)
func (os *OfflineSettings) GetFocusableFieldCount() int {
	return 3
}

// Render renders the offline mode fields
func (os *OfflineSettings) Render(params RenderParams) []string {
	var sections []string

	// PCAP File field (focus index 1)
	pcapStyle := params.UnfocusedStyle
	if params.FocusIndex == 1 {
		if params.Editing {
			pcapStyle = params.EditingStyle
		} else {
			pcapStyle = params.SelectedStyle
		}
	}
	sections = append(sections, pcapStyle.Width(params.Width-4).Render(
		params.LabelStyle.Render("PCAP File:")+"\n"+os.pcapFileInput.View(),
	))

	// Buffer field (focus index 2)
	bufferStyle := params.UnfocusedStyle
	if params.FocusIndex == 2 {
		if params.Editing {
			bufferStyle = params.EditingStyle
		} else {
			bufferStyle = params.SelectedStyle
		}
	}
	sections = append(sections, bufferStyle.Width(params.Width-4).Render(
		params.LabelStyle.Render("Buffer Size:")+"\n"+os.bufferInput.View(),
	))

	// Filter field (focus index 3)
	filterStyle := params.UnfocusedStyle
	if params.FocusIndex == 3 {
		if params.Editing {
			filterStyle = params.EditingStyle
		} else {
			filterStyle = params.SelectedStyle
		}
	}
	sections = append(sections, filterStyle.Width(params.Width-4).Render(
		params.LabelStyle.Render("Capture Filter:")+"\n"+os.filterInput.View(),
	))

	return sections
}

// HandleKey handles keyboard input for offline mode
func (os *OfflineSettings) HandleKey(key string, params KeyHandlerParams) KeyHandlerResult {
	result := KeyHandlerResult{
		Editing: params.Editing,
	}

	switch key {
	case "enter":
		switch params.FocusIndex {
		case 1: // PCAP File
			if !params.Editing {
				result.OpenFileDialog = true
			} else {
				result.Editing = !params.Editing
				if result.Editing {
					os.pcapFileInput.Focus()
				} else {
					os.pcapFileInput.Blur()
					result.TriggerRestart = true
				}
			}

		case 2: // Buffer size
			result.Editing = !params.Editing
			if result.Editing {
				os.bufferInput.Focus()
			} else {
				os.bufferInput.Blur()
				result.TriggerBufferUpdate = true
			}

		case 3: // Filter
			result.Editing = !params.Editing
			if result.Editing {
				os.filterInput.Focus()
			} else {
				os.filterInput.Blur()
				result.TriggerRestart = true
			}
		}

	case "esc":
		if params.Editing {
			switch params.FocusIndex {
			case 1: // PCAP File - cancel edit, don't save
				os.pcapFileInput.Blur()
				result.Editing = false
				// Don't trigger restart - cancel the edit
			case 2: // Buffer - cancel edit, don't save
				os.bufferInput.Blur()
				result.Editing = false
				// Don't trigger update - cancel the edit
			case 3: // Filter - cancel edit, don't save
				os.filterInput.Blur()
				result.Editing = false
				// Don't trigger restart - cancel the edit
			}
		}
	}

	return result
}

// SetSize updates sizes for any UI components
func (os *OfflineSettings) SetSize(width, height int) {
	// Offline mode doesn't have components that need resizing
}

// UpdateTheme updates the theme for any themed components
func (os *OfflineSettings) UpdateTheme(theme themes.Theme) {
	// Offline mode doesn't have themed components beyond the inputs
}

// Update passes bubbletea messages to inputs when editing
func (os *OfflineSettings) Update(msg tea.Msg, focusIndex int) tea.Cmd {
	var cmd tea.Cmd
	switch focusIndex {
	case 1:
		os.pcapFileInput, cmd = os.pcapFileInput.Update(msg)
	case 2:
		os.bufferInput, cmd = os.bufferInput.Update(msg)
	case 3:
		os.filterInput, cmd = os.filterInput.Update(msg)
	}
	return cmd
}
