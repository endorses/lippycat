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

// RemoteSettings encapsulates all settings for remote (processor/hunter) capture mode
type RemoteSettings struct {
	nodesFileInput textinput.Model
	bufferInput    textinput.Model
}

// NewRemoteSettings creates a new RemoteSettings instance
func NewRemoteSettings(nodesFile string, bufferSize int, theme themes.Theme) *RemoteSettings {
	bufferInput, _ := CreateCommonInputs(bufferSize, "")

	// Nodes file input
	nodesFileInput := textinput.New()
	nodesFileInput.Placeholder = "nodes.yaml or ~/.config/lippycat/nodes.yaml"
	nodesFileInput.CharLimit = 512
	nodesFileInput.Width = 50
	nodesFileInput.SetValue(nodesFile)

	return &RemoteSettings{
		nodesFileInput: nodesFileInput,
		bufferInput:    bufferInput,
	}
}

// Validate checks if remote settings are valid
func (rs *RemoteSettings) Validate() error {
	if rs.nodesFileInput.Value() == "" {
		return fmt.Errorf("nodes file path required for remote capture")
	}
	return nil
}

// ToRestartMsg converts remote settings to a restart message
func (rs *RemoteSettings) ToRestartMsg() RestartCaptureMsg {
	return RestartCaptureMsg{
		Mode:       2, // CaptureModeRemote
		NodesFile:  rs.nodesFileInput.Value(),
		BufferSize: rs.GetBufferSize(),
		// Note: Remote mode doesn't use BPF filter (filtering happens on remote nodes)
	}
}

// GetBufferSize returns the configured buffer size
func (rs *RemoteSettings) GetBufferSize() int {
	size, err := strconv.Atoi(rs.bufferInput.Value())
	if err != nil || size <= 0 {
		return 10000
	}
	return size
}

// GetBPFFilter returns empty string (remote mode doesn't support BPF filtering)
func (rs *RemoteSettings) GetBPFFilter() string {
	return ""
}

// GetFocusableFieldCount returns 2: nodesFile(1), buffer(2)
func (rs *RemoteSettings) GetFocusableFieldCount() int {
	return 2
}

// Render renders the remote mode fields
func (rs *RemoteSettings) Render(params RenderParams) []string {
	var sections []string

	// Nodes File field (focus index 1)
	nodesStyle := params.UnfocusedStyle
	if params.FocusIndex == 1 {
		if params.Editing {
			nodesStyle = params.EditingStyle
		} else {
			nodesStyle = params.SelectedStyle
		}
	}
	sections = append(sections, nodesStyle.Width(params.Width-4).Render(
		params.LabelStyle.Render("Nodes File:")+"\n"+rs.nodesFileInput.View(),
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
		params.LabelStyle.Render("Buffer Size:")+"\n"+rs.bufferInput.View(),
	))

	// Add note about filtering
	noteStyle := params.UnfocusedStyle.
		Foreground(params.Theme.WarningColor).
		Italic(true)
	sections = append(sections, noteStyle.Width(params.Width-4).Render(
		"Note: Packet filtering is configured on the remote nodes",
	))

	return sections
}

// HandleKey handles keyboard input for remote mode
func (rs *RemoteSettings) HandleKey(key string, params KeyHandlerParams) KeyHandlerResult {
	result := KeyHandlerResult{
		Editing: params.Editing,
	}

	switch key {
	case "enter":
		switch params.FocusIndex {
		case 1: // Nodes File
			if !params.Editing {
				result.OpenFileDialog = true
			} else {
				result.Editing = !params.Editing
				if result.Editing {
					rs.nodesFileInput.Focus()
				} else {
					rs.nodesFileInput.Blur()
					result.TriggerRestart = true
				}
			}

		case 2: // Buffer size
			result.Editing = !params.Editing
			if result.Editing {
				rs.bufferInput.Focus()
			} else {
				rs.bufferInput.Blur()
				result.TriggerBufferUpdate = true
			}
		}

	case "esc":
		if params.Editing {
			switch params.FocusIndex {
			case 1: // Nodes File - cancel edit, don't save
				rs.nodesFileInput.Blur()
				result.Editing = false
				// Don't trigger restart - cancel the edit
			case 2: // Buffer - cancel edit, don't save
				rs.bufferInput.Blur()
				result.Editing = false
				// Don't trigger update - cancel the edit
			}
		}
	}

	return result
}

// SetSize updates sizes for any UI components
func (rs *RemoteSettings) SetSize(width, height int) {
	// Remote mode doesn't have components that need resizing
}

// UpdateTheme updates the theme for any themed components
func (rs *RemoteSettings) UpdateTheme(theme themes.Theme) {
	// Remote mode doesn't have themed components beyond the inputs
}

// Update passes bubbletea messages to inputs when editing
func (rs *RemoteSettings) Update(msg tea.Msg, focusIndex int) tea.Cmd {
	var cmd tea.Cmd
	switch focusIndex {
	case 1:
		rs.nodesFileInput, cmd = rs.nodesFileInput.Update(msg)
	case 2:
		rs.bufferInput, cmd = rs.bufferInput.Update(msg)
	}
	return cmd
}
