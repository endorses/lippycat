//go:build tui || all
// +build tui all

package settings

import (
	"testing"

	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteSettings_Validate(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name      string
		nodesFile string
		wantErr   bool
	}{
		{
			name:      "valid with nodes file",
			nodesFile: "/tmp/nodes.yaml",
			wantErr:   false,
		},
		{
			name:      "valid with yml extension",
			nodesFile: "~/.config/lippycat/nodes.yml",
			wantErr:   false,
		},
		{
			name:      "valid with empty nodes file - can add processors via Nodes tab",
			nodesFile: "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRemoteSettings(tt.nodesFile, 10000, theme)

			err := rs.Validate()

			if tt.wantErr {
				require.Error(t, err, "Validate() should return error")
			} else {
				assert.NoError(t, err, "Validate() should not return error")
			}
		})
	}
}

func TestRemoteSettings_GetBufferSize(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name           string
		bufferValue    string
		wantBufferSize int
	}{
		{
			name:           "valid buffer size",
			bufferValue:    "12000",
			wantBufferSize: 12000,
		},
		{
			name:           "large buffer size",
			bufferValue:    "200000",
			wantBufferSize: 200000,
		},
		{
			name:           "invalid buffer - returns default",
			bufferValue:    "abc",
			wantBufferSize: 10000,
		},
		{
			name:           "negative buffer - returns default",
			bufferValue:    "-1000",
			wantBufferSize: 10000,
		},
		{
			name:           "zero buffer - returns default",
			bufferValue:    "0",
			wantBufferSize: 10000,
		},
		{
			name:           "empty buffer - returns default",
			bufferValue:    "",
			wantBufferSize: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)
			rs.bufferInput.SetValue(tt.bufferValue)

			result := rs.GetBufferSize()
			assert.Equal(t, tt.wantBufferSize, result, "GetBufferSize() should return expected buffer size")
		})
	}
}

func TestRemoteSettings_GetBPFFilter(t *testing.T) {
	theme := themes.Solarized()
	rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)

	// Remote mode should always return empty filter (filtering happens on remote nodes)
	result := rs.GetBPFFilter()
	assert.Empty(t, result, "Remote mode should not have BPF filter")
}

func TestRemoteSettings_ToRestartMsg(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name           string
		nodesFile      string
		bufferSize     int
		wantNodesFile  string
		wantBufferSize int
	}{
		{
			name:           "basic remote settings",
			nodesFile:      "/tmp/nodes.yaml",
			bufferSize:     12000,
			wantNodesFile:  "/tmp/nodes.yaml",
			wantBufferSize: 12000,
		},
		{
			name:           "remote settings with config path",
			nodesFile:      "~/.config/lippycat/nodes.yaml",
			bufferSize:     20000,
			wantNodesFile:  "~/.config/lippycat/nodes.yaml",
			wantBufferSize: 20000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRemoteSettings(tt.nodesFile, tt.bufferSize, theme)

			msg := rs.ToRestartMsg()

			assert.Equal(t, 2, msg.Mode, "Mode should be 2 (Remote)")
			assert.Equal(t, tt.wantNodesFile, msg.NodesFile, "NodesFile should match")
			assert.Equal(t, tt.wantBufferSize, msg.BufferSize, "BufferSize should match")
			assert.Empty(t, msg.Filter, "Remote mode should not have filter in restart message")
		})
	}
}

func TestRemoteSettings_HandleKey_FileDialog(t *testing.T) {
	theme := themes.Solarized()
	rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)

	// Test that pressing Enter on nodes file field when not editing opens file dialog
	params := KeyHandlerParams{
		FocusIndex: 1,
		Editing:    false,
	}
	result := rs.HandleKey("enter", params)

	assert.True(t, result.OpenFileDialog, "Should request file dialog to open")
	assert.False(t, result.Editing, "Should not enter editing mode")
}

func TestRemoteSettings_HandleKey_BufferEditing(t *testing.T) {
	theme := themes.Solarized()
	rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)

	// Test entering edit mode for buffer (focus index 2)
	params := KeyHandlerParams{
		FocusIndex: 2,
		Editing:    false,
	}
	result := rs.HandleKey("enter", params)

	assert.True(t, result.Editing, "Should enter editing mode")
	assert.False(t, result.TriggerBufferUpdate, "Should not trigger buffer update when entering edit mode")

	// Test exiting edit mode for buffer
	params.Editing = true
	result = rs.HandleKey("enter", params)

	assert.False(t, result.Editing, "Should exit editing mode")
	assert.True(t, result.TriggerBufferUpdate, "Should trigger buffer update when exiting edit mode")
}

func TestRemoteSettings_HandleKey_Escape(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name                 string
		focusIndex           int
		initialEditing       bool
		wantEditing          bool
		wantTriggerRestart   bool
		wantTriggerBufferUpd bool
	}{
		{
			name:                 "escape from nodes file editing - cancel without triggering restart",
			focusIndex:           1,
			initialEditing:       true,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
		{
			name:                 "escape from buffer editing - cancel without triggering update",
			focusIndex:           2,
			initialEditing:       true,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
		{
			name:                 "escape when not editing - no effect",
			focusIndex:           2,
			initialEditing:       false,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)

			params := KeyHandlerParams{
				FocusIndex: tt.focusIndex,
				Editing:    tt.initialEditing,
			}
			result := rs.HandleKey("esc", params)

			assert.Equal(t, tt.wantEditing, result.Editing, "Editing state should match")
			assert.Equal(t, tt.wantTriggerRestart, result.TriggerRestart, "TriggerRestart should match")
			assert.Equal(t, tt.wantTriggerBufferUpd, result.TriggerBufferUpdate, "TriggerBufferUpdate should match")
		})
	}
}

func TestRemoteSettings_GetFocusableFieldCount(t *testing.T) {
	theme := themes.Solarized()
	rs := NewRemoteSettings("/tmp/nodes.yaml", 10000, theme)

	count := rs.GetFocusableFieldCount()
	assert.Equal(t, 2, count, "Remote mode should have 2 focusable fields: nodes file, buffer")
}
