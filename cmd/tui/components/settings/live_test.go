//go:build tui || all
// +build tui all

package settings

import (
	"testing"

	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveSettings_Validate(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name            string
		selectedIfaces  map[string]bool
		promiscuous     bool
		wantErr         bool
		wantErrContains string
	}{
		{
			name:           "valid with single interface",
			selectedIfaces: map[string]bool{"eth0": true},
			promiscuous:    false,
			wantErr:        false,
		},
		{
			name:           "valid with multiple interfaces",
			selectedIfaces: map[string]bool{"eth0": true, "eth1": true},
			promiscuous:    false,
			wantErr:        false,
		},
		{
			name:           "valid with 'any' interface",
			selectedIfaces: map[string]bool{"any": true},
			promiscuous:    false,
			wantErr:        false,
		},
		{
			name:            "invalid - no interfaces selected",
			selectedIfaces:  map[string]bool{},
			promiscuous:     false,
			wantErr:         true,
			wantErrContains: "at least one interface required",
		},
		{
			name:            "invalid - promiscuous mode with 'any' interface",
			selectedIfaces:  map[string]bool{"any": true},
			promiscuous:     true,
			wantErr:         true,
			wantErrContains: "promiscuous mode cannot be used with 'any' interface",
		},
		{
			name:           "valid - promiscuous mode with specific interface",
			selectedIfaces: map[string]bool{"eth0": true},
			promiscuous:    true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings("eth0", 10000, false, "", theme)
			ls.selectedIfaces = tt.selectedIfaces
			ls.promiscuous = tt.promiscuous

			err := ls.Validate()

			if tt.wantErr {
				require.Error(t, err, "Validate() should return error")
				assert.Contains(t, err.Error(), tt.wantErrContains, "error message should contain expected text")
			} else {
				assert.NoError(t, err, "Validate() should not return error")
			}
		})
	}
}

func TestLiveSettings_GetInterface(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name           string
		selectedIfaces map[string]bool
		wantInterface  string
	}{
		{
			name:           "empty selection returns 'any'",
			selectedIfaces: map[string]bool{},
			wantInterface:  "any",
		},
		{
			name:           "single interface",
			selectedIfaces: map[string]bool{"eth0": true},
			wantInterface:  "eth0",
		},
		{
			name:           "multiple interfaces sorted",
			selectedIfaces: map[string]bool{"wlan0": true, "eth0": true, "eth1": true},
			wantInterface:  "eth0,eth1,wlan0",
		},
		{
			name:           "'any' interface",
			selectedIfaces: map[string]bool{"any": true},
			wantInterface:  "any",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings("eth0", 10000, false, "", theme)
			ls.selectedIfaces = tt.selectedIfaces

			result := ls.GetInterface()
			assert.Equal(t, tt.wantInterface, result, "GetInterface() should return expected interface string")
		})
	}
}

func TestLiveSettings_GetBufferSize(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name           string
		bufferValue    string
		wantBufferSize int
	}{
		{
			name:           "valid buffer size",
			bufferValue:    "5000",
			wantBufferSize: 5000,
		},
		{
			name:           "large buffer size",
			bufferValue:    "50000",
			wantBufferSize: 50000,
		},
		{
			name:           "invalid buffer - returns default",
			bufferValue:    "invalid",
			wantBufferSize: 10000,
		},
		{
			name:           "negative buffer - returns default",
			bufferValue:    "-100",
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
			ls := NewLiveSettings("eth0", 10000, false, "", theme)
			ls.bufferInput.SetValue(tt.bufferValue)

			result := ls.GetBufferSize()
			assert.Equal(t, tt.wantBufferSize, result, "GetBufferSize() should return expected buffer size")
		})
	}
}

func TestLiveSettings_GetBPFFilter(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name       string
		filter     string
		wantFilter string
	}{
		{
			name:       "simple filter",
			filter:     "tcp",
			wantFilter: "tcp",
		},
		{
			name:       "complex filter",
			filter:     "tcp port 80 or udp port 53",
			wantFilter: "tcp port 80 or udp port 53",
		},
		{
			name:       "empty filter",
			filter:     "",
			wantFilter: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings("eth0", 10000, false, tt.filter, theme)

			result := ls.GetBPFFilter()
			assert.Equal(t, tt.wantFilter, result, "GetBPFFilter() should return expected filter")
		})
	}
}

func TestLiveSettings_ToRestartMsg(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name            string
		interfaceStr    string
		bufferSize      int
		promiscuous     bool
		filter          string
		wantInterface   string
		wantBufferSize  int
		wantPromiscuous bool
		wantFilter      string
	}{
		{
			name:            "basic live settings",
			interfaceStr:    "eth0",
			bufferSize:      5000,
			promiscuous:     true,
			filter:          "tcp port 80",
			wantInterface:   "eth0",
			wantBufferSize:  5000,
			wantPromiscuous: true,
			wantFilter:      "tcp port 80",
		},
		{
			name:            "multiple interfaces",
			interfaceStr:    "eth0,wlan0",
			bufferSize:      8000,
			promiscuous:     false,
			filter:          "",
			wantInterface:   "eth0,wlan0",
			wantBufferSize:  8000,
			wantPromiscuous: false,
			wantFilter:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings(tt.interfaceStr, tt.bufferSize, tt.promiscuous, tt.filter, theme)

			msg := ls.ToRestartMsg()

			assert.Equal(t, 0, msg.Mode, "Mode should be 0 (Live)")
			assert.Equal(t, tt.wantInterface, msg.Interface, "Interface should match")
			assert.Equal(t, tt.wantBufferSize, msg.BufferSize, "BufferSize should match")
			assert.Equal(t, tt.wantPromiscuous, msg.Promiscuous, "Promiscuous should match")
			assert.Equal(t, tt.wantFilter, msg.Filter, "Filter should match")
		})
	}
}

func TestLiveSettings_HandleKey_PromiscuousToggle(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name              string
		selectedIfaces    map[string]bool
		initialPromisc    bool
		wantPromisc       bool
		wantError         bool
		wantErrorContains string
	}{
		{
			name:           "toggle promiscuous on with specific interface",
			selectedIfaces: map[string]bool{"eth0": true},
			initialPromisc: false,
			wantPromisc:    true,
			wantError:      false,
		},
		{
			name:           "toggle promiscuous off with specific interface",
			selectedIfaces: map[string]bool{"eth0": true},
			initialPromisc: true,
			wantPromisc:    false,
			wantError:      false,
		},
		{
			name:              "cannot enable promiscuous with 'any' interface",
			selectedIfaces:    map[string]bool{"any": true},
			initialPromisc:    false,
			wantPromisc:       false,
			wantError:         true,
			wantErrorContains: "Cannot enable promiscuous mode with 'any' interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings("eth0", 10000, tt.initialPromisc, "", theme)
			ls.selectedIfaces = tt.selectedIfaces

			// Simulate pressing Enter on promiscuous field (focus index 2)
			params := KeyHandlerParams{
				FocusIndex: 2,
				Editing:    false,
			}
			result := ls.HandleKey("enter", params)

			assert.Equal(t, tt.wantPromisc, ls.promiscuous, "Promiscuous mode should match expected value")

			if tt.wantError {
				assert.Contains(t, result.ErrorMessage, tt.wantErrorContains, "Error message should match")
			} else {
				assert.Empty(t, result.ErrorMessage, "Error message should be empty")
			}
		})
	}
}

func TestLiveSettings_HandleKey_BufferEditing(t *testing.T) {
	theme := themes.Solarized()
	ls := NewLiveSettings("eth0", 10000, false, "", theme)

	// Test entering edit mode for buffer (focus index 3)
	params := KeyHandlerParams{
		FocusIndex: 3,
		Editing:    false,
	}
	result := ls.HandleKey("enter", params)

	assert.True(t, result.Editing, "Should enter editing mode")
	assert.False(t, result.TriggerBufferUpdate, "Should not trigger buffer update when entering edit mode")

	// Test exiting edit mode for buffer
	params.Editing = true
	result = ls.HandleKey("enter", params)

	assert.False(t, result.Editing, "Should exit editing mode")
	assert.True(t, result.TriggerBufferUpdate, "Should trigger buffer update when exiting edit mode")
}

func TestLiveSettings_HandleKey_FilterEditing(t *testing.T) {
	theme := themes.Solarized()
	ls := NewLiveSettings("eth0", 10000, false, "", theme)

	// Test entering edit mode for filter (focus index 4)
	params := KeyHandlerParams{
		FocusIndex: 4,
		Editing:    false,
	}
	result := ls.HandleKey("enter", params)

	assert.True(t, result.Editing, "Should enter editing mode")
	assert.False(t, result.TriggerRestart, "Should not trigger restart when entering edit mode")

	// Test exiting edit mode for filter
	params.Editing = true
	result = ls.HandleKey("enter", params)

	assert.False(t, result.Editing, "Should exit editing mode")
	assert.True(t, result.TriggerRestart, "Should trigger restart when exiting edit mode")
}

func TestLiveSettings_HandleKey_Escape(t *testing.T) {
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
			name:                 "escape from buffer editing - cancel without triggering update",
			focusIndex:           3,
			initialEditing:       true,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
		{
			name:                 "escape from filter editing - cancel without triggering restart",
			focusIndex:           4,
			initialEditing:       true,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
		{
			name:                 "escape when not editing - no effect",
			focusIndex:           3,
			initialEditing:       false,
			wantEditing:          false,
			wantTriggerRestart:   false,
			wantTriggerBufferUpd: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := NewLiveSettings("eth0", 10000, false, "", theme)

			params := KeyHandlerParams{
				FocusIndex: tt.focusIndex,
				Editing:    tt.initialEditing,
			}
			result := ls.HandleKey("esc", params)

			assert.Equal(t, tt.wantEditing, result.Editing, "Editing state should match")
			assert.Equal(t, tt.wantTriggerRestart, result.TriggerRestart, "TriggerRestart should match")
			assert.Equal(t, tt.wantTriggerBufferUpd, result.TriggerBufferUpdate, "TriggerBufferUpdate should match")
		})
	}
}

func TestLiveSettings_GetFocusableFieldCount(t *testing.T) {
	theme := themes.Solarized()
	ls := NewLiveSettings("eth0", 10000, false, "", theme)

	count := ls.GetFocusableFieldCount()
	assert.Equal(t, 4, count, "Live mode should have 4 focusable fields: interface, promiscuous, buffer, filter")
}

func TestLiveSettings_SaveInterfaceState(t *testing.T) {
	theme := themes.Solarized()
	ls := NewLiveSettings("eth0,eth1", 10000, false, "", theme)

	// Modify state
	ls.selectedIfaces = map[string]bool{"wlan0": true}
	ls.interfaceList.Select(2)

	// Save state
	ls.SaveInterfaceState()

	// Verify state was saved
	assert.Equal(t, 2, ls.savedInterfaceIndex, "Saved index should match")
	assert.Equal(t, map[string]bool{"wlan0": true}, ls.savedSelectedIfaces, "Saved interfaces should match")

	// Verify it's a copy, not a reference
	ls.selectedIfaces["eth2"] = true
	assert.NotContains(t, ls.savedSelectedIfaces, "eth2", "Saved state should not be affected by changes to current state")
}
