//go:build tui || all

package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfflineSettings_Validate(t *testing.T) {
	theme := themes.Solarized()

	// Create temporary files for testing
	tmpDir := t.TempDir()
	pcapFile := filepath.Join(tmpDir, "capture.pcap")
	pcapngFile := filepath.Join(tmpDir, "capture.pcapng")
	file1 := filepath.Join(tmpDir, "file1.pcap")
	file2 := filepath.Join(tmpDir, "file2.pcap")

	// Create test files
	for _, f := range []string{pcapFile, pcapngFile, file1, file2} {
		err := os.WriteFile(f, []byte("test"), 0644)
		require.NoError(t, err, "failed to create test file: %s", f)
	}

	tests := []struct {
		name            string
		pcapFile        string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:     "valid with single pcap file",
			pcapFile: pcapFile,
			wantErr:  false,
		},
		{
			name:     "valid with single pcapng file",
			pcapFile: pcapngFile,
			wantErr:  false,
		},
		{
			name:     "valid with multiple space-separated files",
			pcapFile: file1 + " " + file2,
			wantErr:  false,
		},
		{
			name:            "invalid - empty pcap file",
			pcapFile:        "",
			wantErr:         true,
			wantErrContains: "at least one PCAP file path required",
		},
		{
			name:            "invalid - file not found",
			pcapFile:        "/nonexistent/path/to/file.pcap",
			wantErr:         true,
			wantErrContains: "file not found",
		},
		{
			name:            "invalid - one of multiple files not found",
			pcapFile:        file1 + " /nonexistent/file.pcap",
			wantErr:         true,
			wantErrContains: "file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os := NewOfflineSettings(tt.pcapFile, 10000, "", theme)

			err := os.Validate()

			if tt.wantErr {
				require.Error(t, err, "Validate() should return error")
				assert.Contains(t, err.Error(), tt.wantErrContains, "error message should contain expected text")
			} else {
				assert.NoError(t, err, "Validate() should not return error")
			}
		})
	}
}

func TestOfflineSettings_GetBufferSize(t *testing.T) {
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
			bufferValue:    "100000",
			wantBufferSize: 100000,
		},
		{
			name:           "invalid buffer - returns default",
			bufferValue:    "not-a-number",
			wantBufferSize: 10000,
		},
		{
			name:           "negative buffer - returns default",
			bufferValue:    "-500",
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
			os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)
			os.bufferInput.SetValue(tt.bufferValue)

			result := os.GetBufferSize()
			assert.Equal(t, tt.wantBufferSize, result, "GetBufferSize() should return expected buffer size")
		})
	}
}

func TestOfflineSettings_GetBPFFilter(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name       string
		filter     string
		wantFilter string
	}{
		{
			name:       "simple filter",
			filter:     "udp",
			wantFilter: "udp",
		},
		{
			name:       "complex filter",
			filter:     "host 192.168.1.1 and port 443",
			wantFilter: "host 192.168.1.1 and port 443",
		},
		{
			name:       "empty filter",
			filter:     "",
			wantFilter: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os := NewOfflineSettings("/tmp/test.pcap", 10000, tt.filter, theme)

			result := os.GetBPFFilter()
			assert.Equal(t, tt.wantFilter, result, "GetBPFFilter() should return expected filter")
		})
	}
}

func TestOfflineSettings_ToRestartMsg(t *testing.T) {
	theme := themes.Solarized()

	tests := []struct {
		name           string
		pcapFile       string
		bufferSize     int
		filter         string
		wantPCAPFiles  []string
		wantBufferSize int
		wantFilter     string
	}{
		{
			name:           "basic offline settings",
			pcapFile:       "/tmp/capture.pcap",
			bufferSize:     8000,
			filter:         "tcp",
			wantPCAPFiles:  []string{"/tmp/capture.pcap"},
			wantBufferSize: 8000,
			wantFilter:     "tcp",
		},
		{
			name:           "offline settings with complex filter",
			pcapFile:       "/home/user/captures/test.pcapng",
			bufferSize:     15000,
			filter:         "tcp port 80 or tcp port 443",
			wantPCAPFiles:  []string{"/home/user/captures/test.pcapng"},
			wantBufferSize: 15000,
			wantFilter:     "tcp port 80 or tcp port 443",
		},
		{
			name:           "multiple space-separated files",
			pcapFile:       "/tmp/file1.pcap /tmp/file2.pcap /tmp/file3.pcap",
			bufferSize:     10000,
			filter:         "",
			wantPCAPFiles:  []string{"/tmp/file1.pcap", "/tmp/file2.pcap", "/tmp/file3.pcap"},
			wantBufferSize: 10000,
			wantFilter:     "",
		},
		{
			name:           "empty pcap file",
			pcapFile:       "",
			bufferSize:     10000,
			filter:         "",
			wantPCAPFiles:  nil,
			wantBufferSize: 10000,
			wantFilter:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os := NewOfflineSettings(tt.pcapFile, tt.bufferSize, tt.filter, theme)

			msg := os.ToRestartMsg()

			assert.Equal(t, 1, msg.Mode, "Mode should be 1 (Offline)")
			assert.Equal(t, tt.wantPCAPFiles, msg.PCAPFiles, "PCAPFiles should match")
			assert.Equal(t, tt.wantBufferSize, msg.BufferSize, "BufferSize should match")
			assert.Equal(t, tt.wantFilter, msg.Filter, "Filter should match")
		})
	}
}

func TestOfflineSettings_HandleKey_FileDialog(t *testing.T) {
	theme := themes.Solarized()
	os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)

	// Test that pressing Enter on PCAP file field when not editing opens file dialog
	params := KeyHandlerParams{
		FocusIndex: 1,
		Editing:    false,
	}
	result := os.HandleKey("enter", params)

	assert.True(t, result.OpenFileDialog, "Should request file dialog to open")
	assert.False(t, result.Editing, "Should not enter editing mode")
}

func TestOfflineSettings_HandleKey_BufferEditing(t *testing.T) {
	theme := themes.Solarized()
	os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)

	// Test entering edit mode for buffer (focus index 2)
	params := KeyHandlerParams{
		FocusIndex: 2,
		Editing:    false,
	}
	result := os.HandleKey("enter", params)

	assert.True(t, result.Editing, "Should enter editing mode")
	assert.False(t, result.TriggerBufferUpdate, "Should not trigger buffer update when entering edit mode")

	// Test exiting edit mode for buffer
	params.Editing = true
	result = os.HandleKey("enter", params)

	assert.False(t, result.Editing, "Should exit editing mode")
	assert.True(t, result.TriggerBufferUpdate, "Should trigger buffer update when exiting edit mode")
}

func TestOfflineSettings_HandleKey_FilterEditing(t *testing.T) {
	theme := themes.Solarized()
	os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)

	// Test entering edit mode for filter (focus index 3)
	params := KeyHandlerParams{
		FocusIndex: 3,
		Editing:    false,
	}
	result := os.HandleKey("enter", params)

	assert.True(t, result.Editing, "Should enter editing mode")
	assert.False(t, result.TriggerRestart, "Should not trigger restart when entering edit mode")

	// Test exiting edit mode for filter
	params.Editing = true
	result = os.HandleKey("enter", params)

	assert.False(t, result.Editing, "Should exit editing mode")
	assert.True(t, result.TriggerRestart, "Should trigger restart when exiting edit mode")
}

func TestOfflineSettings_HandleKey_Escape(t *testing.T) {
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
			name:                 "escape from pcap file editing - cancel without triggering restart",
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
			name:                 "escape from filter editing - cancel without triggering restart",
			focusIndex:           3,
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
			os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)

			params := KeyHandlerParams{
				FocusIndex: tt.focusIndex,
				Editing:    tt.initialEditing,
			}
			result := os.HandleKey("esc", params)

			assert.Equal(t, tt.wantEditing, result.Editing, "Editing state should match")
			assert.Equal(t, tt.wantTriggerRestart, result.TriggerRestart, "TriggerRestart should match")
			assert.Equal(t, tt.wantTriggerBufferUpd, result.TriggerBufferUpdate, "TriggerBufferUpdate should match")
		})
	}
}

func TestOfflineSettings_GetFocusableFieldCount(t *testing.T) {
	theme := themes.Solarized()
	os := NewOfflineSettings("/tmp/test.pcap", 10000, "", theme)

	count := os.GetFocusableFieldCount()
	assert.Equal(t, 3, count, "Offline mode should have 3 focusable fields: pcap file, buffer, filter")
}
