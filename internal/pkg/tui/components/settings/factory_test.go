//go:build tui || all

package settings

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModeFactory_CreateMode(t *testing.T) {
	theme := themes.Solarized()
	factory := NewModeFactory(theme)

	tests := []struct {
		name         string
		mode         CaptureMode
		bufferSize   int
		filter       string
		interfaceStr string
		promiscuous  bool
		pcapFile     string
		nodesFile    string
		wantType     string
	}{
		{
			name:         "create live mode",
			mode:         CaptureModeLive,
			bufferSize:   5000,
			filter:       "tcp port 80",
			interfaceStr: "eth0",
			promiscuous:  true,
			wantType:     "*settings.LiveSettings",
		},
		{
			name:       "create offline mode",
			mode:       CaptureModeOffline,
			bufferSize: 8000,
			filter:     "udp",
			pcapFile:   "/tmp/test.pcap",
			wantType:   "*settings.OfflineSettings",
		},
		{
			name:       "create remote mode",
			mode:       CaptureModeRemote,
			bufferSize: 12000,
			nodesFile:  "/tmp/nodes.yaml",
			wantType:   "*settings.RemoteSettings",
		},
		{
			name:         "invalid mode defaults to live",
			mode:         CaptureMode(99),
			bufferSize:   10000,
			interfaceStr: "any",
			wantType:     "*settings.LiveSettings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := factory.CreateMode(
				tt.mode,
				tt.bufferSize,
				tt.filter,
				tt.interfaceStr,
				tt.promiscuous,
				tt.pcapFile,
				tt.nodesFile,
			)

			require.NotNil(t, mode, "mode should not be nil")
			assert.Equal(t, tt.wantType, getTypeName(mode), "mode type should match")
			assert.Equal(t, tt.bufferSize, mode.GetBufferSize(), "buffer size should be preserved")

			// Verify mode-specific properties
			switch tt.mode {
			case CaptureModeLive:
				assert.Equal(t, tt.filter, mode.GetBPFFilter(), "filter should be set for live mode")
			case CaptureModeOffline:
				assert.Equal(t, tt.filter, mode.GetBPFFilter(), "filter should be set for offline mode")
			case CaptureModeRemote:
				assert.Empty(t, mode.GetBPFFilter(), "remote mode should not have BPF filter")
			}
		})
	}
}

func TestModeFactory_SwitchMode(t *testing.T) {
	tests := []struct {
		name              string
		currentMode       CaptureMode
		currentBufferSize int
		currentFilter     string
		newMode           CaptureMode
		wantType          string
		wantBufferSize    int
	}{
		{
			name:              "switch from live to offline preserves buffer size",
			currentMode:       CaptureModeLive,
			currentBufferSize: 7500,
			currentFilter:     "tcp",
			newMode:           CaptureModeOffline,
			wantType:          "*settings.OfflineSettings",
			wantBufferSize:    7500,
		},
		{
			name:              "switch from offline to remote preserves buffer size",
			currentMode:       CaptureModeOffline,
			currentBufferSize: 15000,
			newMode:           CaptureModeRemote,
			wantType:          "*settings.RemoteSettings",
			wantBufferSize:    15000,
		},
		{
			name:              "switch from remote to live preserves buffer size",
			currentMode:       CaptureModeRemote,
			currentBufferSize: 20000,
			newMode:           CaptureModeLive,
			wantType:          "*settings.LiveSettings",
			wantBufferSize:    20000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh factory for each test case to avoid shared state
			theme := themes.Solarized()
			factory := NewModeFactory(theme)

			// Create initial mode
			currentMode := factory.CreateMode(
				tt.currentMode,
				tt.currentBufferSize,
				tt.currentFilter,
				"eth0",
				false,
				"",
				"",
			)

			// Switch to new mode
			newMode := factory.SwitchMode(tt.newMode, currentMode)

			require.NotNil(t, newMode, "new mode should not be nil")
			assert.Equal(t, tt.wantType, getTypeName(newMode), "mode type should match")
			assert.Equal(t, tt.wantBufferSize, newMode.GetBufferSize(), "buffer size should be preserved across mode switch")

			// Verify that mode-specific settings are reset
			msg := newMode.ToRestartMsg()
			switch tt.newMode {
			case CaptureModeLive:
				assert.Equal(t, "any", msg.Interface, "interface should be reset to 'any'")
				assert.False(t, msg.Promiscuous, "promiscuous should be reset to false")
			case CaptureModeOffline:
				assert.Empty(t, msg.PCAPFile, "pcap file should be reset")
			case CaptureModeRemote:
				assert.Empty(t, msg.NodesFile, "nodes file should be reset")
			}
		})
	}
}

func TestModeFactory_SwitchMode_NilCurrentMode(t *testing.T) {
	theme := themes.Solarized()
	factory := NewModeFactory(theme)

	newMode := factory.SwitchMode(CaptureModeLive, nil)

	require.NotNil(t, newMode, "new mode should not be nil")
	assert.Equal(t, 10000, newMode.GetBufferSize(), "should use default buffer size when current mode is nil")
}

func TestModeFactory_UpdateTheme(t *testing.T) {
	theme1 := themes.Solarized()
	theme2 := themes.GetTheme("solarized") // Use GetTheme to get another instance

	factory := NewModeFactory(theme1)
	assert.Equal(t, theme1, factory.theme, "initial theme should be set")

	factory.UpdateTheme(theme2)
	assert.Equal(t, theme2, factory.theme, "theme should be updated")
}

// Helper function to get type name for assertions
func getTypeName(mode ModeSettings) string {
	switch mode.(type) {
	case *LiveSettings:
		return "*settings.LiveSettings"
	case *OfflineSettings:
		return "*settings.OfflineSettings"
	case *RemoteSettings:
		return "*settings.RemoteSettings"
	default:
		return "unknown"
	}
}
