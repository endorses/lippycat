//go:build tui || all

package components

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestOfflineSettingsRestartDefersPersistence(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	viper.Set("watch.buffer_size", 8)
	path := filepath.Join(t.TempDir(), "capture with spaces.pcap")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	s := NewSettingsView("", 8, false, "", path)
	s.InstallCaptureConfiguration(RestartCaptureMsg{Mode: CaptureModeOffline, PCAPFiles: []string{path}, BufferSize: 123, Filter: "udp"})
	cmd := s.restartCapture()
	require.NotNil(t, cmd)
	msg := cmd().(RestartCaptureMsg)
	require.Equal(t, []string{path}, msg.PCAPFiles)
	require.Equal(t, 123, msg.BufferSize)
	require.Equal(t, 8, viper.GetInt("watch.buffer_size"), "unpublished replacement must not persist settings")
	s.SaveBufferSize()
	require.Equal(t, 123, viper.GetInt("watch.buffer_size"))
}
