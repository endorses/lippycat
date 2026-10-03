//go:build tui || all

package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNodesHighlightingPreferencePersistence(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("watch:\n  nodes_highlighting: normal\n"), 0600))
	viper.SetConfigFile(path)
	require.NoError(t, viper.ReadInConfig())
	saveNodesHighlightingPreference("quiet")
	saved := viper.New()
	saved.SetConfigFile(path)
	require.NoError(t, saved.ReadInConfig())
	require.Equal(t, "quiet", saved.GetString("watch.nodes_highlighting"))
	require.Equal(t, "quiet", loadNodesHighlightingPreference())

	saveNodesHighlightingPreference("invalid")
	require.Equal(t, "quiet", loadNodesHighlightingPreference())
}

func TestNodesHighlightingPreferenceSaveFailureRetainsSessionValue(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(filepath.Join(t.TempDir(), "missing", "config.yaml"))
	saveNodesHighlightingPreference("quiet")
	require.Equal(t, "quiet", loadNodesHighlightingPreference())
}
