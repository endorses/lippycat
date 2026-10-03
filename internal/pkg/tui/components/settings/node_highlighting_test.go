//go:build tui || all

package settings

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNodesHighlightingPreference(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, tc := range []struct{ value, want string }{
		{"", "normal"}, {"normal", "normal"}, {"quiet", "quiet"}, {"invalid", "normal"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			viper.Set("watch.nodes_highlighting", tc.value)
			require.Equal(t, tc.want, LoadNodesHighlightingPreference())
		})
	}
}

func TestRemoteHighlightingToggleDoesNotRestart(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("watch.nodes_highlighting", "quiet")
	rs := NewRemoteSettings("", 10000, themes.Solarized())
	for _, want := range []string{"normal", "quiet"} {
		result := rs.HandleKey("enter", KeyHandlerParams{FocusIndex: 3})
		require.False(t, result.Editing)
		require.False(t, result.TriggerRestart)
		require.False(t, result.TriggerBufferUpdate)
		require.NotNil(t, result.Cmd)
		require.Equal(t, UpdateNodesHighlightingMsg{Mode: want}, result.Cmd())
	}
}
