//go:build tui || all

package components

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestSettingsNodesHighlightingKeyboardAndMouse(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	for _, mouse := range []bool{false, true} {
		s := NewSettingsView("any", 10000, false, "", "")
		s.SetCaptureMode(CaptureModeRemote)
		s.SetSize(160, 40)
		var cmd tea.Cmd
		if mouse {
			point := settingsInputPoint(t, &s, "Nodes highlighting:")
			point.Y += 5
			require.Nil(t, s.Update(point))
			cmd = s.Update(point)
		} else {
			for range 3 {
				s.Update(tea.KeyMsg{Type: tea.KeyDown})
			}
			cmd = s.Update(tea.KeyMsg{Type: tea.KeyEnter})
		}
		require.NotNil(t, cmd)
		require.Equal(t, UpdateNodesHighlightingMsg{Mode: "quiet"}, cmd())
		require.False(t, s.IsEditing())
		require.Contains(t, s.View(), "quiet")
	}
}
