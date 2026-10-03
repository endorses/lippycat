//go:build tui || all

package components

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestSettingsInterfaceCancelPreservesStartupSelection(t *testing.T) {
	for _, iface := range []string{"enp58s0", "enp58s0,wlan0", "any"} {
		for _, mouse := range []bool{false, true} {
			t.Run(iface+map[bool]string{false: "/keyboard", true: "/mouse"}[mouse], func(t *testing.T) {
				s := NewSettingsView(iface, 10000, false, "", "")
				s.SetSize(100, 40)
				for range 2 {
					require.Equal(t, iface, s.GetInterface())
					if mouse {
						click := settingsInputPoint(t, &s, "Interfaces:")
						click.Y += 5
						s.Update(click)
						s.Update(click)
					} else {
						s.focusIndex = 1
						s.Update(tea.KeyMsg{Type: tea.KeyEnter})
					}
					require.True(t, s.IsEditingInterface())
					cmd := s.Update(tea.KeyMsg{Type: tea.KeyEsc})
					require.Nil(t, cmd, "cancelling must not restart capture")
					require.False(t, s.IsEditingInterface())
					require.Equal(t, iface, s.GetInterface())
				}
			})
		}
	}
}
