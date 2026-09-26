//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

// settingsInputPoint locates an input value within the rendered viewport.
func settingsInputPoint(t *testing.T, s *SettingsView, value string) tea.MouseMsg {
	t.Helper()
	for y, line := range strings.Split(ansi.Strip(s.View()), "\n") {
		if index := strings.Index(line, value); index >= 0 {
			return tea.MouseMsg{
				X: ansi.StringWidth(line[:index]), Y: y,
				Button: tea.MouseButtonLeft, Action: tea.MouseActionPress,
			}
		}
	}
	t.Fatalf("input value %q is not visible", value)
	return tea.MouseMsg{}
}

func TestSettingsCenteredFieldClicks(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        CaptureMode
		width       int
		height      int
		scroll      int
		bufferField int
	}{
		{"live", CaptureModeLive, 200, 50, 0, 3},
		{"offline", CaptureModeOffline, 201, 51, 0, 2},
		{"remote", CaptureModeRemote, 200, 50, 0, 2},
		{"scrolled", CaptureModeLive, 200, 10, 8, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSettingsView("test0", 10000, false, "", "")
			s.SetCaptureMode(tc.mode)
			s.SetSize(tc.width, tc.height)
			s.View()
			s.viewport.SetYOffset(tc.scroll)

			// Locate the actual displayed input, independently of hit testing.
			for y, line := range strings.Split(ansi.Strip(s.View()), "\n") {
				index := strings.Index(line, "10000")
				if index < 0 {
					continue
				}
				// The rendered header and tabs occupy five terminal rows.
				click := tea.MouseMsg{Button: tea.MouseButtonLeft, Action: tea.MouseActionPress, Y: y + 5}
				// The new margin beside the form must not focus or edit it.
				s.Update(click)
				s.Update(click)
				require.Zero(t, s.focusIndex)
				require.False(t, s.IsEditing())

				click.X = ansi.StringWidth(line[:index]) + 4
				s.Update(click)
				require.Equal(t, tc.bufferField, s.focusIndex)
				s.Update(click)
				require.True(t, s.IsEditing())
				return
			}
			t.Fatal("buffer field is not visible")
		})
	}
}

func TestSettingsOutsideClickRestoresInputs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  CaptureMode
		field int
		value string
	}{
		{"live buffer", CaptureModeLive, 3, "512"},
		{"live filter", CaptureModeLive, 4, "udp"},
		{"offline buffer", CaptureModeOffline, 2, "512"},
		{"offline filter", CaptureModeOffline, 3, "udp"},
		{"remote buffer", CaptureModeRemote, 2, "512"},
	} {
		for _, size := range [][2]int{{200, 50}, {90, 12}} {
			t.Run(fmt.Sprintf("%s/%dx%d", tc.name, size[0], size[1]), func(t *testing.T) {
				s := NewSettingsView("test0", 10000, false, "tcp", "")
				s.SetCaptureMode(tc.mode)
				s.SetSize(200, 50)
				for range tc.field {
					s.Update(tea.KeyMsg{Type: tea.KeyDown})
				}
				s.Update(tea.KeyMsg{Type: tea.KeyEnter})
				require.True(t, s.IsEditing())
				s.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
				s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tc.value)})

				// Resize and scroll while editing to exercise the displayed bounds.
				s.SetSize(size[0], size[1])
				s.View()
				s.viewport.GotoBottom()
				inside := settingsInputPoint(t, &s, tc.value)
				require.Nil(t, s.CancelInputOnOutsideClick(inside))
				require.True(t, s.IsEditing())

				outside := inside
				outside.X = -1
				for _, gesture := range []tea.MouseMsg{
					{X: -1, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion},
					{X: -1, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease},
					{X: -1, Button: tea.MouseButtonRight, Action: tea.MouseActionPress},
					{X: -1, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress},
				} {
					require.Nil(t, s.CancelInputOnOutsideClick(gesture))
					require.True(t, s.IsEditing())
				}

				require.Nil(t, s.CancelInputOnOutsideClick(outside), "cancellation must not apply or restart capture")
				require.False(t, s.IsEditing())
				require.Equal(t, 10000, s.GetBufferSize())
				if tc.mode != CaptureModeRemote {
					require.Equal(t, "tcp", s.GetBPFFilter())
				}
			})
		}
	}
}

func TestSettingsOutsideClickResetsDoubleClick(t *testing.T) {
	s := NewSettingsView("test0", 10000, false, "", "")
	s.SetSize(200, 50)
	click := settingsInputPoint(t, &s, "10000")
	click.Y += 5 // Header and tabs.
	s.Update(click)
	s.Update(click)
	require.True(t, s.IsEditing())
	s.CancelInputOnOutsideClick(tea.MouseMsg{X: -1, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	require.False(t, s.IsEditing())
	s.Update(click)
	require.False(t, s.IsEditing(), "one click after cancelling must not resume editing")
	s.Update(click)
	require.True(t, s.IsEditing())
}
