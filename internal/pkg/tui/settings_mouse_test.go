//go:build tui || all

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func settingsMouseEditingBuffer(t *testing.T) Model {
	t.Helper()
	m := footerMouseModel(t, 3)
	for range 3 {
		m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("256")})
	require.True(t, m.uiState.SettingsView.IsEditing())
	require.Equal(t, 256, m.uiState.SettingsView.GetBufferSize())
	return m
}

func settingsMouseLabel(t *testing.T, m Model, label string) tea.MouseMsg {
	t.Helper()
	for y, line := range strings.Split(ansi.Strip(m.View()), "\n") {
		if index := strings.Index(line, label); index >= 0 {
			return selectionPress(ansi.StringWidth(line[:index])+ansi.StringWidth(label)/2, y)
		}
	}
	t.Fatalf("settings label %q is not visible", label)
	return tea.MouseMsg{}
}

func TestSettingsMouseOutsideClickCancelsInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		click func(*testing.T, Model) tea.MouseMsg
		tab   int
	}{
		{"header", func(_ *testing.T, _ Model) tea.MouseMsg { return selectionPress(1, 0) }, 3},
		{"tab", func(t *testing.T, m Model) tea.MouseMsg { return settingsMouseLabel(t, m, "Nodes") }, 1},
		{"empty footer", func(t *testing.T, m Model) tea.MouseMsg {
			click := selectionPress(m.uiState.Width-30, m.uiState.Height-1)
			_, hit := m.footerKeyAtMouse(click)
			require.False(t, hit, "test click must miss all footer hints")
			return click
		}, 3},
		{"form margin", func(t *testing.T, m Model) tea.MouseMsg {
			click := settingsMouseLabel(t, m, "Buffer Size:")
			click.X = 0
			return click
		}, 3},
		{"other field", func(t *testing.T, m Model) tea.MouseMsg {
			return settingsMouseLabel(t, m, "Capture Filter:")
		}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := settingsMouseEditingBuffer(t)
			m = updateEventRenderModel(t, m, tc.click(t, m))
			require.False(t, m.uiState.SettingsView.IsEditing())
			require.Equal(t, 128, m.uiState.SettingsView.GetBufferSize())
			require.Equal(t, tc.tab, m.uiState.Tabs.GetActive())
			if tc.name == "other field" {
				// The original click must still focus the destination field.
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("udp")})
				require.True(t, m.uiState.SettingsView.IsEditing())
				require.Equal(t, "udp", m.uiState.SettingsView.GetBPFFilter())
			}
		})
	}
}

func TestSettingsMouseActiveFieldKeepsInput(t *testing.T) {
	for _, position := range []string{"input", "left border", "right border", "top border", "bottom border"} {
		t.Run(position, func(t *testing.T) {
			m := settingsMouseEditingBuffer(t)
			click := settingsMouseLabel(t, m, "Buffer Size:")
			line := strings.Split(ansi.Strip(m.View()), "\n")[click.Y]
			left := ansi.StringWidth(line) - ansi.StringWidth(strings.TrimLeft(line, " "))
			right := ansi.StringWidth(strings.TrimRight(line, " ")) - 1
			switch position {
			case "input":
				index := strings.Index(line, "256")
				require.NotEqual(t, -1, index)
				click.X = ansi.StringWidth(line[:index]) + 1
			case "left border":
				click.X = left
			case "right border":
				click.X = right
			case "top border":
				click.X, click.Y = left, click.Y-1
			case "bottom border":
				click.X, click.Y = right, click.Y+1
			}
			m = updateEventRenderModel(t, m, click)
			require.True(t, m.uiState.SettingsView.IsEditing())
			require.Equal(t, 256, m.uiState.SettingsView.GetBufferSize())
		})
	}
}

func TestSettingsMouseFooterEnterCommitsInput(t *testing.T) {
	m := settingsMouseEditingBuffer(t)
	m = clickFooterHint(t, m, "Enter: edit/toggle")
	require.False(t, m.uiState.SettingsView.IsEditing())
	require.Equal(t, 256, m.uiState.SettingsView.GetBufferSize())
}

func TestSettingsMouseOverlayDoesNotCancelInput(t *testing.T) {
	for name, activate := range map[string]func(*Model){
		"confirmation":         func(m *Model) { m.uiState.ConfirmDialog.Activate("Confirm test action?") },
		"protocol selector":    func(m *Model) { m.uiState.ProtocolSelector.Activate() },
		"settings file dialog": func(m *Model) { m.uiState.SettingsView.GetPcapFileDialog().Activate() },
		"dev console":          func(m *Model) { m.uiState.DevConsole.Toggle() },
	} {
		t.Run(name, func(t *testing.T) {
			m := settingsMouseEditingBuffer(t)
			activate(&m)
			m = updateEventRenderModel(t, m, selectionPress(1, 0))
			require.True(t, m.uiState.SettingsView.IsEditing())
			require.Equal(t, 256, m.uiState.SettingsView.GetBufferSize())
		})
	}
}
