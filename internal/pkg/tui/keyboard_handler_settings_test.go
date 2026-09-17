//go:build tui || all

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestSettingsEnterCommitsEditedInput(t *testing.T) {
	m := NewModel(100, 8, "test0", "", nil, false, false, "", false)
	t.Cleanup(m.Shutdown)
	m.uiState.Tabs.SetActive(3)

	for range 3 {
		m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyDown})
	}
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyEnter})
	require.True(t, m.uiState.SettingsView.IsEditing())

	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyCtrlU})
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("256")})
	m, cmd := m.handleKeyboard(tea.KeyMsg{Type: tea.KeyEnter})

	require.False(t, m.uiState.SettingsView.IsEditing())
	require.Equal(t, 256, m.uiState.SettingsView.GetBufferSize())
	require.NotNil(t, cmd)
	require.Equal(t, components.UpdateBufferSizeMsg{Size: 256}, cmd())
}
