//go:build tui || all

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuitKeysShowConfirmationDialog(t *testing.T) {
	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'q'}},
		{Type: tea.KeyCtrlC},
	} {
		t.Run(key.String(), func(t *testing.T) {
			m := Model{uiState: store.NewUIState(themes.Solarized())}

			updated, cmd := m.Update(key)
			updatedModel := updated.(Model)

			assert.True(t, updatedModel.uiState.ConfirmDialog.IsActive())
			assert.False(t, updatedModel.uiState.Quitting)
			assert.Nil(t, cmd)
		})
	}
}

func TestQuitConfirmationCanBeCancelled(t *testing.T) {
	m := Model{uiState: store.NewUIState(themes.Solarized())}
	m, _ = m.requestQuitConfirmation()

	updated, resultCmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.NotNil(t, resultCmd)
	result := resultCmd()
	confirmResult, ok := result.(components.ConfirmDialogResult)
	require.True(t, ok)

	updated, quitCmd := updated.(Model).Update(confirmResult)
	updatedModel := updated.(Model)

	assert.False(t, updatedModel.uiState.ConfirmDialog.IsActive())
	assert.False(t, updatedModel.uiState.Quitting)
	assert.Nil(t, quitCmd)
}

func TestQuitConfirmationReceivesInputWhileEditingSettingsInterface(t *testing.T) {
	m := Model{uiState: store.NewUIState(themes.Solarized())}
	m.uiState.Tabs.SetActive(3)
	m.uiState.SettingsView = components.NewSettingsView("any", 100, false, "", "")
	m.uiState.SettingsView.Update(tea.KeyMsg{Type: tea.KeyDown})
	m.uiState.SettingsView.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.True(t, m.uiState.SettingsView.IsEditingInterface())

	m, _ = m.requestQuitConfirmation()
	updated, resultCmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})

	require.NotNil(t, resultCmd)
	assert.False(t, updated.(Model).uiState.ConfirmDialog.IsActive())
	assert.IsType(t, components.ConfirmDialogResult{}, resultCmd())
}

func TestQuitConfirmationQuitsWhenConfirmed(t *testing.T) {
	m := Model{uiState: store.NewUIState(themes.Solarized())}
	m, _ = m.requestQuitConfirmation()

	updated, resultCmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	require.NotNil(t, resultCmd)
	result := resultCmd()
	confirmResult, ok := result.(components.ConfirmDialogResult)
	require.True(t, ok)

	updated, quitCmd := updated.(Model).Update(confirmResult)
	updatedModel := updated.(Model)

	assert.True(t, updatedModel.uiState.Quitting)
	require.NotNil(t, quitCmd)
	assert.IsType(t, tea.QuitMsg{}, quitCmd())
}
