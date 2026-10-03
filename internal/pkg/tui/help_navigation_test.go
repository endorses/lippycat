//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestHelpTopBottomBindings(t *testing.T) {
	m := footerMouseModel(t, 4)
	lines := make([]string, 80)
	for i := range lines {
		lines[i] = fmt.Sprintf("Help row %02d", i)
	}
	m.uiState.HelpView.HandleContentLoaded(components.HelpContentLoadedMsg{
		Section: components.SectionKeybindings, RenderedContent: strings.Join(lines, "\n"),
	})
	for _, keys := range []struct {
		name        string
		top, bottom tea.KeyMsg
	}{
		{"Home/End", tea.KeyMsg{Type: tea.KeyHome}, tea.KeyMsg{Type: tea.KeyEnd}},
		{"g/G", tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}}, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}}},
	} {
		t.Run(keys.name, func(t *testing.T) {
			m = updateEventRenderModel(t, m, keys.bottom)
			require.Contains(t, m.uiState.HelpView.View(), "Help row 79")
			require.NotContains(t, m.uiState.HelpView.View(), "Help row 00")
			m = updateEventRenderModel(t, m, keys.top)
			require.Contains(t, m.uiState.HelpView.View(), "Help row 00")
			require.NotContains(t, m.uiState.HelpView.View(), "Help row 79")
		})
	}
	m = clickFooterHint(t, m, "G: bottom")
	require.Contains(t, m.uiState.HelpView.View(), "Help row 79")
	m = clickFooterHint(t, m, "g: top")
	require.Contains(t, m.uiState.HelpView.View(), "Help row 00")
	m.uiState.HelpView.EnterSearchMode()
	m = responsiveDetailKey(t, m, 'g')
	m = responsiveDetailKey(t, m, 'G')
	require.Equal(t, "gG", m.uiState.HelpView.GetSearchQuery())
}
