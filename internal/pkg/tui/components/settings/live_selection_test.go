//go:build tui || all

package settings

import (
	"testing"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/require"
)

func TestInterfaceCheckboxRestoredAfterCancelledEdit(t *testing.T) {
	theme := themes.Solarized()
	ls := NewLiveSettings("enp58s0", 10000, true, "", theme)
	ls.interfaceList.SetItems([]list.Item{
		&settingItem{title: "any"}, &settingItem{title: "enp58s0"},
	})
	ls.interfaceList.Select(1)
	require.Contains(t, ls.interfaceList.View(), "[✓] enp58s0")
	ls.FocusField(1)
	ls.interfaceList.Select(0)
	ls.UpdateInterfaceList(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}, theme)
	require.Equal(t, "any", ls.GetInterface())
	require.False(t, ls.promiscuous)
	exit, _ := ls.UpdateInterfaceList(tea.KeyMsg{Type: tea.KeyEsc}, theme)
	require.True(t, exit)
	require.Equal(t, "enp58s0", ls.GetInterface())
	require.True(t, ls.promiscuous)
	require.Equal(t, 1, ls.interfaceList.Index())
	require.Contains(t, ls.interfaceList.View(), "[✓] enp58s0")
	require.Contains(t, ls.interfaceList.View(), "[ ] any")
}
