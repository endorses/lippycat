//go:build tui || all

package components

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/require"
)

// A new dialog needs only the common lifecycle contract, with no mouse handler.
type exampleModal struct {
	options   ModalRenderOptions
	dismissed bool
}

func (m *exampleModal) View() string { return RenderModal(m.options) }
func (m *exampleModal) Dismiss() tea.Cmd {
	m.dismissed = true
	return func() tea.Msg { return "cancelled" }
}

func TestModalMouseBehaviorIsShared(t *testing.T) {
	dialog := &exampleModal{options: ModalRenderOptions{
		Title: "Example", Content: "\x1b[31m界 e\u0301\x1b[0m\n\nBody", Footer: "Esc: Cancel",
		Width: 120, Height: 40, Theme: themes.Solarized(), ModalWidth: 60,
	}}
	inside := tea.MouseMsg{X: 60, Y: 20, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
	cmd, handled := HandleModalMouse(dialog, inside, 120, 40)
	require.False(t, handled)
	require.Nil(t, cmd)
	require.False(t, dialog.dismissed)

	outside := inside
	outside.X, outside.Y = 0, 0
	cmd, handled = HandleModalMouse(dialog, outside, 120, 40)
	require.True(t, handled)
	require.True(t, dialog.dismissed)
	require.NotNil(t, cmd)
	require.Equal(t, "cancelled", cmd())
}

func TestModalMouseKeepsClippedContentInside(t *testing.T) {
	dialog := &exampleModal{options: ModalRenderOptions{
		Title: "Tall modal", Content: "One\nTwo\nThree\nFour\nFive\nSix",
		Width: 100, Height: 5, Theme: themes.Solarized(), ModalWidth: 60,
	}}
	// The terminal keeps the bottom of the over-height canvas. Its top visible
	// row is still part of the modal, even though the top border is off screen.
	click := tea.MouseMsg{X: 50, Y: 0, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
	_, handled := HandleModalMouse(dialog, click, 100, 5)
	require.False(t, handled)
	require.False(t, dialog.dismissed)
	click.X = 0
	_, handled = HandleModalMouse(dialog, click, 100, 5)
	require.True(t, handled)
}
