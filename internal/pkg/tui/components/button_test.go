//go:build tui || all

package components

import (
	"image"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"
)

type buttonTestModal struct {
	options ModalRenderOptions
	state   ModalState
	actions []string
	focus   []string
}

func (m *buttonTestModal) View() string     { return RenderModal(m.ModalOptions()) }
func (m *buttonTestModal) Dismiss() tea.Cmd { m.actions = append(m.actions, "dismiss"); return nil }
func (m *buttonTestModal) ModalOptions() ModalRenderOptions {
	opts := m.options
	opts.State = &m.state
	return opts
}
func (m *buttonTestModal) HandleModalAction(id string) tea.Cmd {
	m.actions = append(m.actions, id)
	return nil
}
func (m *buttonTestModal) HandleModalFocus(id string) tea.Cmd {
	m.focus = append(m.focus, id)
	return nil
}
func newButtonTestModal() *buttonTestModal {
	return &buttonTestModal{options: ModalRenderOptions{ID: "test", Title: "Actions", Content: "Editable field\nBody", Width: 83, Height: 25, ModalWidth: 50, Theme: themes.Solarized(),
		Targets: []ModalTarget{{ID: "field", Bounds: image.Rect(0, 0, 14, 1), Focusable: true}},
		Actions: []ModalAction{{ID: "save", Label: "Save", Shortcut: "Enter", Kind: ButtonPrimary}, {ID: "disabled", Label: "Delete", Disabled: true, Kind: ButtonDanger}, {ID: "cancel", Label: "Cancel", Shortcut: "Esc"}}}}
}
func buttonHit(t *testing.T, m *buttonTestModal, id string) ModalTarget {
	t.Helper()
	for _, hit := range LayoutModal(m.ModalOptions()).Hits {
		if hit.ID == id {
			return hit
		}
	}
	t.Fatalf("missing hit %s", id)
	return ModalTarget{}
}
func buttonPress(point image.Point) tea.MouseMsg {
	return tea.MouseMsg{X: point.X, Y: point.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
}

func TestButtonsUseRenderedCellGeometry(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	m := newButtonTestModal()
	m.options.Actions[0].Label = "保存 e\u0301"
	for _, width := range []int{83, 44, 25} {
		m.options.Width = width
		layout := LayoutModal(m.ModalOptions())
		require.False(t, layout.Fallback)
		lines := strings.Split(ansi.Strip(layout.View), "\n")
		for _, hit := range layout.Hits {
			if hit.ID == "field" {
				continue
			}
			line := ansi.Cut(lines[hit.Bounds.Min.Y], hit.Bounds.Min.X, hit.Bounds.Max.X)
			require.True(t, strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "▸ "), line)
			require.Equal(t, hit.Bounds.Dx(), ansi.StringWidth(line))
		}
		// The displayed button padding is clickable; the gap after it is not.
		hit := buttonHit(t, m, "save")
		_, handled := HandleModalInput(m, buttonPress(hit.Bounds.Min.Add(image.Pt(1, 0))))
		require.True(t, handled)
		require.Equal(t, "save", m.actions[len(m.actions)-1])
		count := len(m.actions)
		HandleModalInput(m, buttonPress(image.Pt(hit.Bounds.Max.X, hit.Bounds.Min.Y)))
		require.Len(t, m.actions, count)
	}
}

func TestButtonsFocusDisabledAndContextShortcuts(t *testing.T) {
	m := newButtonTestModal()
	m.options.Actions[0].Keys = []string{"s"}
	m.state.Focus = "field"
	_, handled := HandleModalInput(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	require.False(t, handled, "typing in a field must reach its editor")
	HandleModalInput(m, tea.KeyMsg{Type: tea.KeyTab})
	require.Equal(t, "save", m.state.Focus)
	HandleModalInput(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	require.Equal(t, []string{"save"}, m.actions)
	HandleModalInput(m, tea.KeyMsg{Type: tea.KeyTab})
	require.Equal(t, "cancel", m.state.Focus, "disabled action skipped")
	HandleModalInput(m, tea.KeyMsg{Type: tea.KeyEnter})
	require.Equal(t, "cancel", m.actions[1])
	count := len(m.actions)
	hit := buttonHit(t, m, "disabled")
	HandleModalInput(m, buttonPress(hit.Bounds.Min))
	require.Len(t, m.actions, count)
	press := buttonPress(buttonHit(t, m, "save").Bounds.Min)
	HandleModalInput(m, press)
	press.Action = tea.MouseActionRelease
	HandleModalInput(m, press)
	require.Len(t, m.actions, count+1)
}

func TestButtonsLayoutIsPureAndResizesBeforeRender(t *testing.T) {
	m := newButtonTestModal()
	m.state.Focus = "save"
	before := m.state
	m.View()
	LayoutModal(m.ModalOptions())
	require.Equal(t, before, m.state)
	m.options.Width = 35
	m.options.Height = 18
	hit := buttonHit(t, m, "save")
	HandleModalInput(m, buttonPress(hit.Bounds.Min))
	require.Equal(t, []string{"save"}, m.actions)
	m.options.Actions[0].Disabled = true
	HandleModalInput(m, tea.KeyMsg{Type: tea.KeyTab})
	require.NotEqual(t, "save", m.state.Focus)
}

func TestButtonsKeepActionsVisibleWhenContentScrolls(t *testing.T) {
	m := newButtonTestModal()
	m.options.Height = 14
	m.options.Content = strings.Repeat("Scrollable row\n", 30) + "Last field"
	m.options.Targets = append(m.options.Targets, ModalTarget{ID: "last", Bounds: image.Rect(0, 30, 10, 31), Focusable: true})
	layout := LayoutModal(m.ModalOptions())
	require.Less(t, layout.ContentHeight, layout.FullContentHeight)
	save := buttonHit(t, m, "save").Bounds
	EnsureModalTargetVisible(m.ModalOptions(), "last")
	require.Positive(t, m.state.Scroll)
	require.Equal(t, save, buttonHit(t, m, "save").Bounds)
	require.NotEmpty(t, buttonHit(t, m, "last").Bounds)
	for _, size := range []image.Point{{10, 3}, {2, 1}, {30, 4}} {
		m.options.Width, m.options.Height = size.X, size.Y
		layout = LayoutModal(m.ModalOptions())
		require.True(t, layout.Fallback)
		require.LessOrEqual(t, ansi.StringWidth(strings.Split(layout.View, "\n")[0]), size.X)
		require.Empty(t, layout.Hits)
		_, handled := HandleModalInput(m, tea.KeyMsg{Type: tea.KeyEsc})
		require.False(t, handled, "owner retains Esc cleanup in fallback")
	}
}

func TestModalWrappedWideGlyphTarget(t *testing.T) {
	m := newButtonTestModal()
	m.options.Width = 25
	width := ModalContentWidth(m.ModalOptions())
	// A two-cell glyph moves to the next line when only one cell remains.
	m.options.Content = strings.Repeat("x", width-1) + "界Z"
	m.options.Targets = []ModalTarget{{ID: "wide", Bounds: image.Rect(width-1, 0, width+1, 1)}}
	layout := LayoutModal(m.ModalOptions())
	var found bool
	for _, hit := range layout.Hits {
		if hit.ID != "wide" {
			continue
		}
		found = true
		row := strings.Split(ansi.Strip(layout.View), "\n")[hit.Bounds.Min.Y]
		require.Equal(t, "界", ansi.Cut(row, hit.Bounds.Min.X, hit.Bounds.Max.X))
	}
	require.True(t, found)
}

func TestButtonsMouseActivationPreservesContentFocus(t *testing.T) {
	for _, initial := range []string{"", "field", "save", "cancel"} {
		t.Run("focus="+initial, func(t *testing.T) {
			m := newButtonTestModal()
			m.state.Focus = initial
			HandleModalInput(m, buttonPress(buttonHit(t, m, "save").Bounds.Min))
			require.Equal(t, []string{"save"}, m.actions)
			if initial == "" {
				require.Empty(t, m.state.Focus)
			} else {
				require.Equal(t, "field", m.state.Focus)
			}
			_, handled := HandleModalInput(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
			require.False(t, handled, "typing must still reach the content")
			HandleModalInput(m, tea.KeyMsg{Type: tea.KeyShiftTab})
			require.Equal(t, "cancel", m.state.Focus, "keyboard navigation still focuses buttons")
			HandleModalInput(m, tea.KeyMsg{Type: tea.KeyEnter})
			require.Equal(t, []string{"save", "cancel"}, m.actions)
			require.Equal(t, "cancel", m.state.Focus, "keyboard activation retains focus")
		})
	}
}
