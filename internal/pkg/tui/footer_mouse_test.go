//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/stretchr/testify/require"
)

func footerMouseModel(t *testing.T, tab int) Model {
	t.Helper()
	m := NewModel(128, 8, "test0", "", nil, false, false, "", false)
	t.Cleanup(m.Shutdown)
	m.uiState.Tabs.SetActive(tab)
	return updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 240, Height: 40})
}

// Locate clicks in the rendered labels, independently of the hit-test API.
func footerMousePress(t *testing.T, m Model, label string) tea.MouseMsg {
	t.Helper()
	lines := strings.Split(ansi.Strip(m.uiState.Footer.View()), "\n")
	line := lines[len(lines)-1]
	index := strings.Index(line, label)
	require.NotEqual(t, -1, index, "missing footer label %q in %q", label, line)
	x := ansi.StringWidth(line[:index]) + ansi.StringWidth(label)/2
	require.Less(t, x, m.uiState.Width)
	return selectionPress(x, m.uiState.Height-1)
}

func clickFooterHint(t *testing.T, m Model, label string) Model {
	t.Helper()
	return updateEventRenderModel(t, m, footerMousePress(t, m, label))
}

func TestFooterMouseActionsOnEveryTab(t *testing.T) {
	t.Run("capture", func(t *testing.T) {
		m := footerMouseModel(t, 0)
		m = clickFooterHint(t, m, "d: details")
		require.True(t, m.uiState.ShowDetails)
		m = clickFooterHint(t, m, "/: filter")
		require.True(t, m.uiState.FilterMode)
	})
	t.Run("nodes", func(t *testing.T) {
		m := footerMouseModel(t, 1)
		m = clickFooterHint(t, m, "a: add")
		require.True(t, m.uiState.NodesView.IsModalOpen())
	})
	t.Run("statistics", func(t *testing.T) {
		m := footerMouseModel(t, 2)
		m = clickFooterHint(t, m, "2: distributed")
		require.Equal(t, components.SubViewDistributed, m.uiState.StatisticsView.GetSubView())
		m = clickFooterHint(t, m, "1: overview")
		require.Equal(t, components.SubViewOverview, m.uiState.StatisticsView.GetSubView())
	})
	t.Run("settings", func(t *testing.T) {
		m := footerMouseModel(t, 3)
		for range 3 {
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
		}
		m = clickFooterHint(t, m, "Enter: edit/toggle")
		require.True(t, m.uiState.SettingsView.IsEditing())
		m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
		m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("256")})
		m = clickFooterHint(t, m, "Esc: cancel")
		require.False(t, m.uiState.SettingsView.IsEditing())
		require.Equal(t, 128, m.uiState.SettingsView.GetBufferSize())
	})
	t.Run("help", func(t *testing.T) {
		m := footerMouseModel(t, 4)
		m = clickFooterHint(t, m, "3: commands")
		require.Equal(t, components.SectionCommands, m.uiState.HelpView.GetActiveSection())
		m = clickFooterHint(t, m, "/: search")
		require.True(t, m.uiState.HelpView.IsSearchMode())
	})
}

func TestFooterMouseGlobalActionsOnEveryTab(t *testing.T) {
	for tab := range 5 {
		t.Run(fmt.Sprintf("tab-%d", tab), func(t *testing.T) {
			m := footerMouseModel(t, tab)
			m = clickFooterHint(t, m, "Space: pause")
			require.True(t, m.uiState.Paused)
			m = clickFooterHint(t, m, "Space: resume")
			require.False(t, m.uiState.Paused)
			m = clickFooterHint(t, m, "p: protocol")
			require.True(t, m.uiState.ProtocolSelector.IsActive())
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
			require.False(t, m.uiState.ProtocolSelector.IsActive())
			m = clickFooterHint(t, m, "q: quit")
			require.True(t, m.uiState.ConfirmDialog.IsActive())
			require.False(t, m.uiState.Quitting, "clicking quit must preserve keyboard confirmation")
		})
	}
}

func TestFooterMouseSettingsInterfaceEditor(t *testing.T) {
	m := footerMouseModel(t, 3)
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m = clickFooterHint(t, m, "Enter: edit/toggle")
	require.True(t, m.uiState.SettingsView.IsEditingInterface())
	// This editor intercepts input before the usual keyboard/mouse handlers.
	// Quit opens confirmation without committing interface settings to disk.
	m = clickFooterHint(t, m, "q: quit")
	require.True(t, m.uiState.ConfirmDialog.IsActive())
	require.True(t, m.uiState.SettingsView.IsEditingInterface())
}

func TestFooterMouseSpacePreservesSettingsTextInput(t *testing.T) {
	m := footerMouseModel(t, 3)
	for range 4 {
		m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	m = clickFooterHint(t, m, "Enter: edit/toggle")
	require.True(t, m.uiState.SettingsView.IsEditing())
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("tcp")})
	m = clickFooterHint(t, m, "Space: pause")
	require.Equal(t, "tcp ", m.uiState.SettingsView.GetBPFFilter())
	require.False(t, m.uiState.Paused, "editing must retain the keyboard input priority")
	m = clickFooterHint(t, m, "Esc: cancel")
	require.False(t, m.uiState.SettingsView.IsEditing())
	require.Empty(t, m.uiState.SettingsView.GetBPFFilter())
}

func TestFooterMouseFilterActions(t *testing.T) {
	for _, mode := range []string{"packets", "calls", "events"} {
		for _, action := range []string{"Enter: apply", "Esc: cancel"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				m := footerMouseModel(t, 0)
				m.uiState.ViewMode = mode
				var input *components.FilterInput
				var hasFilter func() bool
				switch mode {
				case "packets":
					m.packetStore.AddFilter(filters.NewTextFilter("dns", nil))
					input = &m.uiState.FilterInput
					hasFilter = m.packetStore.HasFilter
				case "calls":
					m.callStore.AddFilter(filters.NewTextFilter("alice", nil))
					input = &m.uiState.CallFilterInput
					hasFilter = m.callStore.HasFilter
				case "events":
					require.NoError(t, m.eventStore.AddUserFilter("kind:dns"))
					input = &m.uiState.EventFilterInput
					hasFilter = m.eventStore.HasUserFilters
				}
				m.prepareViewChrome()
				m = clickFooterHint(t, m, "/: filter")
				require.True(t, input.IsActive())
				input.SetHistory([]string{"newest", "oldest"})
				m = clickFooterHint(t, m, "↑: older history")
				require.Equal(t, "newest", input.Value())
				m = clickFooterHint(t, m, "↑: older history")
				require.Equal(t, "oldest", input.Value())
				m = clickFooterHint(t, m, "↓: newer history")
				require.Equal(t, "newest", input.Value())
				m = clickFooterHint(t, m, "↓: newer history")
				require.Empty(t, input.Value())
				// Empty Enter clears filters without writing filter history.
				m = clickFooterHint(t, m, action)
				require.False(t, input.IsActive())
				require.False(t, m.uiState.FilterMode || m.uiState.CallFilterMode || m.uiState.EventFilterMode)
				require.Equal(t, action == "Esc: cancel", hasFilter())
			})
		}
	}
}

func TestFooterMouseIgnoresNonHintClicksAndNonPresses(t *testing.T) {
	m := footerMouseModel(t, 0)
	press := footerMousePress(t, m, "d: details")
	footerLines := strings.Split(ansi.Strip(m.uiState.Footer.View()), "\n")
	footer := footerLines[len(footerLines)-1]
	columnOf := func(text string) int {
		index := strings.Index(footer, text)
		require.NotEqual(t, -1, index)
		return ansi.StringWidth(footer[:index])
	}
	cases := map[string]tea.MouseMsg{
		"release":           {X: press.X, Y: press.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease},
		"motion":            {X: press.X, Y: press.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion},
		"right button":      {X: press.X, Y: press.Y, Button: tea.MouseButtonRight, Action: tea.MouseActionPress},
		"wheel":             {X: press.X, Y: press.Y, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress},
		"above footer":      selectionPress(press.X, press.Y-1),
		"below footer":      selectionPress(press.X, press.Y+1),
		"negative column":   selectionPress(-1, press.Y),
		"beyond width":      selectionPress(m.uiState.Width, press.Y),
		"leading padding":   selectionPress(0, press.Y),
		"hint separator":    selectionPress(columnOf("│"), press.Y),
		"section separator": selectionPress(columnOf("║"), press.Y),
		"version":           selectionPress(columnOf("🫦"), press.Y),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			m = updateEventRenderModel(t, m, msg)
			require.False(t, m.uiState.ShowDetails)
			require.False(t, m.uiState.FilterMode)
			require.False(t, m.uiState.Paused)
			require.False(t, m.uiState.ProtocolSelector.IsActive())
			require.False(t, m.uiState.ConfirmDialog.IsActive())
		})
	}
	// A complete click toggles once; its release must not toggle back.
	m = updateEventRenderModel(t, m, press)
	require.True(t, m.uiState.ShowDetails)
	press.Action = tea.MouseActionRelease
	m = updateEventRenderModel(t, m, press)
	require.True(t, m.uiState.ShowDetails)
}

func TestFooterMouseDoesNotActivateHintsBehindOverlays(t *testing.T) {
	cases := map[string]func(*Model){
		"protocol selector": func(m *Model) { m.uiState.ProtocolSelector.Activate() },
		"hunter selector":   func(m *Model) { m.uiState.HunterSelector.Activate("test-processor") },
		"filter manager": func(m *Model) {
			m.uiState.FilterManager.Activate("test-processor", "test-processor", components.NodeTypeProcessor)
		},
		"settings file dialog": func(m *Model) { m.uiState.SettingsView.GetPcapFileDialog().Activate() },
		"save file dialog":     func(m *Model) { m.uiState.FileDialog.Activate() },
		"confirmation":         func(m *Model) { m.uiState.ConfirmDialog.Activate("Confirm test action?") },
		"add node":             func(m *Model) { m.uiState.NodesView.ShowAddNodeModal() },
		"dev console":          func(m *Model) { m.uiState.DevConsole.Toggle() },
		"offline opening":      func(m *Model) { m.offlineOpening = true },
		"offline filtering":    func(m *Model) { m.offlineFilter = &offlineFilterState{} },
	}
	for name, activate := range cases {
		t.Run(name, func(t *testing.T) {
			m := footerMouseModel(t, 0)
			press := footerMousePress(t, m, "d: details")
			activate(&m)
			m = updateEventRenderModel(t, m, press)
			require.False(t, m.uiState.ShowDetails)
		})
	}
}

func TestFooterMouseRowMatchesRenderedFooter(t *testing.T) {
	for _, width := range []int{60, 100, 240} {
		for tab := range 5 {
			t.Run(fmt.Sprintf("width-%d/tab-%d", width, tab), func(t *testing.T) {
				m := footerMouseModel(t, tab)
				m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: width, Height: 30})
				checkFooterRow := func() {
					t.Helper()
					lines := strings.Split(ansi.Strip(m.View()), "\n")
					require.GreaterOrEqual(t, len(lines), m.uiState.Height)
					// Bubble Tea drops excess rows from the top of the view.
					visible := lines[len(lines)-m.uiState.Height:]
					footer := strings.Split(ansi.Strip(m.uiState.Footer.View()), "\n")
					require.Equal(t, ansi.Truncate(footer[len(footer)-1], width, ""), ansi.Truncate(visible[m.uiState.Height-1], width, ""))
				}
				checkFooterRow()
				m.uiState.Toast.Show("A notification\nwith several lines\nabove the footer", components.ToastInfo, components.ToastDurationLong)
				checkFooterRow()
				if tab == 0 {
					m.uiState.Toast.Hide()
					m.uiState.FilterMode = true
					m.uiState.FilterInput.Activate()
					for _, r := range strings.Repeat("long filter ", 30) {
						m.uiState.FilterInput.InsertRune(r)
					}
					m.prepareViewChrome()
					checkFooterRow()
				}
			})
		}
	}
}
