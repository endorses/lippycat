//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

// Find the visible modal edges from terminal output, independently of the
// implementation's hit testing. Bubble Tea retains the last rows on overflow.
func modalMouseEdges(t *testing.T, m Model) (left, top, right, bottom int) {
	t.Helper()
	lines := strings.Split(ansi.Strip(m.View()), "\n")
	if len(lines) > m.uiState.Height {
		lines = lines[len(lines)-m.uiState.Height:]
	}
	left, top, right, bottom = m.uiState.Width, len(lines), -1, -1
	for y, line := range lines {
		line = ansi.Truncate(line, m.uiState.Width, "")
		if strings.TrimSpace(line) == "" {
			continue
		}
		left = min(left, ansi.StringWidth(line)-ansi.StringWidth(strings.TrimLeft(line, " ")))
		right = max(right, ansi.StringWidth(strings.TrimRight(line, " "))-1)
		top = min(top, y)
		bottom = y
	}
	require.Less(t, left, right, "modal must have visible content")
	require.Less(t, top, bottom, "modal must have visible content")
	return
}

func TestModalMouseOutsideClickClosesEveryModal(t *testing.T) {
	cases := []struct {
		name     string
		tab      int
		activate func(*Model)
		active   func(Model) bool
	}{
		{"confirmation", 0,
			func(m *Model) { m.uiState.ConfirmDialog.Activate("Confirm test action?") },
			func(m Model) bool { return m.uiState.ConfirmDialog.IsActive() }},
		{"protocol selector", 0,
			func(m *Model) { m.uiState.ProtocolSelector.Activate() },
			func(m Model) bool { return m.uiState.ProtocolSelector.IsActive() }},
		{"hunter selector", 1,
			func(m *Model) { m.uiState.HunterSelector.Activate("test-processor") },
			func(m Model) bool { return m.uiState.HunterSelector.IsActive() }},
		{"filter manager", 1,
			func(m *Model) {
				m.uiState.FilterManager.Activate("test-processor", "test-processor", components.NodeTypeProcessor)
			},
			func(m Model) bool { return m.uiState.FilterManager.IsActive() }},
		{"save file", 0,
			func(m *Model) { m.uiState.FileDialog.Activate() },
			func(m Model) bool { return m.uiState.FileDialog.IsActive() }},
		{"settings pcap file", 3,
			func(m *Model) { m.uiState.SettingsView.GetPcapFileDialog().Activate() },
			func(m Model) bool { return m.uiState.SettingsView.IsFileDialogActive() }},
		{"settings nodes file", 3,
			func(m *Model) { m.uiState.SettingsView.GetNodesFileDialog().Activate() },
			func(m Model) bool { return m.uiState.SettingsView.IsFileDialogActive() }},
		{"add node", 1,
			func(m *Model) { m.uiState.NodesView.ShowAddNodeModal() },
			func(m Model) bool { return m.uiState.NodesView.IsModalOpen() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := footerMouseModel(t, tc.tab)
			tc.activate(&m)
			m.prepareViewChrome()
			require.True(t, tc.active(m))
			left, top, right, bottom := modalMouseEdges(t, m)
			for _, click := range []tea.MouseMsg{
				selectionPress((left+right)/2, (top+bottom)/2),
				selectionPress(left, top),
				selectionPress(right, top),
				selectionPress(left, bottom),
				selectionPress(right, bottom),
			} {
				m = updateEventRenderModel(t, m, click)
				require.True(t, tc.active(m), "click inside or on the border must retain the modal")
			}
			require.Positive(t, left, "test needs a visible margin outside the modal")
			m = updateEventRenderModel(t, m, selectionPress(left-1, (top+bottom)/2))
			require.False(t, tc.active(m))
			require.Equal(t, tc.tab, m.uiState.Tabs.GetActive())
		})
	}
}

func TestModalMouseOutsideClickDoesNotActivateUnderlyingControls(t *testing.T) {
	for _, target := range []string{"tab", "footer"} {
		t.Run(target, func(t *testing.T) {
			m := footerMouseModel(t, 0)
			var click tea.MouseMsg
			if target == "tab" {
				click = settingsMouseLabel(t, m, "Nodes")
			} else {
				click = footerMousePress(t, m, "Space: pause")
			}
			m.uiState.ConfirmDialog.Activate("Confirm test action?")
			m = updateEventRenderModel(t, m, click)
			require.False(t, m.uiState.ConfirmDialog.IsActive())
			require.Equal(t, 0, m.uiState.Tabs.GetActive())
			require.False(t, m.uiState.Paused)
			click.Action = tea.MouseActionRelease
			m = updateEventRenderModel(t, m, click)
			require.Equal(t, 0, m.uiState.Tabs.GetActive())
			require.False(t, m.uiState.Paused)
			// A new click must still work after consuming the dismissal gesture.
			click.Action = tea.MouseActionPress
			m = updateEventRenderModel(t, m, click)
			if target == "tab" {
				require.Equal(t, 1, m.uiState.Tabs.GetActive())
			} else {
				require.True(t, m.uiState.Paused)
			}
		})
	}
}

func TestModalMouseDismissalReturnsCancellationResult(t *testing.T) {
	m := footerMouseModel(t, 0)
	context := &struct{ ID string }{ID: "pending-action"}
	m.uiState.ConfirmDialog.Show(components.ConfirmDialogOptions{
		Title: "Confirm", Message: "Proceed?", UserData: context,
	})
	updated, cmd := m.Update(selectionPress(0, 0))
	m = updated.(Model)
	require.False(t, m.uiState.ConfirmDialog.IsActive())
	require.NotNil(t, cmd)
	result, ok := cmd().(components.ConfirmDialogResult)
	require.True(t, ok)
	require.False(t, result.Confirmed)
	require.Same(t, context, result.UserData)
	updated, cmd = m.Update(result)
	require.False(t, updated.(Model).uiState.Quitting)
	require.Nil(t, cmd)
}

func TestModalMouseIgnoresNonLeftPressesOutside(t *testing.T) {
	m := footerMouseModel(t, 0)
	m.uiState.ProtocolSelector.Activate()
	for name, msg := range map[string]tea.MouseMsg{
		"right":   {X: 0, Y: 0, Button: tea.MouseButtonRight, Action: tea.MouseActionPress},
		"middle":  {X: 0, Y: 0, Button: tea.MouseButtonMiddle, Action: tea.MouseActionPress},
		"wheel":   {X: 0, Y: 0, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress},
		"motion":  {X: 0, Y: 0, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion},
		"release": {X: 0, Y: 0, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease},
	} {
		t.Run(name, func(t *testing.T) {
			m = updateEventRenderModel(t, m, msg)
			require.True(t, m.uiState.ProtocolSelector.IsActive())
		})
	}
}

func TestModalMouseGeometryFollowsResizeAndClipping(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{
		{Width: 240, Height: 40},
		{Width: 100, Height: 30},
		{Width: 60, Height: 18},
	} {
		t.Run(fmt.Sprintf("%dx%d", size.Width, size.Height), func(t *testing.T) {
			m := footerMouseModel(t, 0)
			m.uiState.ProtocolSelector.Activate()
			m = updateEventRenderModel(t, m, size)
			left, top, right, bottom := modalMouseEdges(t, m)
			for _, click := range []tea.MouseMsg{
				selectionPress(left, (top+bottom)/2),
				selectionPress(right, (top+bottom)/2),
				selectionPress((left+right)/2, bottom),
				selectionPress((left+right)/2, top),
			} {
				m = updateEventRenderModel(t, m, click)
				require.True(t, m.uiState.ProtocolSelector.IsActive())
			}
			require.Positive(t, left)
			m = updateEventRenderModel(t, m, selectionPress(left-1, (top+bottom)/2))
			require.False(t, m.uiState.ProtocolSelector.IsActive())
		})
	}
}

func TestModalMouseDismissesFileDialogFromEveryInputMode(t *testing.T) {
	for name, key := range map[string]tea.KeyMsg{
		"filename": {Type: tea.KeyTab},
		"filter":   {Type: tea.KeyRunes, Runes: []rune{'/'}},
		"folder":   {Type: tea.KeyRunes, Runes: []rune{'n'}},
	} {
		t.Run(name, func(t *testing.T) {
			m := footerMouseModel(t, 0)
			m.uiState.FileDialog.Activate()
			m = updateEventRenderModel(t, m, key)
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("uncommitted")})
			updated, cmd := m.Update(selectionPress(0, 0))
			require.False(t, updated.(Model).uiState.FileDialog.IsActive(), "outside click must close the dialog, not just leave its input mode")
			require.Nil(t, cmd, "cancellation must not select a file or create a folder")
		})
	}
}

func TestModalMouseDismissesOnlyVisibleFilterManagerLayer(t *testing.T) {
	m := footerMouseModel(t, 1)
	filter := &management.Filter{
		Id: "test-filter", Pattern: "udp", Type: management.FilterType_FILTER_BPF, Enabled: true,
	}
	m.uiState.FilterManager.Activate("test-processor", "test-processor", components.NodeTypeProcessor)
	m.uiState.FilterManager.SetFilters([]*management.Filter{filter})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	require.Contains(t, ansi.Strip(m.View()), "Delete Filter")
	updated, cmd := m.Update(selectionPress(0, 0))
	m = updated.(Model)
	require.True(t, m.uiState.FilterManager.IsActive())
	require.NotContains(t, ansi.Strip(m.View()), "Delete Filter")
	require.Contains(t, ansi.Strip(m.View()), "Filter Management")
	require.NotNil(t, cmd)
	result, ok := cmd().(components.ConfirmDialogResult)
	require.True(t, ok)
	require.False(t, result.Confirmed)
	require.Same(t, filter, result.UserData)
	updated, cmd = m.Update(result)
	m = updated.(Model)
	require.Nil(t, cmd, "cancelled confirmation must not delete the filter")
	require.Same(t, filter, m.uiState.FilterManager.GetSelectedFilter())

	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("tcp")})
	require.Contains(t, ansi.Strip(m.View()), "Edit Filter")
	updated, cmd = m.Update(selectionPress(0, 0))
	m = updated.(Model)
	require.Nil(t, cmd, "dismissed edit form must not save its changes")
	require.True(t, m.uiState.FilterManager.IsActive())
	require.Contains(t, ansi.Strip(m.View()), "Filter Management")
	require.Equal(t, "udp", filter.Pattern)

	// Search is an inline field in the manager, not a nested modal layer.
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m = updateEventRenderModel(t, m, selectionPress(0, 0))
	require.False(t, m.uiState.FilterManager.IsActive())
}
