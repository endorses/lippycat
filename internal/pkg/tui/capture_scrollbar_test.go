//go:build tui || all

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestCapturePacketScrollbarDragAndPaneWidth(t *testing.T) {
	m := NewModel(200, 8, "test0", "", nil, false, false, "", false)
	m, _ = m.handleWindowSizeMsg(tea.WindowSizeMsg{Width: 180, Height: 35})
	m.uiState.ViewMode = "packets"
	m.uiState.ShowDetails = true
	m.uiState.PacketList.SetSize(103, 25)
	m.uiState.PacketList.SetVirtualPackets(1000, 0, make([]components.PacketDisplay, 50))
	content := m.renderCaptureTab(25)
	for _, line := range strings.Split(content, "\n") {
		require.Equal(t, 180, ansi.StringWidth(line))
	}
	barX := ansi.StringWidth(strings.Split(m.uiState.PacketList.View(true, true), "\n")[0]) - 2
	require.Contains(t, "│▉", string([]rune(ansi.Strip(strings.Split(content, "\n")[2]))[barX]))
	m, _ = m.handleMouse(tea.MouseMsg{X: barX, Y: 22, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	require.Equal(t, "list", m.scrollDrag)
	require.Greater(t, m.uiState.PacketList.LogicalOffset(), uint64(0))
	m, _ = m.handleMouse(tea.MouseMsg{X: 80, Y: 30, Action: tea.MouseActionMotion})
	require.Equal(t, uint64(1000-m.uiState.PacketList.VisibleRows()), m.uiState.PacketList.LogicalOffset())
	m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	require.Empty(t, m.scrollDrag)
	before := m.uiState.PacketList.LogicalOffset()
	m, _ = m.handleMouse(tea.MouseMsg{X: barX, Y: 20, Button: tea.MouseButtonWheelUp, Action: tea.MouseActionPress})
	require.Less(t, m.uiState.PacketList.LogicalOffset(), before)
}

func TestPacketScrollbarThumbPressAndDragWithDetails(t *testing.T) {
	m := NewModel(200, 8, "test0", "", nil, false, false, "", false)
	m, _ = m.handleWindowSizeMsg(tea.WindowSizeMsg{Width: 180, Height: 35})
	m.uiState.PacketList.SetVirtualPackets(1000, 0, make([]components.PacketDisplay, 50))
	m = m.toggleDetailsPanel()
	m.uiState.PacketList.SetScrollOffset(123)
	start, _ := components.ScrollbarThumb(1000, m.uiState.PacketList.VisibleRows(), 123, 21)
	barX := ansi.StringWidth(strings.Split(m.uiState.PacketList.View(true, true), "\n")[0]) - 2
	barY := 7 + start // Actual content starts at Y=5.
	lines := strings.Split(m.View(), "\n")
	require.Equal(t, "▉", string([]rune(ansi.Strip(lines[barY]))[barX]))

	m, _ = m.handleMouse(tea.MouseMsg{X: barX, Y: barY, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	require.Equal(t, "list", m.scrollDrag)
	require.Equal(t, uint64(123), m.uiState.PacketList.LogicalOffset(), "pressing the thumb must not move it")
	m, _ = m.handleMouse(tea.MouseMsg{X: barX, Y: barY, Action: tea.MouseActionMotion})
	require.Equal(t, uint64(123), m.uiState.PacketList.LogicalOffset(), "first motion at the same row must not jump")
	m, _ = m.handleMouse(tea.MouseMsg{X: barX, Y: barY + 2, Action: tea.MouseActionMotion})
	require.Greater(t, m.uiState.PacketList.LogicalOffset(), uint64(123))
}

func TestCaptureScrollbarSplitLayouts(t *testing.T) {
	m := NewModel(200, 8, "test0", "", nil, false, false, "", false)
	m, _ = m.handleWindowSizeMsg(tea.WindowSizeMsg{Width: 180, Height: 35})
	for _, mode := range []string{"events", "calls"} {
		m.uiState.ViewMode = mode
		m.uiState.EventShowDetails = true
		if mode == "calls" && !m.uiState.CallsView.IsShowingDetails() {
			m.uiState.CallsView.ToggleDetails()
		}
		content := m.renderCaptureTab(25)
		for _, line := range strings.Split(content, "\n") {
			require.Equalf(t, 180, ansi.StringWidth(line), "%s pane width", mode)
		}
		line := ansi.Strip(strings.Split(content, "\n")[2])
		require.Equal(t, 2, strings.Count(line, "▉"))
	}
}

func TestOfflinePacketScrollbarRequestsNewPage(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m, _ = m.handleWindowSizeMsg(tea.WindowSizeMsg{Width: 180, Height: 35})
	m.uiState.ViewMode = "packets"
	m.uiState.ShowDetails = false
	m.uiState.PacketList.SetSize(180, 25)
	barX := ansi.StringWidth(strings.Split(m.uiState.PacketList.View(false, false), "\n")[0]) - 2
	m, cmd := m.handleMouse(tea.MouseMsg{X: barX, Y: 27, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	require.NotNil(t, cmd)
	require.Greater(t, m.uiState.PacketList.LogicalOffset(), uint64(0))
	msg := cmd().(offlineBrowseMsg)
	require.NoError(t, msg.result.err)
	m, _ = m.handleOfflineBrowse(msg)
	require.Equal(t, m.uiState.PacketList.LogicalCursor(), uint64(m.offlineBrowse.current.detail.Value.ID))
}
