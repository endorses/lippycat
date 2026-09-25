//go:build tui || all

package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func selectionTestModel(t *testing.T, mode string) Model {
	t.Helper()
	m := NewModel(128, 8, "", "", nil, false, true, "", true)
	t.Cleanup(m.Shutdown)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = mode
	m.uiState.ShowDetails = true
	m.uiState.EventShowDetails = true
	m, _ = m.handleWindowSizeMsg(tea.WindowSizeMsg{Width: 180, Height: 40})
	return m
}

func selectionPress(x, y int) tea.MouseMsg {
	return tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
}

func TestCaptureTextSelectionPaneBoundaries(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := selectionTestModel(t, mode)
			if mode == "calls" && !m.uiState.CallsView.IsShowingDetails() {
				m.uiState.CallsView.ToggleDetails()
			}
			_ = m.View()
			for _, x := range []int{5, 110} {
				region, ok := m.textSelectionRegion(x, 8)
				require.True(t, ok)
				if x == 5 {
					require.Equal(t, 3, region.X)
					require.LessOrEqual(t, region.X+region.Width, 99)
				} else {
					require.Equal(t, 104, region.X)
					require.LessOrEqual(t, region.X+region.Width, 178)
				}
				m, _ = m.handleTextSelectionMouse(selectionPress(x, 8))
				require.NotNil(t, m.textSelection)
				m, _ = m.handleTextSelectionMouse(tea.MouseMsg{X: 300, Y: 100, Action: tea.MouseActionMotion})
				for _, line := range strings.Split(m.textSelection.Text(), "\n") {
					require.LessOrEqual(t, ansi.StringWidth(line), region.Width)
					require.NotContains(t, line, "│")
					require.NotContains(t, line, "┃")
				}
				m.textSelection = nil
			}
			for _, x := range []int{0, 100, 101, 179, 99, 178} {
				_, ok := m.textSelectionRegion(x, 8)
				require.False(t, ok, "border/scrollbar at x=%d", x)
			}
		})
	}
}

func TestPacketASCIITextSelectionCopiesOnlyASCII(t *testing.T) {
	m := selectionTestModel(t, "packets")
	m.uiState.DetailsPanel.SetPacket(&types.PacketDisplay{RawData: []byte(strings.Repeat("INVITE sip:alice", 8))})
	_ = m.View()
	m.uiState.DetailsPanel.SetScrollOffset(100000)
	view := m.View()
	var x, y int
	for row, line := range strings.Split(ansi.Strip(view), "\n") {
		if i := strings.Index(line, "INVITE sip:alice"); i >= 0 {
			x, y = ansi.StringWidth(line[:i]), row
			break
		}
	}
	require.NotZero(t, y, "dump must be visible")
	m, _ = m.handleTextSelectionMouse(selectionPress(x, y))
	require.NotNil(t, m.textSelection)
	m, _ = m.handleTextSelectionMouse(tea.MouseMsg{X: x + 15, Y: y + 2, Action: tea.MouseActionMotion})
	require.Equal(t, "INVITE sip:alice\nINVITE sip:alice\nINVITE sip:alice", m.textSelection.Text())
	require.NotContains(t, m.textSelection.Text(), "49 4e 56")
	m, cmd := m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	require.Nil(t, m.textSelection)
	require.NotNil(t, cmd, "release must schedule clipboard copy")
}

func TestTextSelectionKeepsSnapshotWhileEventsArrive(t *testing.T) {
	m := newEventRenderModel(t, true)
	t.Cleanup(m.Shutdown)
	before := m.View()
	selectedID := m.uiState.EventsView.SelectedID()
	m, _ = m.handleTextSelectionMouse(selectionPress(85, 9))
	require.NotNil(t, m.textSelection)
	m, _ = m.handleTextSelectionMouse(tea.MouseMsg{X: 145, Y: 12, Action: tea.MouseActionMotion})
	copied := m.textSelection.Text()
	m = updateEventRenderModel(t, m, EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("arrived-during-drag", 999)),
	}}})
	m.syncEventsView()
	require.Equal(t, copied, m.textSelection.Text())
	require.Equal(t, ansi.Strip(before), ansi.Strip(m.View()), "only highlighting changes the visible snapshot")
	require.NotEqual(t, selectedID, m.uiState.EventsView.SelectedID(), "capture continues behind snapshot")
	m, cmd := m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	require.Nil(t, m.textSelection)
	require.NotNil(t, cmd)
}

func TestTextSelectionPlainClickAndDoubleClick(t *testing.T) {
	m := newEventRenderModel(t, false)
	t.Cleanup(m.Shutdown)
	id, ok := m.uiState.EventsView.EventIDAtVisibleRow(0)
	require.True(t, ok)
	for i := range 2 {
		m, _ = m.handleTextSelectionMouse(selectionPress(5, 8))
		require.NotNil(t, m.textSelection)
		m, _ = m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
		require.Nil(t, m.textSelection)
		require.Equal(t, id, m.uiState.EventsView.SelectedID())
		require.Equal(t, i == 1, m.uiState.EventShowDetails)
	}
}

func TestTextSelectionDoesNotClickChangedLiveRow(t *testing.T) {
	m := newEventRenderModel(t, false)
	t.Cleanup(m.Shutdown)
	m, _ = m.handleTextSelectionMouse(selectionPress(5, 8))
	require.NotNil(t, m.textSelection)
	m = updateEventRenderModel(t, m, EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("arrived-before-release", 999)),
	}}})
	m.syncEventsView()
	selected := m.uiState.EventsView.SelectedID()
	m, _ = m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	require.Equal(t, selected, m.uiState.EventsView.SelectedID(), "the row under the frozen click must not be replaced")
	require.Nil(t, m.textSelection)
}

func TestTextSelectionCancellation(t *testing.T) {
	for _, msg := range []tea.Msg{tea.KeyMsg{Type: tea.KeyEsc}, tea.WindowSizeMsg{Width: 180, Height: 35}, tea.ResumeMsg{}} {
		m := selectionTestModel(t, "packets")
		m, _ = m.handleTextSelectionMouse(selectionPress(5, 8))
		require.NotNil(t, m.textSelection)
		m = updateEventRenderModel(t, m, msg)
		require.Nil(t, m.textSelection)
	}
}

func TestTextSelectionLeavesScrollbarsAndTabsWorking(t *testing.T) {
	m := selectionTestModel(t, "packets")
	m.uiState.PacketList.SetVirtualPackets(1000, 0, make([]components.PacketDisplay, 50))
	m, _ = m.handleTextSelectionMouse(selectionPress(99, 15))
	require.Nil(t, m.textSelection)
	require.Equal(t, "list", m.scrollDrag)
	m, _ = m.handleTextSelectionMouse(tea.MouseMsg{X: 80, Y: 32, Action: tea.MouseActionMotion})
	require.Greater(t, m.uiState.PacketList.LogicalOffset(), uint64(0))
	m, _ = m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	require.Empty(t, m.scrollDrag)
	m, _ = m.handleTextSelectionMouse(selectionPress(5, 3))
	require.Nil(t, m.textSelection)
	for _, tab := range []int{1, 2, 4} {
		m.uiState.Tabs.SetActive(tab)
		m, _ = m.handleTextSelectionMouse(selectionPress(10, 10))
		require.NotNil(t, m.textSelection, "tab %d", tab)
		m, _ = m.handleTextSelectionMouse(tea.MouseMsg{X: 15, Y: 11, Action: tea.MouseActionMotion})
		require.True(t, m.textSelection.Dragged())
		m, _ = m.handleTextSelectionMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
	}
}

func TestTextCopyFeedback(t *testing.T) {
	for _, err := range []error{nil, errors.New("terminal unavailable")} {
		m := selectionTestModel(t, "packets")
		m = updateEventRenderModel(t, m, textCopiedMsg{err: err})
		require.True(t, m.uiState.Toast.IsActive())
		if err == nil {
			require.Contains(t, m.View(), "Text copied")
		} else {
			require.Contains(t, m.View(), "Copy failed: terminal unavailable")
		}
	}
}
