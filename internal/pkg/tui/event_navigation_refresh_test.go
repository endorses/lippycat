//go:build tui || all

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestEventRelativeNavigationUsesDisplayedSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action func(Model) (Model, tea.Cmd)
		want   string
	}{
		{"up", Model.handleMoveUp, "initial-1"},
		{"down", Model.handleMoveDown, "pending-0"},
		{"page up", Model.handlePageUp, "initial-0"},
		{"page down", Model.handlePageDown, "pending-1"},
		{"wheel up", func(m Model) (Model, tea.Cmd) {
			return m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp})
		}, "initial-1"},
		{"wheel down", func(m Model) (Model, tea.Cmd) {
			return m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
		}, "pending-0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(10, 8, "", "", nil, false, true, "", true)
			m.uiState.Tabs.SetActive(0)
			m.uiState.ViewMode = "events"
			m.uiState.EventShowDetails = false
			m.uiState.Height = 12 // Two event rows per page.
			m.eventStore.AddBatch(makeEventBatch(3, "initial").Events)
			m.syncEventsView()
			m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(3, "pending")})
			require.Equal(t, "initial-2", m.uiState.EventsView.SelectedID())
			before := m.eventViewSyncCount
			m, _ = tc.action(m)
			require.Equal(t, tc.want, m.eventStore.SelectedID())
			require.Equal(t, tc.want, m.uiState.EventsView.SelectedID())
			require.Equal(t, before+1, m.eventViewSyncCount)
			m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(1, "later")})
			require.Equal(t, tc.want, m.eventStore.SelectedID(), "navigation into history must stop following new arrivals")
		})
	}
}

func TestEventRelativeNavigationFollowsLatestAtNewEdge(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = false
	m.eventStore.AddBatch(makeEventBatch(3, "initial").Events)
	m.syncEventsView()
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(1, "pending")})
	m, _ = m.handleMoveDown()
	require.Equal(t, "pending-0", m.uiState.EventsView.SelectedID())
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(1, "later")})
	require.Equal(t, "later-0", m.eventStore.SelectedID())
}

func TestEventRelativeNavigationFallsBackWhenDisplayedSelectionEvicted(t *testing.T) {
	m := NewModel(3, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = false
	m.eventStore.AddBatch(makeEventBatch(3, "initial").Events)
	m.syncEventsView()
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(3, "pending")})
	m, _ = m.handleMoveUp()
	require.Equal(t, "pending-1", m.eventStore.SelectedID())
	require.Equal(t, "pending-1", m.uiState.EventsView.SelectedID())
}
