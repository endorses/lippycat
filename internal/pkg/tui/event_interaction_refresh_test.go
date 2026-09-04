//go:build tui || all

package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestEventUserActionsRefreshPendingPresentationImmediately(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tab    int
		action func(Model) (Model, tea.Cmd)
	}{
		{"next tab entry", 4, Model.handleNextTab},
		{"previous tab entry", 1, Model.handlePreviousTab},
		{"number tab entry", 2, func(m Model) (Model, tea.Cmd) { return m.handleAltNumberKey("alt+1") }},
		{"mouse tab entry", 2, func(m Model) (Model, tea.Cmd) {
			return m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 3, Y: 3})
		}},
		{"details toggle", 0, Model.handleDKey},
		{"pause", 0, Model.handlePauseResume},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(8, 8, "", "", nil, false, true, "", true)
			m.uiState.ViewMode = "events"
			m.uiState.Tabs.SetActive(tc.tab)
			m.uiState.Tabs.SetWidth(160)
			m.syncEventsView()
			m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(1, "pending")})
			before := m.eventViewSyncCount
			m, _ = tc.action(m)
			require.Equal(t, before+1, m.eventViewSyncCount)
			require.Equal(t, "pending-0", m.uiState.EventsView.SelectedID())
			require.False(t, m.eventViewDirty)
			if m.uiState.Paused {
				m, _ = m.handlePauseResume()
			}
		})
	}
}

func TestRemotePauseTransitionsAccountQueuedEventsBeforeToggle(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.pendingRemoteEvents.addBatch(types.EventBatch{Events: []events.Event{events.NewDNSEvent(testEventEnvelope("before-pause", 1))}})
	m, _ = m.handlePauseResume()
	require.True(t, m.eventStore.Paused())
	require.Equal(t, "before-pause", m.uiState.EventsView.SelectedID())
	m.pendingRemoteEvents.addBatch(types.EventBatch{Events: []events.Event{events.NewDNSEvent(testEventEnvelope("while-paused", 2))}, CompatibilityOmissions: 3})
	m, _ = m.handlePauseResume()
	require.False(t, m.eventStore.Paused())
	require.Equal(t, uint64(1), m.eventStore.Stats().Retained)
	require.Equal(t, uint64(1), m.eventStore.Stats().Paused)
	require.Equal(t, uint64(3), m.eventStore.Stats().TransportLost)
	require.Empty(t, m.pendingRemoteEvents.drain(0))
}

func TestRestartClearsEventPresentationAndPendingRemoteDeliveries(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.eventStore.AddBatch(makeEventBatch(1, "old").Events)
	m.syncEventsViewAt(time.Now())
	m.eventStore.SetPaused(true)
	m.pendingRemoteEvents.addBatch(makeEventBatch(1, "queued"))
	m, _ = m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: components.CaptureModeRemote, BufferSize: 8})
	require.Empty(t, m.uiState.EventsView.SelectedID())
	require.Empty(t, m.eventStore.Events())
	require.False(t, m.eventStore.Paused())
	require.Empty(t, m.pendingRemoteEvents.drain(0))
}

func TestEventClearDiscardsPendingRemoteDeliveries(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.eventStore.AddBatch(makeEventBatch(1, "old").Events)
	m.syncEventsView()
	m.pendingRemoteEvents.addBatch(makeEventBatch(1, "queued"))
	m, _ = m.handleClearPackets()
	require.Empty(t, m.eventStore.Events())
	require.Empty(t, m.uiState.EventsView.SelectedID())
	require.Empty(t, m.pendingRemoteEvents.drain(0))
}
