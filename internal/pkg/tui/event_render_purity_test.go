//go:build tui || all

package tui

import (
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func updateEventRenderModel(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	updated, _ := m.Update(msg)
	require.IsType(t, Model{}, updated)
	return updated.(Model)
}

func newEventRenderModel(t *testing.T, details bool) Model {
	t.Helper()
	m := NewModel(128, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.EventShowDetails = details
	m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 160, Height: 24})
	batch := types.EventBatch{}
	for i := range 40 {
		batch.Events = append(batch.Events, events.NewDNSEvent(testEventEnvelope(fmt.Sprintf("render-%d", i), uint64(i+1))))
	}
	m = updateEventRenderModel(t, m, EventBatchMsg{Batch: batch})
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	require.Equal(t, "events", m.uiState.ViewMode)
	return m
}

func TestEventModelViewDoesNotMutatePresentation(t *testing.T) {
	for _, details := range []bool{false, true} {
		t.Run(fmt.Sprintf("details-%t", details), func(t *testing.T) {
			m := newEventRenderModel(t, details)
			// Pin history and scroll details before the first render. Rendering
			// must neither prepare a viewport nor repair timeline selection.
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyUp})
			m.uiState.EventsView.ScrollDetailsToBottom()
			m = updateEventRenderModel(t, m, EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
				events.NewDNSEvent(testEventEnvelope("pending-render", 41)),
			}}})
			beforeView := fmt.Sprintf("%#v", *m.uiState.EventsView)
			beforeHeader := fmt.Sprintf("%#v", m.uiState.Header)
			beforeFooter := fmt.Sprintf("%#v", m.uiState.Footer)
			beforeEvents, beforeStats := m.eventStore.Events(), m.eventStore.Stats()
			beforeSelection := m.eventStore.SelectedID()
			beforeSync, beforeTime := m.eventViewSyncCount, m.lastEventViewUpdate
			var first string
			for i := range 5 {
				output := m.View()
				require.NotEmpty(t, output)
				if i == 0 {
					first = output
				} else {
					require.Equal(t, first, output)
				}
				require.Equal(t, beforeView, fmt.Sprintf("%#v", *m.uiState.EventsView))
				require.Equal(t, beforeHeader, fmt.Sprintf("%#v", m.uiState.Header))
				require.Equal(t, beforeFooter, fmt.Sprintf("%#v", m.uiState.Footer))
			}
			require.Equal(t, beforeEvents, m.eventStore.Events())
			require.Equal(t, beforeStats, m.eventStore.Stats())
			require.Equal(t, beforeSelection, m.eventStore.SelectedID())
			require.Equal(t, beforeSync, m.eventViewSyncCount)
			require.Equal(t, beforeTime, m.lastEventViewUpdate)
			require.True(t, m.eventViewDirty)
			// Presentation is complete without consulting the event store,
			// including the footer's event-filter indicators.
			m.eventStore = nil
			require.NotPanics(t, func() { require.Equal(t, first, m.View()) })
		})
	}
}

func TestEventProjectionOwnedByUpdates(t *testing.T) {
	m := newEventRenderModel(t, true)
	initial := m.eventViewSyncCount
	// Clean tab round trips and unrelated messages need no new projection.
	for _, msg := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyTab}, tea.KeyMsg{Type: tea.KeyShiftTab},
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}, Alt: true},
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}, Alt: true},
		struct{}{},
	} {
		m = updateEventRenderModel(t, m, msg)
		_ = m.View()
		require.Equal(t, initial, m.eventViewSyncCount, "%T must not rebuild clean event projection", msg)
	}
	// Every arrival is stored, with just one projection on the due tick.
	for i := range 20 {
		m = updateEventRenderModel(t, m, EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
			events.NewDNSEvent(testEventEnvelope(fmt.Sprintf("update-%d", i), uint64(i+41))),
		}}})
		_ = m.View()
		require.Equal(t, initial, m.eventViewSyncCount)
	}
	m = updateEventRenderModel(t, m, TickMsg{Time: m.lastEventViewUpdate.Add(time.Second)})
	require.Equal(t, initial+1, m.eventViewSyncCount)
	require.Len(t, m.eventStore.Events(), 60)
	require.Equal(t, "update-19", m.uiState.EventsView.SelectedID())
	for range 3 {
		_ = m.View()
	}
	require.Equal(t, initial+1, m.eventViewSyncCount)
	// Returning to a dirty event tab refreshes immediately once.
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m = updateEventRenderModel(t, m, EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("inactive-arrival", 61)),
	}}})
	m = updateEventRenderModel(t, m, struct{}{})
	_ = m.View()
	require.Equal(t, initial+1, m.eventViewSyncCount)
	m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyShiftTab})
	_ = m.View()
	require.Equal(t, initial+2, m.eventViewSyncCount)
	require.Equal(t, "inactive-arrival", m.uiState.EventsView.SelectedID())
}
