//go:build tui || all

package tui

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/stretchr/testify/require"
)

func TestModelEventIncrementalProjection(t *testing.T) {
	m := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	m.uiState.ViewMode = "events"
	m.uiState.Width, m.uiState.Height = 120, 40
	m.syncEventsView()
	require.EqualValues(t, 1, m.eventViewFullSyncCount)
	for i := 0; i < 40; i++ {
		event := events.NewDNSEvent(testEventEnvelope(fmt.Sprint(i), uint64(i+1)))
		m.eventStore.AddEvent(event)
		m.syncEventsView()
		require.EqualValues(t, 1, m.eventViewFullSyncCount, "ordinary arrival must use a delta")
		reference := components.NewEventsView()
		reference.SetEvents(m.eventStore.Events())
		reference.SetSelectedID(m.eventStore.SelectedID())
		reference.PrepareLayout(120, 30, 0, 0)
		require.Equal(t, reference.RenderTimeline(120, 30, true), m.uiState.EventsView.RenderTimeline(120, 30, true))
	}
	m.eventStore.SelectOffset(-3)
	m.syncEventsView()
	require.Equal(t, m.eventStore.SelectedID(), m.uiState.EventsView.SelectedID())
	require.EqualValues(t, 1, m.eventViewFullSyncCount)

	m.eventStore.SetKindFilter([]events.Kind{events.KindHTTP})
	m.syncEventsView()
	require.EqualValues(t, 2, m.eventViewFullSyncCount)
	require.Empty(t, m.uiState.EventsView.SelectedID())
	m.eventStore.AddEvent(events.NewDNSEvent(testEventEnvelope("hidden", 100)))
	m.syncEventsView()
	require.EqualValues(t, 2, m.eventViewFullSyncCount)
	m.eventStore.SetKindFilter(nil)
	m.syncEventsView()
	require.EqualValues(t, 3, m.eventViewFullSyncCount)
	require.Equal(t, m.eventStore.SelectedID(), m.uiState.EventsView.SelectedID())

	m.eventStore.Reset()
	m.syncEventsView()
	require.EqualValues(t, 4, m.eventViewFullSyncCount)
	require.Empty(t, m.uiState.EventsView.SelectedID())
	// Replacing a store can reuse the same sequence/revision; it still needs a snapshot.
	m.eventStore = store.NewEventStore(8)
	m.eventStore.AddEvent(events.NewDNSEvent(testEventEnvelope("replacement", 1)))
	m.syncEventsView()
	require.EqualValues(t, 5, m.eventViewFullSyncCount)
	require.Equal(t, "replacement", m.uiState.EventsView.SelectedID())
	m.eventStore.AddBatch(makeEventBatch(16, "overflow").Events)
	m.syncEventsView()
	require.EqualValues(t, 6, m.eventViewFullSyncCount)
	require.Equal(t, m.eventStore.SelectedID(), m.uiState.EventsView.SelectedID())
}
