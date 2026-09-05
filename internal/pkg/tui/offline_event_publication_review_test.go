//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestOfflinePublicationPreservesEventProtocolScope(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m.uiState.SelectedProtocol = components.Protocol{Name: "DNS"}
	m.setCaptureView("events")
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	result.session.EventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("dns", 1)),
		events.NewHTTPEvent(testEventEnvelope("http", 2)),
	})
	m, _ = m.completeOffline(result)
	require.Equal(t, "DNS", m.uiState.SelectedProtocol.Name)
	require.Equal(t, "events", m.uiState.ViewMode)
	selected, ok := m.uiState.EventsView.Selected()
	require.True(t, ok)
	require.Equal(t, events.KindDNS, selected.Event.Kind())
	fullSyncs := m.eventViewFullSyncCount
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("dns-later", 3)),
		events.NewHTTPEvent(testEventEnvelope("http-later", 4)),
	})
	m.syncEventsView()
	require.Equal(t, fullSyncs, m.eventViewFullSyncCount, "subsequent events retain incremental projection")
	require.Equal(t, "dns-later", m.uiState.EventsView.SelectedID())

	m, cmd = m.openOffline(open)
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	result.session.EventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("replacement-dns", 1)),
		events.NewHTTPEvent(testEventEnvelope("replacement-http", 2)),
	})
	m, cleanup := m.completeOffline(result)
	cleanup()
	require.Equal(t, fullSyncs+1, m.eventViewFullSyncCount)
	require.Equal(t, "replacement-dns", m.uiState.EventsView.SelectedID())
}
