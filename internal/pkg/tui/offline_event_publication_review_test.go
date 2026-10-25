//go:build tui || all

package tui

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func publishTestOfflineEventScope(t *testing.T, m Model, result offlineOpenCompleteMsg, sequence uint64) Model {
	t.Helper()
	require.NoError(t, result.session.EventDataset.Close())
	builder, err := m.offlineController.storage.NewEventBuilder(result.generation)
	require.NoError(t, err)
	env := noticefixture.Event().Envelope()
	env.EventSequence = sequence
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, sequence)
	dns := events.NewDNSEvent(env)
	dns.Query, dns.QType, dns.QClass = "scope.example.test", 1, 1
	require.NoError(t, builder.Append(context.Background(), dns))
	env.EventSequence++
	env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, env.EventSequence)
	env.Flow.Protocol = 6
	require.NoError(t, builder.Append(context.Background(), events.NewHTTPEvent(env)))
	result.session.EventDataset, err = builder.Finish(context.Background())
	require.NoError(t, err)
	m, cleanup := m.completeOffline(result)
	if cleanup != nil {
		require.NoError(t, cleanup().(offlineCleanupMsg).err)
	}
	require.Equal(t, "DNS", m.uiState.SelectedProtocol.Name)
	require.Equal(t, "events", m.uiState.ViewMode)
	m = completeOfflineEventFilter(t, m, m.syncOfflineEventBrowser())
	m = loadCompleteOfflineEvents(t, m)
	return m
}

func TestOfflinePublicationPreservesEventProtocolScope(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m.uiState.SelectedProtocol = components.Protocol{Name: "DNS"}
	m.uiState.Width, m.uiState.Height = 180, 35
	m.setCaptureView("events")
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m = publishTestOfflineEventScope(t, m, result, 1)
	selected, ok := m.uiState.EventsView.Selected()
	require.True(t, ok)
	require.Equal(t, events.KindDNS, selected.Event.Kind())
	require.EqualValues(t, 1, m.offlineEventCount())
	firstID := selected.Event.Envelope().EventID
	// Compatibility-ring arrivals do not replace immutable completed disk rows.
	m.eventStore.AddBatch([]events.Event{events.NewDNSEvent(testEventEnvelope("ring-only", 3))})
	m.syncEventsView()
	require.Equal(t, firstID, m.uiState.EventsView.SelectedID())
	require.EqualValues(t, 1, m.offlineEventCount())
	m, cmd = m.openOffline(open)
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m = publishTestOfflineEventScope(t, m, result, 100)
	require.NotEqual(t, firstID, m.uiState.EventsView.SelectedID())
	require.EqualValues(t, 1, m.offlineEventCount())
	require.True(t, m.uiState.EventsView.IsVirtual())
}
