//go:build tui || all

package tui

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPresentationRefreshPolicy(t *testing.T) {
	for _, tc := range []struct {
		rate     int64
		interval time.Duration
		suppress bool
	}{
		{0, 100 * time.Millisecond, false},
		{10, 100 * time.Millisecond, false},
		{11, 200 * time.Millisecond, false},
		{100, 200 * time.Millisecond, false},
		{101, 250 * time.Millisecond, true},
		{300, 250 * time.Millisecond, true},
		{301, 500 * time.Millisecond, true},
		{1000, 500 * time.Millisecond, true},
	} {
		t.Run(fmt.Sprint(tc.rate), func(t *testing.T) {
			interval, suppress := presentationRefreshPolicy(100*time.Millisecond, tc.rate)
			require.Equal(t, tc.interval, interval)
			require.Equal(t, tc.suppress, suppress)
		})
	}
}

func TestEventRefreshCoalescesArrivalsInsideWindow(t *testing.T) {
	m := NewModel(128, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	m.syncEventsViewAt(now)
	initial := m.eventViewSyncCount
	for i := range 50 {
		m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
			events.NewDNSEvent(testEventEnvelope(fmt.Sprintf("event-%d", i), uint64(i+1))),
		}}})
		m.refreshEventsView(now.Add(time.Duration(i) * time.Microsecond))
	}
	require.Len(t, m.eventStore.Events(), 50)
	require.True(t, m.eventViewDirty)
	require.Equal(t, initial, m.eventViewSyncCount)
	interval, _ := presentationRefreshPolicy(m.packetListUpdateInterval, GetBridgeStats().RecentDropRate)
	m.refreshEventsView(now.Add(interval))
	require.Equal(t, initial+1, m.eventViewSyncCount)
	require.False(t, m.eventViewDirty)
	require.Equal(t, "event-49", m.uiState.EventsView.SelectedID())
	m.refreshEventsView(now.Add(2 * interval))
	require.Equal(t, initial+1, m.eventViewSyncCount)
}

func TestEventRefreshDefersInactiveViewAndExplicitSyncResetsWindow(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.uiState.Tabs.SetActive(1)
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("event", 1)),
	}}})
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	m.refreshEventsView(now)
	require.Zero(t, m.eventViewSyncCount)
	require.True(t, m.eventViewDirty)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "packets"
	m.refreshEventsView(now)
	require.Zero(t, m.eventViewSyncCount)
	m.syncEventsViewAt(now)
	require.False(t, m.eventViewDirty)
	require.Equal(t, now, m.lastEventViewUpdate)
	require.Equal(t, uint64(1), m.eventViewSyncCount)
}

func TestEventRefreshIdleTicksDoNotSynchronize(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.uiState.Tabs.SetActive(0)
	m.uiState.Capturing = true
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	m.syncEventsViewAt(now)
	for i := 1; i <= 5; i++ {
		m, _ = m.handleTickMsg(TickMsg{Time: now.Add(time.Duration(i) * time.Second)})
	}
	require.Equal(t, uint64(1), m.eventViewSyncCount)
	require.False(t, m.eventViewDirty)
}
