//go:build tui || all

package tui

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestRemoteTickDrainsDisconnectedBacklogAndFinishesDeferredRefresh(t *testing.T) {
	m := NewModel(128, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.Capturing = false
	now := time.Now().Add(time.Hour)
	m.syncEventsViewAt(now)
	handler := newRemoteTUIEventHandler(nil, m.pendingRemoteEvents)
	for _, event := range makeEventBatch(128, "final").Events {
		handler.OnEventBatch(types.EventBatch{Events: []events.Event{event}})
	}
	handler.OnEventBatch(types.EventBatch{CompatibilityOmissions: 3})

	m, cmd := m.handleTickMsg(TickMsg{Time: now})
	require.NotNil(t, cmd, "idle polling must continue across reconnects")
	require.Empty(t, m.pendingRemoteEvents.drain(0))
	require.Equal(t, uint64(128), m.eventStore.Stats().Retained)
	require.Equal(t, uint64(3), m.eventStore.Stats().TransportLost)
	require.True(t, m.eventViewDirty)
	require.Equal(t, uint64(1), m.eventViewSyncCount, "final delivery must still respect the refresh window")

	m, cmd = m.handleTickMsg(TickMsg{Time: now.Add(time.Second)})
	require.NotNil(t, cmd)
	require.Equal(t, uint64(2), m.eventViewSyncCount)
	require.Equal(t, "final-127", m.uiState.EventsView.SelectedID())
	require.False(t, m.eventViewDirty)
}

func TestRemoteTickAccountsPausedDeliveriesAndGatesCaptureOrigin(t *testing.T) {
	for _, mode := range []components.CaptureMode{components.CaptureModeRemote, components.CaptureModeLive, components.CaptureModeOffline} {
		m := NewModel(128, 8, "", "", nil, false, true, "", true)
		m.captureMode = mode
		m.uiState.Capturing = true
		m.uiState.Paused = true
		m.eventStore.SetPaused(true)
		for _, event := range makeEventBatch(128, "paused").Events {
			m.pendingRemoteEvents.addBatch(types.EventBatch{Events: []events.Event{event}})
		}
		m.pendingRemoteEvents.addBatch(types.EventBatch{Losses: []types.EventLoss{{Count: 2}}, CompatibilityOmissions: 3})
		m, _ = m.handleTickMsg(TickMsg{})
		require.Empty(t, m.pendingRemoteEvents.drain(0))
		require.Zero(t, m.eventStore.Stats().Retained)
		if mode == components.CaptureModeRemote {
			require.Equal(t, uint64(128), m.eventStore.Stats().Arrived)
			require.Equal(t, uint64(128), m.eventStore.Stats().Paused)
			require.Equal(t, uint64(5), m.eventStore.Stats().TransportLost)
		} else {
			require.Zero(t, m.eventStore.Stats().Arrived)
			require.Zero(t, m.eventStore.Stats().TransportLost)
		}
	}
}

func TestEventRenderingDoesNotBypassRefreshWindow(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.Width, m.uiState.Height = 160, 40
	m.eventStore.AddBatch(makeEventBatch(1, "visible").Events)
	m.setCaptureView("events")
	before := m.eventViewSyncCount
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: makeEventBatch(1, "pending")})
	for range 10 {
		require.NotEmpty(t, m.View())
		require.Equal(t, "visible-0", m.uiState.EventsView.SelectedID())
	}
	require.Equal(t, before, m.eventViewSyncCount)
	require.True(t, m.eventViewDirty)
	m, _ = m.handleTickMsg(TickMsg{Time: m.lastEventViewUpdate.Add(time.Second)})
	require.Equal(t, "pending-0", m.uiState.EventsView.SelectedID())
}

func TestEventTickRefreshesRelatedPacketNoticeAfterPacketOnlyEviction(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.Width, m.uiState.Height = 160, 40
	m.uiState.EventShowDetails = true
	m.eventStore.AddBatch(makeEventBatch(1, "selected").Events)
	m.packetStore.AddPacket(components.PacketDisplay{
		SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "80", NodeID: "processor",
	})
	m.setCaptureView("events")
	require.NotContains(t, m.renderCaptureTab(30), "no longer buffered")
	m, _ = m.handlePacketBatchMsg(PacketBatchMsg{Packets: []components.PacketDisplay{
		{SrcIP: "203.0.113.1", DstIP: "203.0.113.2", NodeID: "processor"},
		{SrcIP: "203.0.113.1", DstIP: "203.0.113.2", NodeID: "processor"},
	}})
	require.True(t, m.eventViewDirty)
	m, _ = m.handleTickMsg(TickMsg{Time: m.lastEventViewUpdate.Add(time.Second)})
	require.Contains(t, m.renderCaptureTab(30), "no longer buffered")
	require.Equal(t, uint64(1), m.eventStore.Stats().Retained)
}
