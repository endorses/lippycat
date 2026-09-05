//go:build tui || all

package tui

import (
	"context"
	"errors"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/stretchr/testify/require"
)

func offlineRelatedModel(t *testing.T) Model {
	t.Helper()
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 32 << 20, CacheBytes: 4 << 20, MaxRecordBytes: 1 << 20, MaxSources: 1})
	require.NoError(t, err)
	builder, err := storage.NewBuilder(42, nil)
	require.NoError(t, err)
	for i := 0; i < 513; i++ {
		packet := relatedTestPacket()
		packet.NodeID = "Local"
		if i != 512 {
			packet.SrcPort = "54321"
		}
		require.NoError(t, builder.Append(context.Background(), offline.Detail{Packet: packet}))
	}
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	m := NewModel(8, 8, "", "", nil, false, false, "", false)
	m.captureMode = components.CaptureModeOffline
	m.offlineSession = &offlineIndexedSession{Dataset: dataset}
	session := m.offlineSession
	t.Cleanup(func() { require.NoError(t, session.Close()); require.NoError(t, storage.Close()); m.Shutdown() })
	m.uiState.PacketList.SetVirtualPackets(dataset.Count(), 0, nil)
	m.uiState.Width, m.uiState.Height = 180, 40
	m.uiState.EventShowDetails = true
	m.uiState.ViewMode = "events"
	m.eventStore.AddBatch([]events.Event{events.NewHTTPEvent(testEventEnvelope("far-event", 1))})
	m.syncEventsView()
	return m
}
func TestOfflineRelatedDistantPacketAndPageEviction(t *testing.T) {
	m := offlineRelatedModel(t)
	before := m.eventStore.Stats()
	require.NotContains(t, m.uiState.EventsView.RenderDetails(77, 20, false), "no longer buffered")
	require.Contains(t, m.uiState.EventsView.RenderDetails(77, 20, false), "Enter: jump to first related packet")
	cmd := m.requestOfflineRelated()
	require.NotNil(t, cmd)
	result := cmd().(offlineRelatedMsg)
	require.NoError(t, result.err)
	require.Equal(t, offline.PacketID(512), result.first)
	m, _ = m.handleOfflineRelated(result)
	selected, ok := m.uiState.EventsView.Selected()
	require.True(t, ok)
	require.True(t, m.hasRelatedPacket(selected.Event))
	m.uiState.PacketList.SetVirtualPackets(513, 200, nil)
	require.True(t, m.hasRelatedPacket(selected.Event))
	require.Nil(t, m.requestOfflineRelated(), "page eviction must preserve flow cache")
	m, _ = m.navigateOfflineRelated()
	require.Equal(t, "packets", m.uiState.ViewMode)
	require.Equal(t, uint64(512), m.uiState.PacketList.LogicalCursor())
	require.Equal(t, before, m.eventStore.Stats())
	require.Equal(t, 0, m.packetStore.PacketsCount)
}
func TestOfflineRelatedStaleResultAndRetry(t *testing.T) {
	m := offlineRelatedModel(t)
	cmd := m.requestOfflineRelated()
	original := m.offlineRelated
	result := cmd().(offlineRelatedMsg)
	m, _ = m.handleOfflineRelated(offlineRelatedMsg{state: original, err: errors.New("injected read failure")})
	require.False(t, m.offlineRelated.known)
	m, retry := m.navigateOfflineRelated()
	require.NotNil(t, retry)
	require.NotSame(t, original, m.offlineRelated)
	m, _ = m.handleOfflineRelated(result)
	require.False(t, m.offlineRelated.known)
	next := retry().(offlineRelatedMsg)
	m.uiState.ViewMode = "calls"
	m, _ = m.handleOfflineRelated(next)
	require.Equal(t, "calls", m.uiState.ViewMode, "late lookups cannot pull users back to packets")
}
func TestOfflineEventProjectionReplacementAndDelta(t *testing.T) {
	m := offlineRelatedModel(t)
	m.eventStore = store.NewEventStore(8)
	m.eventStore.AddBatch([]events.Event{events.NewHTTPEvent(testEventEnvelope("replacement", 1))})
	before := m.eventViewFullSyncCount
	m.syncEventsView()
	require.Equal(t, before+1, m.eventViewFullSyncCount)
	require.Equal(t, "replacement", m.uiState.EventsView.SelectedID())
	m.eventStore.AddBatch([]events.Event{events.NewHTTPEvent(testEventEnvelope("appended", 2))})
	m.syncEventsView()
	require.Equal(t, before+1, m.eventViewFullSyncCount)
	require.Equal(t, "appended", m.uiState.EventsView.SelectedID())
}
func TestOfflineRelatedAbandonedCommandCloses(t *testing.T) {
	m := offlineRelatedModel(t)
	require.NotNil(t, m.requestOfflineRelated())
	require.NoError(t, m.offlineSession.Close())
}

func TestOfflineRelatedTransportAndDirection(t *testing.T) {
	m := offlineRelatedModel(t)
	for _, tc := range []struct {
		name      string
		transport uint8
		reverse   bool
		want      bool
	}{
		{"tcp", 6, false, true}, {"reverse", 6, true, true}, {"udp differs", 17, false, false}, {"unknown wildcard", 0, false, true}, {"unsupported transport", 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testEventEnvelope(tc.name, 1)
			env.NodeID = "custom-local-producer"
			env.Flow.Protocol = tc.transport
			if tc.reverse {
				env.Flow.SourceAddress, env.Flow.DestinationAddress = env.Flow.DestinationAddress, env.Flow.SourceAddress
				env.Flow.SourcePort, env.Flow.DestinationPort = env.Flow.DestinationPort, env.Flow.SourcePort
			}
			m.eventStore.Reset()
			m.eventStore.AddBatch([]events.Event{events.NewHTTPEvent(env)})
			m.syncEventsView()
			cmd := m.requestOfflineRelated()
			require.NotNil(t, cmd)
			result := cmd().(offlineRelatedMsg)
			require.NoError(t, result.err)
			m, _ = m.handleOfflineRelated(result)
			require.Equal(t, tc.want, m.hasRelatedPacket(events.NewHTTPEvent(env)))
			if !tc.want {
				require.Contains(t, m.uiState.EventsView.RenderDetails(77, 20, false), "No related packets in this dataset.")
			}
		})
	}
}
