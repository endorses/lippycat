//go:build tui || all

package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func readyOfflineBrowser(t *testing.T) Model {
	t.Helper()
	m, open := offlineLifecycleModel(t)
	open.Config.Inputs = writeOrderedBridgeFixtures(t)
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, _ = m.completeOffline(result)
	m.uiState.Width = 180
	m.uiState.Height = 35
	m.prepareViewChrome()
	return m
}
func loadOfflineBrowser(t *testing.T, m Model) Model {
	t.Helper()
	cmd := m.syncOfflineBrowser()
	require.NotNil(t, cmd)
	msg := cmd().(offlineBrowseMsg)
	require.NoError(t, msg.result.err)
	m, _ = m.handleOfflineBrowse(msg)
	return m
}
func TestOfflineBrowserFarNavigationAndPrefetch(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	firstPage := m.offlineBrowse.current.page.Rows
	require.NotEmpty(t, firstPage)
	require.Equal(t, offline.PacketID(0), m.offlineBrowse.current.detail.Value.ID)
	m.uiState.PacketList.SetLogicalCursor(1)
	m = loadOfflineBrowser(t, m)
	require.Same(t, &firstPage[0], &m.offlineBrowse.current.page.Rows[0], "cursor changes reuse prefetched summaries")
	require.Equal(t, offline.PacketID(1), m.offlineBrowse.current.detail.Value.ID)
	m.uiState.PacketList.GotoBottom()
	m = loadOfflineBrowser(t, m)
	require.Equal(t, offline.PacketID(1076), m.offlineBrowse.current.detail.Value.ID)
	require.Equal(t, uint64(1077), m.uiState.PacketList.LogicalCount())
	require.Zero(t, m.packetStore.PacketsCount)
	require.Equal(t, int64(1077), m.statistics.TotalPackets)
	m.uiState.PacketList.GotoTop()
	m = loadOfflineBrowser(t, m)
	require.Equal(t, offline.PacketID(0), m.offlineBrowse.current.detail.Value.ID)
}
func TestOfflineBrowserObsoleteAndAbandonedResults(t *testing.T) {
	m := readyOfflineBrowser(t)
	cmd := m.syncOfflineBrowser()
	stale := cmd().(offlineBrowseMsg)
	for i := 1; i < 40; i++ {
		m.uiState.PacketList.SetLogicalCursor(uint64(i))
		cmd = m.syncOfflineBrowser()
		require.NotNil(t, cmd)
		// Commands may complete without Bubble Tea ever receiving their results.
		<-m.offlineBrowse.owner.done
	}
	b := m.offlineBrowse.owner
	b.mu.Lock()
	retained := len(b.results)
	b.mu.Unlock()
	require.LessOrEqual(t, retained, 1)
	m, _ = m.handleOfflineBrowse(stale)
	require.Nil(t, m.offlineBrowse.current)
	latest := cmd().(offlineBrowseMsg)
	require.NoError(t, latest.result.err)
	m, _ = m.handleOfflineBrowse(latest)
	require.Equal(t, offline.PacketID(39), m.offlineBrowse.current.detail.Value.ID)
	m, _ = m.handleOfflineBrowse(latest)
	require.Equal(t, offline.PacketID(39), m.offlineBrowse.current.detail.Value.ID)
	require.NoError(t, b.close())
	require.Nil(t, m.offlineBrowse.current.detail)
	require.Nil(t, m.offlineBrowse.current.page.Rows)
	require.Nil(t, b.current)
	require.Zero(t, m.offlineSession.Dataset.Resources().PinnedBytes)
}

func TestOfflineBrowserKeyboardEndResizeAndLoading(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.ViewMode = "packets"
	m.uiState.FocusedPane = "left"
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	m = updated.(Model)
	require.Equal(t, uint64(1076), m.uiState.PacketList.LogicalCursor())
	require.Nil(t, m.offlineBrowse.current, "unloaded selections release prior details/page")
	m.uiState.DetailsPanel.SetSize(77, 25)
	require.Contains(t, m.uiState.DetailsPanel.View(false), "Loading packet details")
	<-m.offlineBrowse.owner.done
	b := m.offlineBrowse.owner
	b.mu.Lock()
	var result *offlineBrowseResult
	for r := range b.results {
		result = r
	}
	b.mu.Unlock()
	require.NotNil(t, result)
	require.NoError(t, result.err)
	m, _ = m.handleOfflineBrowse(offlineBrowseMsg{b, result})
	require.Equal(t, offline.PacketID(1076), m.offlineBrowse.current.detail.Value.ID)
	m, _ = m.handleUpdateBufferSizeMsg(components.UpdateBufferSizeMsg{Size: 4})
	require.True(t, m.uiState.PacketList.IsVirtual())
	require.Equal(t, uint64(1077), m.uiState.PacketList.LogicalCount())
	m.updatePacketListIncremental()
	m.doFullPacketListRefresh(false)
	require.True(t, m.uiState.PacketList.IsVirtual())
}

func TestOfflineBrowserMouseSplitBoundaryAndHiddenDetailsKeys(t *testing.T) {
	for _, tc := range []struct {
		name     string
		width, x int
		focus    string
		cursor   uint64
	}{
		{"wide details boundary", 180, 101, "right", 0},
		{"wide last list column", 180, 100, "left", 2},
		{"narrow full width", 140, 139, "left", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := readyOfflineBrowser(t)
			m.uiState.ShowDetails = true
			m.uiState.Width = tc.width
			m.uiState.ViewMode = "packets"
			m, _ = m.handlePacketListClick(tea.MouseMsg{X: tc.x, Y: 10}, 6, 25)
			require.Equal(t, tc.focus, m.uiState.FocusedPane)
			require.Equal(t, tc.cursor, m.uiState.PacketList.LogicalCursor())
		})
	}
	m := readyOfflineBrowser(t)
	m.uiState.ShowDetails = true
	m.uiState.Width = 140
	m.uiState.ViewMode = "packets"
	m.uiState.FocusedPane = "right"
	m, _ = m.handleMoveDown()
	require.Equal(t, uint64(1), m.uiState.PacketList.LogicalCursor())
	m, _ = m.handleFocusRight()
	require.Equal(t, "left", m.uiState.FocusedPane)
	m.uiState.Width = 180
	m, _ = m.handleFocusRight()
	require.Equal(t, "right", m.uiState.FocusedPane)
	m, _ = m.handleMoveDown()
	require.Equal(t, uint64(1), m.uiState.PacketList.LogicalCursor(), "visible details receive navigation")
}

func TestOfflineBrowserPartialPageLoadsSelectedRow(t *testing.T) {
	m := readyOfflineBrowser(t)
	// Tighten the request cap while leaving storage capacity intact to exercise
	// a legitimate short page, independently of the record scratch budget.
	m.offlineInstalled.Limits = offline.ResourceLimits{CacheBytes: 8192}
	m.uiState.PacketList.SetLogicalCursor(10)
	m = loadOfflineBrowser(t, m)
	require.Less(t, m.offlineBrowse.current.page.Row+uint64(len(m.offlineBrowse.current.page.Rows)), uint64(11))
	m = loadOfflineBrowser(t, m)
	require.Equal(t, uint64(10), m.offlineBrowse.current.page.Row)
	require.NotNil(t, m.uiState.PacketList.GetSelectedPacket())
	require.Nil(t, m.syncOfflineBrowser(), "selected row resolved without reload loop")
}

func TestOfflineEventsReleaseLargeHiddenBrowserLeases(t *testing.T) {
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 64 << 20, CacheBytes: (6 << 20) + (128 << 10), MaxRecordBytes: 2 << 20, MaxSources: 1}
	storage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	builder, err := storage.NewBuilder(42, nil)
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		packet := relatedTestPacket()
		packet.NodeID = "Local"
		if i == 0 {
			packet.RawData = make([]byte, 7<<18)
		} else if i == 4 {
			packet.Info = strings.Repeat("z", 1<<20)
		} else {
			packet.Info = strings.Repeat("x", 512<<10)
		}
		require.NoError(t, builder.Append(context.Background(), offline.Detail{Packet: packet}))
	}
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	m := NewModel(8, 8, "", "", nil, false, false, "", false)
	session := &offlineIndexedSession{Dataset: dataset}
	m.offlineSession = session
	m.offlineInstalled.Limits = limits
	m.captureMode = components.CaptureModeOffline
	t.Cleanup(func() { require.NoError(t, session.Close()); require.NoError(t, storage.Close()); m.Shutdown() })
	m.uiState.PacketList.SetVirtualPackets(dataset.Count(), 0, nil)
	m.uiState.PacketList.SetSize(180, 30)
	m.uiState.ViewMode = "packets"
	m = loadOfflineBrowser(t, m)
	require.Greater(t, dataset.Resources().PinnedBytes, uint64(2<<20))
	m.eventStore.AddBatch([]events.Event{events.NewHTTPEvent(testEventEnvelope("large-hidden", 1))})
	m.uiState.ViewMode = "events"
	m.syncEventsView()
	cleanup := m.syncOfflineBrowser()
	require.NotNil(t, cleanup)
	require.Nil(t, m.offlineBrowse.current)
	require.Nil(t, m.uiState.PacketList.GetPackets())
	// The lookup joins cancelled reads itself even if cleanup's command is abandoned.
	cmd := m.requestOfflineRelated()
	require.NotNil(t, cmd)
	result := cmd().(offlineRelatedMsg)
	require.NoError(t, result.err)
	require.True(t, result.available)
	require.Zero(t, dataset.Resources().PinnedBytes)
	m, _ = m.handleOfflineRelated(result)
	m.uiState.ViewMode = "packets"
	m = loadOfflineBrowser(t, m)
	require.Len(t, m.offlineBrowse.current.detail.Value.Packet.RawData, 7<<18)
}
