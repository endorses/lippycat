//go:build tui || all

package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineFilterDistantDetailAndRemove(t *testing.T) {
	m := offlineRelatedModel(t)
	m.uiState.ViewMode = "packets"
	m.offlineInstalled.Limits.CacheBytes = 4 << 20
	m = loadOfflineBrowser(t, m)
	global := m.offlineSession.Dataset.Statistics()
	cmd := m.parseAndApplyFilter("port " + relatedTestPacket().SrcPort)
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, uint64(1), m.offlinePacketCount())
	require.Equal(t, global, m.offlineSession.Dataset.Statistics())
	require.Equal(t, uint64(1), m.offlineBrowse.owner.query.Statistics().Packets)
	m = loadOfflineBrowser(t, m)
	require.Equal(t, offline.PacketID(512), m.offlineBrowse.current.detail.Value.ID)
	require.Equal(t, uint64(0), m.uiState.PacketList.LogicalCursor())
	cmd = m.parseAndApplyFilter("impossible-stacked")
	m = finishOfflineFilter(t, m, cmd)
	require.Zero(t, m.offlinePacketCount())
	m, cmd = m.handleRemoveLastFilter()
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, uint64(1), m.offlinePacketCount())
	m, cmd = m.handleRemoveLastFilter()
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, uint64(513), m.offlinePacketCount())
	require.False(t, m.packetStore.HasFilter())
}

type failingOfflineQueryDataset struct{ offline.Dataset }

func (d failingOfflineQueryDataset) Query(context.Context, offline.QuerySpec) (offline.Query, error) {
	return nil, errors.New("injected query failure")
}
func TestOfflineFilterFailureKeepsCompletedQuery(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	cmd := m.parseAndApplyFilter("NOT impossible")
	m = finishOfflineFilter(t, m, cmd)
	old := m.offlineBrowse.owner.query
	descriptions := m.packetStore.FilterChain.GetFilterDescriptions()
	m.offlineSession.Dataset = failingOfflineQueryDataset{m.offlineSession.Dataset}
	cmd = m.parseAndApplyFilter("impossible")
	msg := cmd().(tea.BatchMsg)[0]().(offlineFilterMsg)
	require.ErrorContains(t, msg.err, "injected")
	m, _ = m.handleOfflineFilter(msg)
	require.Same(t, old, m.offlineBrowse.owner.query)
	require.Equal(t, descriptions, m.packetStore.FilterChain.GetFilterDescriptions())
	require.Equal(t, uint64(1077), m.offlinePacketCount())
	require.Nil(t, m.offlineFilter)
}

func TestOfflineFilterAbandonedResultsStayBounded(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	for i := 0; i < 12; i++ {
		m.parseAndApplyFilter("NOT impossible")
		<-m.offlineFilter.owner.done
		m.offlineFilter.owner.mu.Lock()
		require.LessOrEqual(t, len(m.offlineFilter.owner.queries), 1)
		m.offlineFilter.owner.mu.Unlock()
	}
	require.False(t, m.packetStore.HasFilter())
	require.Equal(t, uint64(1077), m.offlinePacketCount())
}
func TestOfflineFilteredRelatedJumpClearsQuery(t *testing.T) {
	m := offlineRelatedModel(t)
	m.offlineInstalled.Limits.CacheBytes = 4 << 20
	m.uiState.ViewMode = "packets"
	m = loadOfflineBrowser(t, m)
	cmd := m.parseAndApplyFilter("port 54321")
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, uint64(512), m.offlinePacketCount())
	m.uiState.ViewMode = "events"
	m.syncOfflineBrowser()
	m, lookup := m.navigateOfflineRelated()
	msg := lookup().(offlineRelatedMsg)
	require.NoError(t, msg.err)
	m, filter := m.handleOfflineRelated(msg)
	require.NotNil(t, m.offlineFilter)
	require.True(t, m.packetStore.HasFilter())
	m = finishOfflineFilter(t, m, filter)
	require.False(t, m.packetStore.HasFilter())
	require.Equal(t, "packets", m.uiState.ViewMode)
	require.Equal(t, uint64(512), m.uiState.PacketList.LogicalCursor())
	m = loadOfflineBrowser(t, m)
	require.Equal(t, offline.PacketID(512), m.offlineBrowse.current.detail.Value.ID)
}
