//go:build tui || all

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func finishOfflineFilter(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	require.NotNil(t, cmd)
	batch := cmd().(tea.BatchMsg)
	msg := batch[0]().(offlineFilterMsg)
	require.NoError(t, msg.err)
	m, cleanup := m.handleOfflineFilter(msg)
	if cleanup != nil {
		cleanup()
	}
	return m
}
func TestOfflineProtocolSelectionPublishesAtomically(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	total := m.offlinePacketCount()
	previous := m.uiState.SelectedProtocol
	m, cmd := m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "DNS", BPFFilter: "port 53"}})
	require.Equal(t, previous, m.uiState.SelectedProtocol)
	require.Equal(t, total, m.uiState.PacketList.LogicalCount())
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, "DNS", m.uiState.SelectedProtocol.Name)
	require.True(t, m.packetStore.HasFilter())
	require.Less(t, m.offlinePacketCount(), total)
	m.eventStore.Reset()
	m.eventStore.AddBatch([]events.Event{events.NewDNSEvent(testEventEnvelope("dns", 1)), events.NewHTTPEvent(testEventEnvelope("http", 2))})
	m, _ = m.handleToggleView()
	require.Equal(t, "events", m.uiState.ViewMode)
	require.Len(t, m.eventStore.Events(), 1)
}
func TestOfflineFilterActionsAndStalePublication(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	total := m.offlinePacketCount()
	m, _ = m.handleEnterFilterMode()
	require.True(t, m.uiState.FilterMode)
	first := m.parseAndApplyFilter("impossible-first-filter")
	firstMessage := first().(tea.BatchMsg)[0]().(offlineFilterMsg)
	second := m.parseAndApplyFilter("impossible-second-filter")
	m, cleanup := m.handleOfflineFilter(firstMessage)
	if cleanup != nil {
		cleanup()
	}
	require.Equal(t, total, m.offlinePacketCount())
	require.False(t, m.packetStore.HasFilter())
	m = finishOfflineFilter(t, m, second)
	require.Zero(t, m.offlinePacketCount())
	require.Contains(t, m.packetStore.FilterChain.GetFilterDescriptions()[0], "second")
	m = loadOfflineBrowser(t, m)
	require.Nil(t, m.offlineBrowse.current.detail)
	m, clear := m.handleClearAllFilters()
	m = finishOfflineFilter(t, m, clear)
	require.Equal(t, total, m.offlinePacketCount())
	require.False(t, m.packetStore.HasFilter())
	m = loadOfflineBrowser(t, m)
	query := m.parseAndApplyFilter("impossible-cancelled-filter")
	m.offlineFilter.cancelled = true
	m.offlineFilter.owner.cancel()
	message := query().(tea.BatchMsg)[0]().(offlineFilterMsg)
	m, cleanup = m.handleOfflineFilter(message)
	if cleanup != nil {
		cleanup()
	}
	require.Equal(t, total, m.offlinePacketCount())
	require.False(t, m.packetStore.HasFilter())
}

func TestOfflineEventJumpLoadsDistantDetail(t *testing.T) {
	m := offlineRelatedModel(t)
	m.offlineInstalled.Limits.CacheBytes = 4 << 20
	m.uiState.ViewMode = "packets"
	m = loadOfflineBrowser(t, m)
	require.Equal(t, uint64(0), uint64(m.offlineBrowse.current.detail.Value.ID))
	before := m.eventStore.Stats()
	m.uiState.ViewMode = "events"
	m.syncOfflineBrowser()
	m, cmd := m.navigateOfflineRelated()
	require.NotNil(t, cmd)
	result := cmd().(offlineRelatedMsg)
	require.NoError(t, result.err)
	m, _ = m.handleOfflineRelated(result)
	m = loadOfflineBrowser(t, m)
	require.Equal(t, uint64(512), uint64(m.offlineBrowse.current.detail.Value.ID))
	require.Equal(t, relatedTestPacket().SrcPort, m.offlineBrowse.current.detail.Value.Packet.SrcPort)
	require.Equal(t, before, m.eventStore.Stats())
	require.Zero(t, m.packetStore.PacketsCount)
}
