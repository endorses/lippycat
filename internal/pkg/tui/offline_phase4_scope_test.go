//go:build tui || all

package tui

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestOfflineProtocolSelectionScopesEventsWithoutClaimingPacketFiltering(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	total := m.offlineSession.Dataset.Count()
	selected := m.uiState.PacketList.GetSelectedPacket()
	require.NotNil(t, selected)
	m.uiState.Toast.Hide()
	m, _ = m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{
		Protocol: components.Protocol{Name: "DNS", BPFFilter: "port 53"},
	})
	require.Contains(t, m.uiState.Toast.View(), "Selected DNS views")
	require.Contains(t, m.uiState.Toast.View(), "Offline packet filtering is not available yet")
	require.NotContains(t, m.uiState.Toast.View(), "Filtering: DNS")
	require.Equal(t, "DNS", m.uiState.SelectedProtocol.Name)
	require.True(t, m.uiState.PacketList.IsVirtual())
	require.Equal(t, total, m.uiState.PacketList.LogicalCount())
	require.Equal(t, selected, m.uiState.PacketList.GetSelectedPacket())
	require.False(t, m.packetStore.HasFilter())

	m.eventStore.Reset()
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("offline-dns-scope", 1)),
		events.NewHTTPEvent(testEventEnvelope("offline-http-scope", 2)),
	})
	m, _ = m.handleToggleView()
	require.Equal(t, "events", m.uiState.ViewMode)
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, events.KindDNS, m.eventStore.Events()[0].Event.Kind())
	require.Equal(t, total, m.uiState.PacketList.LogicalCount())
}

func TestOfflinePhase4RejectsPartialPacketOperations(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	require.NotNil(t, m.parseAndApplyFilter("udp"))
	require.False(t, m.packetStore.HasFilter())
	m, _ = m.handleEnterFilterMode()
	require.False(t, m.uiState.FilterMode)
	m.uiState.FilterMode = true
	m.uiState.FilterInput.Clear()
	updated, _ := m.handleFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	require.False(t, m.uiState.FilterMode)
	m, _ = m.handleSavePackets()
	require.False(t, m.uiState.FileDialog.IsActive())
	path := filepath.Join(t.TempDir(), "partial.pcap")
	m.proceedWithSave(path)
	result := m.startOneShotSave(path)().(SaveCompleteMsg)
	require.False(t, result.Success)
	require.ErrorContains(t, result.Error, "not available yet")
	_, err := os.Stat(path)
	require.True(t, os.IsNotExist(err))
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
