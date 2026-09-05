//go:build tui || all

package tui

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

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
