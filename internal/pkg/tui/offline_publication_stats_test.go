//go:build tui || all

package tui

import (
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestOfflinePublicationClearsPreviousCaptureDrops(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m.captureMode = components.CaptureModeLive
	m.uiState.StatisticsView.GetDropStats().SetKernelStats(100, 7)
	m.uiState.StatisticsView.GetDropStats().SetBufferDropStages(3, 2)
	m.uiState.StatisticsView.SetBridgeStats(&components.BridgeStatistics{
		PacketsReceived: 100, PacketsSampledOut: 20, PendingPacketEvictions: 5,
	})
	previous := m.uiState.StatisticsView.GetDropSummary()

	failed := open
	failed.Config.Inputs = []string{filepath.Join(t.TempDir(), "missing.pcap")}
	m, cmd := m.openOffline(failed)
	require.Equal(t, previous, m.uiState.StatisticsView.GetDropSummary())
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.Error(t, result.err)
	m, _ = m.completeOffline(result)
	require.Equal(t, previous, m.uiState.StatisticsView.GetDropSummary())

	m, cmd = m.openOffline(open)
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, _ = m.cancelOffline()
	m, cleanup := m.completeOffline(result)
	updated, _ := m.update(cleanup())
	m = updated.(Model)
	require.Equal(t, previous, m.uiState.StatisticsView.GetDropSummary())

	m, cmd = m.openOffline(open)
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, cleanup = m.completeOffline(result)
	cleanup()
	// A refresh must not restore losses from a retained bridge snapshot.
	m.uiState.StatisticsView.UpdateDropsFromBridge()
	require.False(t, m.uiState.StatisticsView.GetDropStats().HasDrops(), "new complete offline session must not inherit prior live capture losses")
	require.Zero(t, m.uiState.StatisticsView.GetDropSummary().DisplayDrops)
}
