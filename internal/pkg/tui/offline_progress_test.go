//go:build tui || all

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineProgressKnownAndUnknownTotals(t *testing.T) {
	require.Contains(t, offlineProgressBar(0, 100, true, 0), "  0%")
	require.Contains(t, offlineProgressBar(1, 2, true, 0), " 50%")
	require.Contains(t, offlineProgressBar(9999, 10000, true, 0), " 99%")
	require.Contains(t, offlineProgressBar(100, 100, true, 0), "100%")
	require.Contains(t, offlineProgressBar(0, 0, true, 0), "100%")
	unknown := offlineProgressBar(100, 0, false, 0)
	require.NotContains(t, unknown, "%")
	require.NotEqual(t, unknown, offlineProgressBar(100, 0, false, time.Second))
}

func TestOfflineFilterBarAndCompactModal(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, false, "", false)
	m.uiState.Width, m.uiState.Height = 120, 40
	m.offlineFilter = &offlineFilterState{owner: &offlineFilterOwner{
		progress: offline.QueryProgress{Scanned: 25, Total: 100, Matched: 3},
	}}
	view := m.offlineFilterModal()
	require.Contains(t, view, "25%")
	require.Contains(t, view, "Matches: 3")
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "╭") {
			// Shared renderer adds two border cells to the requested width.
			require.Equal(t, offlineProgressModalWidth+2, len([]rune(strings.TrimSpace(line))))
		}
	}
	m.offlineFilter.cancelled = true
	require.NotContains(t, m.offlineFilterModal(), "%")
	require.Contains(t, m.offlineFilterModal(), "Waiting for cleanup")
}

func TestOfflineOpeningBarOnlyUsesKnownIndexingTotal(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, false, "", false)
	m.uiState.Width, m.uiState.Height = 120, 40
	m.offlineProgress = offline.Progress{State: offline.Reading, LogicalPackets: 50}
	require.NotContains(t, m.offlineModal(), "%")
	m.offlineProgress.State = offline.Indexing
	m.offlineProgress.TotalPackets = 100
	require.Contains(t, m.offlineModal(), "50%")
	m.offlineProgress.State = offline.Finalizing
	require.NotContains(t, m.offlineModal(), "%")
	m.offlineProgress.State = offline.Cancelling
	require.NotContains(t, m.offlineModal(), "%")
}
