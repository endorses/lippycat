//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineDetailScrollSurvivesSameCursorViewportReload(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.DetailsPanel.SetSize(40, 8)
	m.uiState.DetailsPanel.SetScrollOffset(5)
	_, _, offset := m.uiState.DetailsPanel.ScrollState()
	require.Equal(t, 5, offset)
	priorPin := m.offlineBrowse.current.detail
	m.uiState.PacketList.SetSize(120, 12)
	cmd := m.syncOfflineBrowser()
	require.NotNil(t, cmd)
	require.Empty(t, priorPin.Value.Packet.RawData, "old leased payload released before reload")
	total, _, offset := m.uiState.DetailsPanel.ScrollState()
	require.LessOrEqual(t, total, 1, "loading viewport must drop old rendered content")
	require.Zero(t, offset)
	require.Contains(t, m.uiState.DetailsPanel.View(true), "Loading packet details")
	msg := cmd().(offlineBrowseMsg)
	require.NoError(t, msg.result.err)
	m, _ = m.handleOfflineBrowse(msg)
	_, _, offset = m.uiState.DetailsPanel.ScrollState()
	require.Equal(t, 5, offset, "same packet keeps reading position after viewport resize")
	require.NotSame(t, priorPin, m.offlineBrowse.current.detail)
	m.uiState.PacketList.SetLogicalCursor(1)
	m = loadOfflineBrowser(t, m)
	_, _, offset = m.uiState.DetailsPanel.ScrollState()
	require.Zero(t, offset, "another selected packet starts at the top")
}

func TestOfflineDetailScrollSurvivesHiddenBrowserRelease(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.DetailsPanel.SetSize(40, 8)
	m.uiState.DetailsPanel.SetScrollOffset(5)
	m.uiState.ViewMode = "events"
	cleanup := m.syncOfflineBrowser()
	require.NotNil(t, cleanup)
	cleanup()
	require.Nil(t, m.offlineBrowse.current)
	require.Zero(t, m.offlineSession.Dataset.Resources().PinnedBytes)
	require.Contains(t, m.uiState.DetailsPanel.View(false), "Select a packet")
	m.uiState.ViewMode = "packets"
	m = loadOfflineBrowser(t, m)
	_, _, offset := m.uiState.DetailsPanel.ScrollState()
	require.Equal(t, 5, offset)
}

func TestOfflineDetailScrollIdentityExcludesStaleDatasetsQueriesAndCursors(t *testing.T) {
	s := offlineBrowserState{detailScrollValid: true, detailScroll: 5, detailScrollCursor: 4, detailScrollToken: offline.Token{Dataset: 2, Query: 3}}
	require.True(t, s.matchesDetailScroll(offline.Token{Dataset: 2, Query: 3, Request: 999}, 4))
	require.False(t, s.matchesDetailScroll(offline.Token{Dataset: 5, Query: 3}, 4))
	require.False(t, s.matchesDetailScroll(offline.Token{Dataset: 2, Query: 6}, 4))
	require.False(t, s.matchesDetailScroll(offline.Token{Dataset: 2, Query: 3}, 5))
}
