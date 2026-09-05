//go:build tui || all

package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOfflineBrowserKeyboardNavigationLoadsEntireViewport(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.ViewMode = "packets"
	m.uiState.FocusedPane = "left"
	keys := []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune("G")},
		{Type: tea.KeyPgUp}, {Type: tea.KeyPgUp},
		{Type: tea.KeyPgDown}, {Type: tea.KeyPgDown},
		{Type: tea.KeyRunes, Runes: []rune("g")},
		{Type: tea.KeyPgDown}, {Type: tea.KeyPgDown},
		{Type: tea.KeyPgUp}, {Type: tea.KeyPgUp},
		{Type: tea.KeyRunes, Runes: []rune("G")},
		{Type: tea.KeyRunes, Runes: []rune("g")},
	}
	for _, key := range keys {
		updated, _ := m.Update(key)
		m = updated.(Model)
		browser := m.offlineBrowse.owner
		<-browser.done
		browser.mu.Lock()
		var result *offlineBrowseResult
		for pending := range browser.results {
			if pending.token.Request == m.offlineBrowse.request {
				result = pending
			}
		}
		browser.mu.Unlock()
		require.NotNil(t, result, "key %s", key.String())
		require.NoError(t, result.err)
		m, _ = m.handleOfflineBrowse(offlineBrowseMsg{browser, result})
		page := m.offlineBrowse.current.page
		start := m.uiState.PacketList.LogicalOffset()
		end := min(m.uiState.PacketList.LogicalCount(), start+uint64(m.uiState.PacketList.VisibleRows()))
		require.LessOrEqual(t, page.Row, start, "key %s must load rows above selection", key.String())
		require.GreaterOrEqual(t, page.Row+uint64(len(page.Rows)), end, "key %s must load rows below selection", key.String())
		require.Equal(t, offline.PacketID(m.uiState.PacketList.LogicalCursor()), m.offlineBrowse.current.detail.Value.ID)
		require.Nil(t, m.syncOfflineBrowser(), "key %s must leave a stable completed viewport", key.String())
	}
}

func TestOfflineBrowserSupersededResultReleasesPinBudget(t *testing.T) {
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 64 << 20, CacheBytes: (3 << 20) + (128 << 10), MaxRecordBytes: 1 << 20, MaxSources: 1}
	storage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	builder, err := storage.NewBuilder(1, nil)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		require.NoError(t, builder.Append(context.Background(), offline.Detail{Packet: types.PacketDisplay{RawData: make([]byte, 256<<10)}}))
	}
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	b := &offlineBrowser{dataset: dataset, results: make(map[*offlineBrowseResult]struct{})}
	defer func() {
		require.NoError(t, b.close())
		require.NoError(t, dataset.Close())
		require.NoError(t, storage.Close())
	}()
	first := b.load(offline.Token{Dataset: 1, Query: 1, Request: 1}, 0, 0, 1, limits.CacheBytes/4, false)().(offlineBrowseMsg)
	require.NoError(t, first.result.err)
	second := b.load(offline.Token{Dataset: 1, Query: 1, Request: 2}, 1, 1, 1, limits.CacheBytes/4, false)().(offlineBrowseMsg)
	require.NoError(t, second.result.err)
}

func TestOfflineBrowserRepeatedEndPreservesPendingLoading(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.ViewMode = "packets"
	m.uiState.FocusedPane = "left"
	m.uiState.DetailsPanel.SetSize(77, 25)
	m, _ = m.handleJumpToBottom()
	load := m.syncOfflineBrowser()
	require.NotNil(t, load)
	require.Contains(t, m.uiState.DetailsPanel.View(false), "Loading packet details")

	// Repeat End before Bubble Tea delivers the pending read result. Selection
	// is unchanged, so no replacement request should be needed.
	m, _ = m.handleJumpToBottom()
	require.Nil(t, m.syncOfflineBrowser())
	require.Contains(t, m.uiState.DetailsPanel.View(false), "Loading packet details")

	result := load().(offlineBrowseMsg)
	require.NoError(t, result.result.err)
	m, _ = m.handleOfflineBrowse(result)
	require.Equal(t, offline.PacketID(m.uiState.PacketList.LogicalCursor()), m.offlineBrowse.current.detail.Value.ID)
	require.NotContains(t, m.uiState.DetailsPanel.View(false), "Loading packet details")
}
