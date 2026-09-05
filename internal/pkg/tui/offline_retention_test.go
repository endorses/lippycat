//go:build tui || all

package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestOfflineNoticeBeforeDatasetAndModeChanges(t *testing.T) {
	m := NewModel(2, 8, "", "", []string{"fixture.pcap"}, false, false, "", false)
	m.packetStore.AddPacketBatch([]components.PacketDisplay{{}, {}, {}})
	m.prepareViewChrome()
	require.Contains(t, m.renderBottomArea("footer"), "No completed offline dataset.")
	require.NotContains(t, m.renderBottomArea("footer"), "retained packets only")
	require.Contains(t, m.uiState.Header.View(), "Retained: 2")
	m.uiState.FilterMode = true
	m.uiState.FilterInput.Activate()
	require.NotContains(t, m.renderBottomArea("footer"), "retained packets only")
	m.uiState.FilterMode = false
	m.packetStore.Clear()
	m.prepareViewChrome()
	require.Contains(t, m.renderBottomArea("footer"), "No completed offline dataset.")
	for _, mode := range []components.CaptureMode{components.CaptureModeLive, components.CaptureModeRemote} {
		m.captureMode = mode
		m.prepareViewChrome()
		require.Empty(t, m.uiState.OfflinePacketNotice)
		require.NotContains(t, m.uiState.FilterInput.View(), "retained packets")
		require.Contains(t, m.uiState.Header.View(), "Packets: 0")
	}
}

func TestOfflineRetentionNoticeFitsNarrowTerminal(t *testing.T) {
	m := NewModel(2, 8, "", "", []string{"fixture.pcap"}, false, false, "", false)
	for _, width := range []int{20, 40, 80} {
		m.uiState.Width = width
		m.prepareViewChrome()
		notice := m.renderBottomArea("footer")
		require.Len(t, strings.Split(notice, "\n"), 4)
		for _, line := range strings.Split(notice, "\n") {
			require.LessOrEqual(t, lipgloss.Width(line), width)
		}
		m.uiState.FilterInput.SetWidth(width)
		m.uiState.FilterInput.Activate()
		input := m.uiState.FilterInput.View()
		require.Equal(t, 3, lipgloss.Height(input))
		require.LessOrEqual(t, lipgloss.Width(input), width)
	}
	m.uiState.CallFilterInput.Activate()
	m.uiState.EventFilterInput.Activate()
	require.NotContains(t, m.uiState.CallFilterInput.View(), "retained packets only")
	require.NotContains(t, m.uiState.EventFilterInput.View(), "retained packets only")
}
