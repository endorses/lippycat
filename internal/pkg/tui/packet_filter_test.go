//go:build tui || all

package tui

import (
	"fmt"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func packetFilterTestModel(mode components.CaptureMode, capacity int) Model {
	m := Model{
		captureMode: mode,
		packetStore: store.NewPacketStore(capacity),
		uiState:     store.NewUIState(themes.Solarized()),
	}
	m.uiState.Capturing = true
	return m
}

// The scan is the first command when paired with a toast. Do not run toast
// timers: these tests control scan completion and message delivery explicitly.
func packetFilterResult(t *testing.T, cmd tea.Cmd) packetFilterMsg {
	t.Helper()
	require.NotNil(t, cmd)
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		return packetFilterResult(t, batch[0])
	}
	result, ok := msg.(packetFilterMsg)
	require.True(t, ok, "expected packet filter result, got %T", msg)
	return result
}

func TestPacketFilterSnapshotLiveAndRemote(t *testing.T) {
	for _, mode := range []components.CaptureMode{components.CaptureModeLive, components.CaptureModeRemote} {
		for _, paused := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode=%d/paused=%t", mode, paused), func(t *testing.T) {
				m := packetFilterTestModel(mode, 8)
				m.uiState.Paused = paused
				old := components.PacketDisplay{Protocol: "TCP", Info: "old keep"}
				nonmatch := components.PacketDisplay{Protocol: "UDP", Info: "skip"}
				m.packetStore.AddPacketBatch([]components.PacketDisplay{old, nonmatch})
				m.updatePacketListIncremental()

				cmd := m.parseAndApplyFilter("protocol:TCP")
				newPacket := components.PacketDisplay{Protocol: "TCP", Info: "new keep"}
				m.packetStore.AddPacketBatch([]components.PacketDisplay{nonmatch, newPacket})
				m.updatePacketListIncremental()
				require.Equal(t, []components.PacketDisplay{newPacket}, m.uiState.PacketList.GetPackets(), "new arrivals are visible before historical filtering completes")

				result := packetFilterResult(t, cmd)
				// Another arrival between evaluation and completion must also survive.
				latest := components.PacketDisplay{Protocol: "TCP", Info: "latest other"}
				m.packetStore.AddPacket(latest)
				m.updatePacketListIncremental()
				// Async completion must bypass modal routing.
				m.uiState.ConfirmDialog.Show(components.ConfirmDialogOptions{Title: "Test modal"})
				updated, _ := m.update(result)
				m = updated.(Model)
				want := []components.PacketDisplay{old, newPacket, latest}
				require.Equal(t, want, m.uiState.PacketList.GetPackets())
				m.updatePacketListIncremental()
				require.Equal(t, want, m.uiState.PacketList.GetPackets(), "completion must not duplicate new arrivals on the next tick")

				stacked := m.parseAndApplyFilter("info:keep")
				m, _ = m.handlePacketFilter(packetFilterResult(t, stacked))
				require.Equal(t, []components.PacketDisplay{old, newPacket}, m.uiState.PacketList.GetPackets())
				m, cmd = m.handleRemoveLastFilter()
				m, _ = m.handlePacketFilter(packetFilterResult(t, cmd))
				require.Equal(t, want, m.uiState.PacketList.GetPackets(), "removing a stacked filter must restore retained matches")
				m, _ = m.handleRemoveLastFilter()
				require.Equal(t, m.packetStore.GetPacketsInOrder(), m.uiState.PacketList.GetPackets())
				m.updatePacketListIncremental()
				require.Equal(t, m.packetStore.GetPacketsInOrder(), m.uiState.PacketList.GetPackets())
			})
		}
	}
}

func TestPacketFilterInputStartsSnapshot(t *testing.T) {
	previousConfig := viper.ConfigFileUsed()
	previousHistory := viper.Get("watch.filter_history")
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() {
		viper.SetConfigFile(previousConfig)
		viper.Set("watch.filter_history", previousHistory)
	})
	m := packetFilterTestModel(components.CaptureModeLive, 8)
	packet := components.PacketDisplay{Protocol: "TCP"}
	m.packetStore.AddPacket(packet)
	m, _ = m.handleEnterFilterMode()
	for _, r := range "protocol:TCP" {
		m.uiState.FilterInput.InsertRune(r)
	}
	updated, cmd := m.handleFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	require.False(t, m.uiState.FilterMode)
	m, _ = m.handlePacketFilter(packetFilterResult(t, cmd))
	require.Equal(t, []components.PacketDisplay{packet}, m.uiState.PacketList.GetPackets())
}

func TestPacketFilterObsoleteCompletion(t *testing.T) {
	for _, action := range []string{"replace-filter", "clear-filters", "clear-packets", "replace-store", "remove-last-filter"} {
		t.Run(action, func(t *testing.T) {
			m := packetFilterTestModel(components.CaptureModeRemote, 8)
			m.packetStore.AddPacketBatch([]components.PacketDisplay{{Protocol: "TCP"}, {Protocol: "UDP"}})
			result := packetFilterResult(t, m.parseAndApplyFilter("protocol:TCP"))
			switch action {
			case "replace-filter":
				cmd := m.parseAndApplyFilter("protocol:UDP")
				m, _ = m.handlePacketFilter(packetFilterResult(t, cmd))
			case "clear-filters":
				m, _ = m.handleClearAllFilters()
			case "clear-packets":
				m.packetStore.Clear()
				m.doFullPacketListRefresh(true)
			case "replace-store":
				m.packetStore = store.NewPacketStore(8)
				m.doFullPacketListRefresh(false)
			case "remove-last-filter":
				m, _ = m.handleRemoveLastFilter()
			}
			want := append([]components.PacketDisplay{}, m.uiState.PacketList.GetPackets()...)
			m, _ = m.handlePacketFilter(result)
			require.Equal(t, want, append([]components.PacketDisplay{}, m.uiState.PacketList.GetPackets()...))
		})
	}
}

func TestPacketFilterResizeRestartsSnapshot(t *testing.T) {
	previousConfig := viper.ConfigFileUsed()
	previousSize := viper.Get("watch.buffer_size")
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() {
		viper.SetConfigFile(previousConfig)
		viper.Set("watch.buffer_size", previousSize)
	})
	m := packetFilterTestModel(components.CaptureModeLive, 8)
	m.uiState.SettingsView = components.NewSettingsView("", 8, false, "", "")
	m.packetStore.AddPacketBatch([]components.PacketDisplay{
		{Protocol: "TCP", Info: "evicted"},
		{Protocol: "UDP"},
		{Protocol: "TCP", Info: "retained"},
	})
	stale := packetFilterResult(t, m.parseAndApplyFilter("protocol:TCP"))
	m, cmd := m.handleUpdateBufferSizeMsg(components.UpdateBufferSizeMsg{Size: 2})
	m, _ = m.handlePacketFilter(packetFilterResult(t, cmd))
	m, _ = m.handlePacketFilter(stale)
	require.Equal(t, []components.PacketDisplay{{Protocol: "TCP", Info: "retained"}}, m.uiState.PacketList.GetPackets())
}
