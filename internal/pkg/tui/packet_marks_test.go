//go:build tui || all

package tui

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func markedPacketModel(t *testing.T) Model {
	t.Helper()
	m := responsiveDetailModel(t, "packets", 180, 35)
	m.packetStore = store.NewPacketStore(5)
	packets := make([]components.PacketDisplay, 5)
	for i := range packets {
		packets[i] = components.PacketDisplay{Timestamp: time.Unix(100, int64(i)), Protocol: "TCP", RawData: []byte{byte(i), 2, 3}, Length: 42, LinkType: layers.LinkTypeEthernet}
	}
	m.packetStore.AddPacketBatch(packets)
	m.uiState.PacketList.SetPackets(m.packetStore.GetPacketsInOrder())
	m.uiState.PacketList.SetCursor(0)
	m.uiState.FocusedPane = "left"
	return m
}

func markKey(t *testing.T, m Model, key rune) Model {
	t.Helper()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
	return next.(Model)
}

func TestPacketMarksKeyboardRangesAndLimits(t *testing.T) {
	m := markedPacketModel(t)
	m = markKey(t, m, 'm')
	require.Contains(t, m.packetMarks.records, uint64(1))
	m.uiState.PacketList.SetCursor(3)
	m = markKey(t, m, 'M')
	require.Len(t, m.packetMarks.records, 4)
	m = markKey(t, m, 'm')
	require.NotContains(t, m.packetMarks.records, uint64(4))
	require.Equal(t, uint64(4), m.packetMarks.anchor)
	before := clonePacketMarks(m.packetMarks.records)
	m.packetMarks.maxPackets = 2
	m.uiState.PacketList.SetCursor(0)
	require.NotNil(t, m.markPacketRange(true))
	require.Equal(t, before, m.packetMarks.records, "failed replacing range must be atomic")
	m.packetMarks.maxPackets = 10
	m.packetMarks.maxBytes = m.packetMarks.bytes
	m.uiState.PacketList.SetCursor(4)
	m = markKey(t, m, 'm')
	require.Equal(t, before, m.packetMarks.records, "failed byte admission preserves marks")
	m.uiState.FocusedPane = "right"
	m = markKey(t, m, 'm')
	require.Equal(t, before, m.packetMarks.records, "details focus must not mark hidden list rows")
}

func TestPacketMarksMouseRanges(t *testing.T) {
	m := markedPacketModel(t)
	click := func(row int, ctrl, shift bool) {
		msg := tea.MouseMsg{X: 5, Y: m.captureContentOrigin() + 3 + row, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress, Ctrl: ctrl, Shift: shift}
		next, _ := m.Update(msg)
		m = next.(Model)
		next, _ = m.Update(tea.MouseMsg{Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease, X: msg.X, Y: msg.Y})
		m = next.(Model)
	}
	click(1, true, false)
	require.Nil(t, m.textSelection)
	require.Contains(t, m.packetMarks.records, uint64(2))
	click(3, false, true)
	require.Len(t, m.packetMarks.records, 3)
	require.NotContains(t, m.packetMarks.records, uint64(1))
	click(0, true, true)
	require.Len(t, m.packetMarks.records, 4)
	click(4, false, false)
	require.Len(t, m.packetMarks.records, 4, "plain click keeps marks")
	require.Equal(t, uint64(5), m.packetMarks.anchor)
	require.Equal(t, "left", m.uiState.FocusedPane)
	click(4, true, false)
	require.Len(t, m.packetMarks.records, 5, "modified click does not double-click details")
}

func runMarkedSave(t *testing.T, cmd tea.Cmd) SaveCompleteMsg {
	t.Helper()
	msg := cmd()
	if result, ok := msg.(SaveCompleteMsg); ok {
		return result
	}
	if batch, ok := msg.(tea.BatchMsg); ok {
		// The first command updates the toast; the final command writes the file.
		return runMarkedSave(t, batch[len(batch)-1])
	}
	t.Fatalf("unexpected save command result %T", msg)
	return SaveCompleteMsg{}
}

func TestPacketMarksRetainBytesAndExportHiddenEvictedSnapshot(t *testing.T) {
	m := markedPacketModel(t)
	m.uiState.PacketList.SetCursor(3)
	m = markKey(t, m, 'm')
	m.uiState.PacketList.SetCursor(0)
	m = markKey(t, m, 'm')
	// Capture bytes must be copied when marking, not borrowed from the buffer.
	packets := m.packetStore.GetPacketsInOrder()
	packets[0].RawData[0] = 99
	filter := filters.NewTextFilter("UDP", []string{"protocol"})
	m.packetStore.AddFilter(filter)
	m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
	require.Len(t, m.packetMarks.records, 2)
	for i := 0; i < 6; i++ {
		m.packetStore.AddPacket(components.PacketDisplay{Protocol: "UDP"})
	}
	m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
	path := filepath.Join(t.TempDir(), "marked.pcap")
	cmd := m.proceedWithSave(path)
	require.True(t, m.uiState.SaveInProgress)
	require.False(t, m.uiState.StreamingSave)
	m.clearPacketMarks() // Export owns the submission snapshot even after clearing.
	result := runMarkedSave(t, cmd)
	require.NoError(t, result.Error)
	require.Equal(t, uint64(2), result.PacketsSaved)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for _, i := range []byte{0, 3} {
		raw, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, []byte{i, 2, 3}, raw)
		require.Equal(t, 42, ci.Length)
		require.True(t, time.Unix(100, int64(i)).Equal(ci.Timestamp))
	}
	_, _, err = r.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}

func TestPacketMarksMixedLinksPreserveDestination(t *testing.T) {
	m := markedPacketModel(t)
	m = markKey(t, m, 'm')
	p := m.uiState.PacketList.GetPackets()[1]
	p.LinkType = layers.LinkTypeLinuxSLL
	require.Nil(t, m.togglePacketMark(p))
	path := filepath.Join(t.TempDir(), "existing.pcap")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	result := runMarkedSave(t, m.proceedWithSave(path))
	require.ErrorContains(t, result.Error, "mixed link types")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
	require.Len(t, m.packetMarks.records, 2)
}

func TestPacketMarksDialogClearAndFlush(t *testing.T) {
	m := markedPacketModel(t)
	m = markKey(t, m, 'm')
	m = markKey(t, m, 'w')
	require.Contains(t, m.uiState.FileDialog.View(), "Save 1 marked packets")
	next, _ := m.Update(components.ClearPacketMarksMsg{})
	m = next.(Model)
	require.Empty(t, m.packetMarks.records)
	m.uiState.FileDialog.Deactivate()
	m = markKey(t, m, 'm')
	require.Len(t, m.packetMarks.records, 1)
	m = markKey(t, m, 'x')
	require.Empty(t, m.packetMarks.records)
}

func TestPacketMarksStaleRangeAnchorDoesNotMove(t *testing.T) {
	m := markedPacketModel(t)
	m = markKey(t, m, 'm')
	packets := m.uiState.PacketList.GetPackets()
	m.uiState.PacketList.SetPackets(packets[1:])
	m.uiState.PacketList.SetCursor(1)
	m = markKey(t, m, 'M')
	require.Len(t, m.packetMarks.records, 1)
	require.Contains(t, m.packetMarks.records, uint64(1))
}

func TestMarkedExportOwnerStartsWithoutDeliveryAndJoinsShutdown(t *testing.T) {
	m := markedPacketModel(t)
	original := m // The original program owner must see work from later model copies.
	m = markKey(t, m, 'm')
	dir := t.TempDir()
	path := filepath.Join(dir, "marked.pcap")
	m.proceedWithSave(path) // Deliberately abandon the Bubble Tea delivery command.
	state := m.markedExports.current()
	require.NotNil(t, state)
	original.Shutdown()
	select {
	case <-state.done:
	default:
		t.Fatal("shutdown returned before export worker cleanup")
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.Equal(t, "marked.pcap", entry.Name(), "no incomplete export files may remain")
	}
}

func TestMarkedExportLateStreamingCompletionKeepsGuard(t *testing.T) {
	m := markedPacketModel(t)
	m = markKey(t, m, 'm')
	// Hold a tracked export at its completion boundary while the earlier
	// recording-stop result is delivered. No timing assumptions about disk I/O.
	state := &offlineExportState{cancel: func() {}, done: make(chan struct{})}
	m.markedExports.state = state
	defer close(state.done)
	m.uiState.SaveInProgress = true
	m, _ = m.handleSaveCompleteMsg(SaveCompleteMsg{Success: true, Streaming: true})
	require.True(t, m.uiState.SaveInProgress)
	require.True(t, m.exportRunning())
	m = markKey(t, m, 'w')
	require.False(t, m.uiState.FileDialog.IsActive(), "late stop completion must not admit another save")
}
