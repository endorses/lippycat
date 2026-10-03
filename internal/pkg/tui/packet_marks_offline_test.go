//go:build tui || all

package tui

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflinePacketMarksRangeBeyondLoadedPage(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.ensurePacketMarks()
	require.Equal(t, uint64(1), m.uiState.PacketList.GetSelectedPacket().CaptureID)
	m.packetMarks.anchor = 1
	cmd := m.startOfflineMarkRange(1, 900, false)
	msg := cmd().(offlineMarkRangeMsg)
	require.NoError(t, msg.state.err)
	m, _ = m.handleOfflineMarkRange(msg)
	require.Len(t, m.packetMarks.records, 901)
	require.Contains(t, m.packetMarks.records, uint64(901))
	require.Zero(t, m.packetMarks.bytes)
	for _, record := range m.packetMarks.records {
		require.Nil(t, record.RawData, "offline marks retain disk identities, not borrowed packet payloads")
	}
	m.packetMarks.maxPackets = 5
	cmd = m.startOfflineMarkRange(1, 10, true)
	m, _ = m.handleOfflineMarkRange(cmd().(offlineMarkRangeMsg))
	require.Len(t, m.packetMarks.records, 901, "failed replacement preserves marks")
}

func TestOfflinePacketMarksDiscardStaleRange(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.ensurePacketMarks()
	cmd := m.startOfflineMarkRange(1, 500, false)
	msg := cmd().(offlineMarkRangeMsg)
	m.clearPacketMarks()
	m, _ = m.handleOfflineMarkRange(msg)
	require.Empty(t, m.packetMarks.records)
}

func TestOfflineMarkedExportIgnoresCurrentFilter(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	b := m.offlineBrowse.owner
	q, err := b.dataset.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: b.dataset.Generation(), Query: 2}, Match: func(s offline.Summary) bool { return s.ID == 500 }})
	require.NoError(t, err)
	b.mu.Lock()
	old := b.query
	b.query = q
	b.mu.Unlock()
	require.NoError(t, old.Close())
	path := filepath.Join(t.TempDir(), "marked.pcap")
	m.startMarkedOfflineExport(path, []uint64{1077, 1})
	<-m.offlineExport.done
	require.NoError(t, m.offlineExport.result.Error)
	require.EqualValues(t, 2, m.offlineExport.result.PacketsSaved)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	for _, id := range []offline.PacketID{0, 1076} {
		want, err := m.offlineSession.Dataset.Detail(context.Background(), offline.Token{Dataset: b.dataset.Generation()}, id)
		require.NoError(t, err)
		raw, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, want.Packet.RawData, raw)
		require.Equal(t, want.Packet.Timestamp, ci.Timestamp)
	}
	_, _, err = r.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
}

func TestOfflineMarkRangeAbandonedCommandSessionCleanup(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.startOfflineMarkRange(1, 1076, false)
	state := m.offlineSession.markRange
	closed := make(chan error, 1)
	go func() { closed <- m.offlineSession.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("session cleanup waited for an abandoned mark command")
	}
	select {
	case <-state.done:
	default:
		t.Fatal("mark worker was not joined")
	}
}

func TestOfflineMarkRangeRefreshesOpenSaveDialog(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	m.uiState.FileDialog.SetSize(m.uiState.Width, m.uiState.Height)
	m.ensurePacketMarks()
	cmd := m.startOfflineMarkRange(1, 10, false)
	msg := cmd().(offlineMarkRangeMsg)
	m, _ = m.handleSavePackets()
	require.True(t, m.uiState.FileDialog.IsActive())
	require.NotContains(t, m.uiState.FileDialog.View(), "marked packets")
	next, _ := m.Update(msg)
	m = next.(Model)
	require.Len(t, m.packetMarks.records, 11)
	require.Contains(t, m.uiState.FileDialog.View(), "Save 11 marked packets")
	require.Contains(t, m.uiState.FileDialog.View(), "Clear marks")
}
