//go:build tui || all

package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func exportTestDetail(id int) offline.Detail {
	return offline.Detail{ID: offline.PacketID(id), CapturedLength: 3, OriginalLength: 42, Packet: types.PacketDisplay{Timestamp: time.Unix(int64(id), 123456789), LinkType: layers.LinkTypeEthernet, RawData: []byte{byte(id), byte(id >> 8), byte(id >> 16)}}}
}

func exportTestRaw(id int) offline.RawRecord {
	d := exportTestDetail(id)
	return offline.RawRecord{ID: d.ID, Timestamp: d.Packet.Timestamp, CapturedLength: d.CapturedLength, OriginalLength: d.OriginalLength, LinkType: d.Packet.LinkType, RawData: d.Packet.RawData}
}

func TestOfflineExportCompleteFilteredAndUnfiltered(t *testing.T) {
	s := testOfflineStorage(t)
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	const total = 4097
	for i := 0; i < total; i++ {
		require.NoError(t, b.Append(context.Background(), exportTestDetail(i)))
	}
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	for _, filtered := range []bool{false, true} {
		t.Run(map[bool]string{false: "all", true: "beginning_middle_end"}[filtered], func(t *testing.T) {
			spec := offline.QuerySpec{Token: offline.Token{Dataset: 1, Query: 1}}
			if filtered {
				spec.Match = func(s offline.Summary) bool { return s.ID == 0 || s.ID == total/2 || s.ID == total-1 }
			}
			q, err := d.Query(context.Background(), spec)
			require.NoError(t, err)
			pin, err := offline.PinQuery(q)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "result.pcap")
			count, err := exportOfflinePCAP(context.Background(), path, pin.IterateRaw)
			require.NoError(t, err)
			require.Equal(t, q.Count(), count)
			require.NoError(t, pin.Close())
			require.NoError(t, q.Close())
			f, err := os.Open(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, f.Close()) }()
			r, err := pcapgo.NewReader(f)
			require.NoError(t, err)
			require.Equal(t, layers.LinkTypeEthernet, r.LinkType())
			seen := 0
			for i := 0; i < total; i++ {
				if filtered && i != 0 && i != total/2 && i != total-1 {
					continue
				}
				raw, ci, err := r.ReadPacketData()
				require.NoError(t, err)
				detail := exportTestDetail(i)
				require.Equal(t, detail.Packet.RawData, raw)
				require.Equal(t, detail.Packet.Timestamp.UTC(), ci.Timestamp.UTC())
				require.Equal(t, 42, ci.Length)
				require.Equal(t, 3, ci.CaptureLength)
				seen++
			}
			_, _, err = r.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)
			require.Equal(t, uint64(seen), count)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestOfflineExportFailurePreservesDestination(t *testing.T) {
	for _, kind := range []string{"cancel", "mixed_links", "read_error", "bad_lengths", "empty"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "saved.pcap")
			require.NoError(t, os.WriteFile(path, []byte("existing"), 0600))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			iterate := func(ctx context.Context, visit func(offline.RawRecord) error) error {
				if kind == "empty" {
					return nil
				}
				if err := visit(exportTestRaw(0)); err != nil {
					return err
				}
				d := exportTestRaw(1)
				switch kind {
				case "cancel":
					cancel()
				case "mixed_links":
					d.LinkType = layers.LinkTypeRaw
				case "read_error":
					return errors.New("corrupt detail")
				case "bad_lengths":
					d.CapturedLength = 2
				}
				return visit(d)
			}
			_, err := exportOfflinePCAP(ctx, path, iterate)
			require.Error(t, err)
			if kind == "cancel" {
				require.ErrorIs(t, err, context.Canceled)
			}
			if kind == "mixed_links" {
				require.Contains(t, err.Error(), "mixed link types")
			}
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "existing", string(raw))
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

type offlineExportFailWriter struct{ remaining int }

func (w *offlineExportFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, io.ErrClosedPipe
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestOfflineExportWriterErrorsAndOneRecordMemory(t *testing.T) {
	for _, remaining := range []int{0, 24, 40} {
		_, err := writeOfflinePCAP(context.Background(), &offlineExportFailWriter{remaining}, func(ctx context.Context, visit func(offline.RawRecord) error) error { return visit(exportTestRaw(0)) })
		require.ErrorContains(t, err, io.ErrClosedPipe.Error())
	}
	var output bytes.Buffer
	count, err := writeOfflinePCAP(context.Background(), &output, func(ctx context.Context, visit func(offline.RawRecord) error) error {
		d := exportTestRaw(0)
		for i := 0; i < 10; i++ {
			d.RawData[0] = byte(i)
			if err := visit(d); err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, uint64(10), count)
	r, err := pcapgo.NewReader(&output)
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		raw, _, err := r.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, byte(i), raw[0])
	}
}

func TestOfflineExportPinsQueryBeforeAbandonedCommand(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	path := filepath.Join(t.TempDir(), "all.pcap")
	cmd := m.startOfflineExport(path)
	require.NotNil(t, cmd)
	// Deliberately never execute cmd. The session still owns the running worker.
	export := m.offlineExport
	require.NotNil(t, export)
	select {
	case <-export.done:
	case <-time.After(10 * time.Second):
		t.Fatal("export worker depended on command execution")
	}
	require.NoError(t, export.result.Error)
	require.Equal(t, uint64(1077), export.result.PacketsSaved)
	require.False(t, m.exportRunning())
}

func TestOfflineExportReadyWithoutPacketView(t *testing.T) {
	m := readyOfflineBrowser(t)
	if m.offlineBrowse != nil {
		require.NoError(t, m.offlineBrowse.owner.close())
	}
	m.offlineBrowse = nil
	m.offlineSession.browser = nil
	m.startOfflineExport(filepath.Join(t.TempDir(), "unvisited.pcap"))
	require.NotNil(t, m.offlineExport)
	<-m.offlineExport.done
	require.NoError(t, m.offlineExport.result.Error)
	require.Equal(t, uint64(1077), m.offlineExport.result.PacketsSaved)
}

func TestOfflineExportInstalledFilterSnapshot(t *testing.T) {
	m := loadOfflineBrowser(t, readyOfflineBrowser(t))
	b := m.offlineBrowse.owner
	q, err := b.dataset.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: b.dataset.Generation(), Query: 2}, Match: func(s offline.Summary) bool { return s.ID == 0 || s.ID == 500 || s.ID == 1076 }})
	require.NoError(t, err)
	b.mu.Lock()
	old := b.query
	b.query = q
	b.mu.Unlock()
	require.NoError(t, old.Close())
	m.startOfflineExport(filepath.Join(t.TempDir(), "filtered.pcap"))
	// Replace the active filter immediately, while the command is still queued.
	all, err := offline.AllPackets(context.Background(), b.dataset, offline.Token{Dataset: b.dataset.Generation(), Query: 3})
	require.NoError(t, err)
	b.mu.Lock()
	b.query = all
	b.mu.Unlock()
	closed := make(chan error, 1)
	go func() { closed <- q.Close() }()
	<-m.offlineExport.done
	require.NoError(t, m.offlineExport.result.Error)
	require.Equal(t, uint64(3), m.offlineExport.result.PacketsSaved)
	require.NoError(t, <-closed)
}

func TestOfflineExportSessionCleanupCancelsAndJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &offlineExportState{cancel: cancel, done: make(chan struct{})}
	go func() { <-ctx.Done(); close(s.done) }()
	session := &offlineIndexedSession{export: s}
	require.NoError(t, session.Close())
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	select {
	case <-s.done:
	default:
		t.Fatal("session cleanup did not join export")
	}
}
