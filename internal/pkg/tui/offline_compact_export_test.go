//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineCompactPinnedExportAcrossSessionReplacement(t *testing.T) {
	ctx := context.Background()
	storage := testOfflineStorage(t)
	cfg := OfflineAnalysisConfig{Inputs: []string{writeCompactProtocolFixture(t)}, EventCapacity: 32}
	old, err := indexOfflineCompactDataset(ctx, storage, 51, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, old.Close()) })
	query, err := old.Dataset.Query(ctx, offline.QuerySpec{Token: offline.Token{Dataset: 51, Query: 1}, Match: func(s offline.Summary) bool { return s.ID%2 == 0 }})
	require.NoError(t, err)
	var expected []offline.Detail
	require.NoError(t, query.Iterate(ctx, func(d offline.Detail) error { expected = append(expected, d); return nil }))
	pin, err := offline.PinQuery(query)
	require.NoError(t, err)
	defer func() { require.NoError(t, pin.Close()) }()
	replacement, err := indexOfflineCompactDataset(ctx, storage, 52, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, replacement.Close()) })
	entered, release := make(chan struct{}), make(chan struct{})
	path := filepath.Join(t.TempDir(), "old-query.pcap")
	exported := make(chan error, 1)
	go func() {
		first := true
		_, err := exportOfflinePCAP(ctx, path, func(ctx context.Context, visit func(offline.RawRecord) error) error {
			return pin.IterateRaw(ctx, func(record offline.RawRecord) error {
				if first {
					first = false
					close(entered)
					<-release
				}
				return visit(record)
			})
		})
		closeErr := pin.Close()
		if err == nil {
			err = closeErr
		}
		exported <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("compact export did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- old.Dataset.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("dataset closed during pinned export: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-exported:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("compact export deadlocked behind replacement cleanup")
	}
	require.NoError(t, <-closed)
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	for _, want := range expected {
		raw, info, err := reader.ReadPacketData()
		require.NoError(t, err)
		require.Equal(t, want.Packet.RawData, raw)
		require.True(t, want.Packet.Timestamp.Equal(info.Timestamp))
		require.EqualValues(t, want.CapturedLength, info.CaptureLength)
		require.EqualValues(t, want.OriginalLength, info.Length)
	}
	_, err = replacement.Dataset.Detail(ctx, offline.Token{Dataset: 52}, 0)
	require.NoError(t, err)
}
