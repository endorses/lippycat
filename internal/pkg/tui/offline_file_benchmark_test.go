//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

// BenchmarkOfflineFileIndex profiles a local capture without committing traffic
// fixtures. Set LIPPYCAT_BENCH_PCAP and use -benchtime=1x for a full file open.
func BenchmarkOfflineFileIndex(b *testing.B) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		b.Skip("set LIPPYCAT_BENCH_PCAP to a local capture")
	}
	info, err := os.Stat(path)
	require.NoError(b, err)
	b.SetBytes(info.Size())
	for i := 0; i < b.N; i++ {
		open := FreezeOfflineOpen([]string{path}, "", 10000)
		open.Limits.Directory = b.TempDir()
		storage, err := offline.NewStorage(open.Limits)
		require.NoError(b, err)
		b.Cleanup(func() { require.NoError(b, storage.Close()) })
		start := time.Now()
		var previous offline.State
		session, err := indexOfflineDataset(context.Background(), storage, 1, open.Config, func(p offline.Progress) {
			if p.State != previous {
				b.Logf("phase=%v elapsed=%v packets=%d", p.State, time.Since(start), p.LogicalPackets)
				previous = p.State
			}
		})
		if session != nil {
			b.Cleanup(func() { require.NoError(b, session.Close()) })
		}
		require.NoError(b, err)
		b.ReportMetric(float64(session.Dataset.Count()), "packets/op")
		b.ReportMetric(float64(session.Dataset.Resources().DiskBytes), "index-bytes/op")
		b.ReportMetric(float64(session.EventStore.Stats().Arrived), "events/op")
		require.NoError(b, filepath.WalkDir(open.Limits.Directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			switch entry.Name() {
			case "summaries", "details", "offsets":
				info, err := entry.Info()
				if err != nil {
					return err
				}
				b.ReportMetric(float64(info.Size()), entry.Name()+"-bytes/op")
			}
			return nil
		}))
		require.NoError(b, session.Close())
		require.NoError(b, storage.Close())
	}
}
