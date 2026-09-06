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
	"github.com/stretchr/testify/require"
)

// Run each backend in fresh processes with -benchtime=1x. The explicit ready
// metric excludes fixture warming, compilation, inspection and cleanup.
func BenchmarkOfflineCompactCompleted(b *testing.B) {
	for _, candidate := range []struct {
		name  string
		build offlineOracleBuilder
	}{{"legacy", indexOfflineLegacyDataset}, {"compact", indexOfflineCompactDataset}, {"compact-sync", func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		return indexOfflineDatasetBackendWithAsync(ctx, storage, generation, cfg, report, nil, true, true, false)
	}}, {"compact-workers", func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		return indexOfflineDatasetBackendWithWorkers(ctx, storage, generation, cfg, report, nil, true, true, true, true)
	}}} {
		b.Run(candidate.name, func(b *testing.B) {
			path := os.Getenv("LIPPYCAT_BENCH_PCAP")
			if path == "" {
				b.Skip("set LIPPYCAT_BENCH_PCAP to a local capture")
			}
			b.StopTimer()
			f, err := os.Open(path)
			require.NoError(b, err)
			_, err = io.Copy(io.Discard, f)
			require.NoError(b, err)
			require.NoError(b, f.Close())
			for i := 0; i < b.N; i++ {
				open := FreezeOfflineOpen([]string{path}, "", 10000)
				open.Limits.Directory = b.TempDir()
				storage, err := offline.NewStorage(open.Limits)
				require.NoError(b, err)
				b.Cleanup(func() { require.NoError(b, storage.Close()) })
				b.StartTimer()
				start := time.Now()
				session, err := candidate.build(context.Background(), storage, 1, open.Config, nil)
				elapsed := time.Since(start)
				b.StopTimer()
				if session != nil {
					b.Cleanup(func() { require.NoError(b, session.Close()) })
				}
				require.NoError(b, err)
				b.ReportMetric(elapsed.Seconds(), "ready-seconds/op")
				b.ReportMetric(float64(session.Dataset.Count()), "packets/op")
				b.ReportMetric(float64(session.EventStore.Stats().Arrived), "events/op")
				usage := storage.Resources()
				b.ReportMetric(float64(usage.DiskBytes), "accounted-disk-bytes/op")
				b.ReportMetric(float64(usage.CachedBytes+usage.PinnedBytes+usage.PrefetchBytes+usage.InFlightBytes), "accounted-memory-bytes/op")
				var completeBytes uint64
				require.NoError(b, filepath.WalkDir(open.Limits.Directory, func(_ string, entry os.DirEntry, walkErr error) error {
					if walkErr != nil || entry.IsDir() {
						return walkErr
					}
					info, err := entry.Info()
					if err != nil {
						return err
					}
					completeBytes += uint64(info.Size())
					switch entry.Name() {
					case "summaries", "details", "offsets", "manifest":
						b.ReportMetric(float64(info.Size()), entry.Name()+"-bytes/op")
					}
					return nil
				}))
				require.Equal(b, completeBytes, usage.DiskBytes, "all completed sidecars must be charged")
				b.ReportMetric(float64(completeBytes), "complete-bytes/op")
				require.NoError(b, session.Close())
				require.NoError(b, storage.Close())
			}
		})
	}
}
