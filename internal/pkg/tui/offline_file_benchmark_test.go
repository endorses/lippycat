//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
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

// BenchmarkOfflineFilter measures the watch-file path after a completed index:
// compile the same TUI filter chain used by startOfflineFilter, run Dataset.Query,
// then request the first Page. The selective marker should normally match no
// packets; dense is its complement. Actual match counts are reported because a
// supplied capture may contain the marker. The empty chain is the all-match case.
//
// Run with LIPPYCAT_BENCH_PCAP and -benchtime=1x -benchmem. Indexing warms the
// source and sidecar filesystem caches, so these are post-index warm queries.
// A cold-cache result requires a separately controlled OS-cache experiment in a
// fresh process; do not compare it as equivalent to this run. Keep capture paths,
// contents, and raw profiles out of committed benchmark results.
func BenchmarkOfflineFilter(b *testing.B) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		b.Skip("set LIPPYCAT_BENCH_PCAP to a local capture")
	}
	b.StopTimer()
	open := FreezeOfflineOpen([]string{path}, "", 10000)
	open.Limits.Directory = b.TempDir()
	storage, err := offline.NewStorage(open.Limits)
	require.NoError(b, err)
	defer func() { require.NoError(b, storage.Close()) }()

	ctx := context.Background()
	var beforeIndex, afterIndex runtime.MemStats
	runtime.ReadMemStats(&beforeIndex)
	indexStart := time.Now()
	session, err := indexOfflineDataset(ctx, storage, 1, open.Config, nil)
	indexElapsed := time.Since(indexStart)
	require.NoError(b, err)
	defer func() { require.NoError(b, session.Close()) }()
	runtime.ReadMemStats(&afterIndex)
	indexDisk := storage.Resources().DiskBytes
	indexPeaks := storage.Peaks()

	const marker = "lippycat-benchmark-absent-marker-42f07c9d"
	for _, workload := range []struct {
		name  string
		chain func() *filters.FilterChain
	}{
		{"selective", func() *filters.FilterChain {
			chain := filters.NewFilterChain()
			chain.Add(filters.NewTextFilter(marker, []string{"info"}))
			return chain
		}},
		{"dense", func() *filters.FilterChain {
			chain := filters.NewFilterChain()
			chain.Add(filters.NewBooleanFilter(filters.OpNOT, filters.NewTextFilter(marker, []string{"info"}), nil, ""))
			return chain
		}},
		{"all-match", filters.NewFilterChain},
	} {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(indexElapsed.Seconds(), "index-seconds")
			b.ReportMetric(float64(afterIndex.TotalAlloc-beforeIndex.TotalAlloc), "index-allocated-B")
			b.ReportMetric(float64(indexDisk), "index-accounted-disk-B")
			b.ReportMetric(float64(indexPeaks.DiskBytes), "index-peak-accounted-disk-B")
			b.ReportMetric(float64(indexPeaks.MemoryBytes), "index-peak-accounted-memory-B")
			for i := 0; i < b.N; i++ {
				chain := workload.chain()
				compileStart := time.Now()
				expression, err := chain.OfflineExpression()
				require.NoError(b, err)
				compileElapsed := time.Since(compileStart)
				if !chain.IsEmpty() {
					require.NotNil(b, expression)
				}

				token := offline.Token{Dataset: session.Dataset.Generation(), Query: offline.QueryGeneration(i + 1)}
				spec := offline.QuerySpec{Token: token, Description: chain.GetFilterDescriptions()}
				if !chain.IsEmpty() {
					spec.Expression = expression
					spec.Match = func(summary offline.Summary) bool { return chain.Match(summary) }
				}
				var beforeQuery, afterQuery, afterPage runtime.MemStats
				runtime.ReadMemStats(&beforeQuery)
				queryStart := time.Now()
				query, err := session.Dataset.Query(ctx, spec)
				queryElapsed := time.Since(queryStart)
				require.NoError(b, err)
				runtime.ReadMemStats(&afterQuery)
				usage := storage.Resources()
				peaks := storage.Peaks()

				pageStart := time.Now()
				page, err := query.Page(ctx, offline.PageRequest{Token: token, Limit: 64, MaxBytes: offlinePageBudget(open.Limits)})
				pageElapsed := time.Since(pageStart)
				require.NoError(b, err)
				runtime.ReadMemStats(&afterPage)
				b.ReportMetric(compileElapsed.Seconds(), "compile-seconds/op")
				b.ReportMetric(queryElapsed.Seconds(), "query-seconds/op")
				b.ReportMetric(float64(afterQuery.TotalAlloc-beforeQuery.TotalAlloc), "query-allocated-B/op")
				b.ReportMetric(pageElapsed.Seconds(), "first-page-seconds/op")
				b.ReportMetric(float64(afterPage.TotalAlloc-afterQuery.TotalAlloc), "first-page-allocated-B/op")
				b.ReportMetric(float64(query.Count()), "matches/op")
				b.ReportMetric(float64(len(page.Rows)), "first-page-rows/op")
				b.ReportMetric(float64(usage.DiskBytes-indexDisk), "query-accounted-disk-B/op")
				b.ReportMetric(float64(peaks.MemoryBytes), "cumulative-peak-accounted-memory-B")
				b.ReportMetric(float64(peaks.DiskBytes), "cumulative-peak-accounted-disk-B")
				require.NoError(b, page.Close())
				require.NoError(b, query.Close())
			}
		})
	}
}
