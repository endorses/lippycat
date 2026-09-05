package offline_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Run each subbenchmark in a fresh compiled process to measure RSS independently.
// Fixed flow cardinality and fixed budgets isolate dataset infrastructure growth.
func BenchmarkPhase6Dataset(b *testing.B) {
	for _, count := range []int{100000, 1000000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			for iteration := 0; iteration < b.N; iteration++ {
				ctx := context.Background()
				storage, err := offline.NewStorage(offline.ResourceLimits{Directory: b.TempDir(), DiskBytes: 4 << 30, CacheBytes: 2 << 20, MaxRecordBytes: 64 << 10, MaxSources: 8})
				if err != nil {
					b.Fatal(err)
				}
				source := offline.SourcePosition{Path: "benchmark.pcap"}
				builder, err := storage.NewBuilder(1, []offline.SourcePosition{source})
				if err != nil {
					b.Fatal(err)
				}
				packet := types.PacketDisplay{Timestamp: time.Unix(1, 0).UTC(), Protocol: "UDP", Transport: 17, Length: 256, RawData: make([]byte, 256), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "1234", DstPort: "53"}
				var peakHeap uint64
				sampleHeap := func() {
					var memory runtime.MemStats
					runtime.ReadMemStats(&memory)
					if memory.HeapAlloc > peakHeap {
						peakHeap = memory.HeapAlloc
					}
				}
				start := time.Now()
				for i := 0; i < count; i++ {
					if i%1024 == 0 {
						sampleHeap()
					}
					source.Sequence = uint64(i)
					if err := builder.Append(ctx, offline.Detail{ID: offline.PacketID(i), Source: source, CapturedLength: 256, OriginalLength: 256, Packet: packet}); err != nil {
						b.Fatal(err)
					}
				}
				ds, err := builder.Finish(ctx)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(count)/time.Since(start).Seconds(), "index-packets/s")
				token := offline.Token{Dataset: 1, Query: 1}
				start = time.Now()
				q, err := ds.Query(ctx, offline.QuerySpec{Token: token, Match: func(offline.Summary) bool { return true }, Progress: func(offline.QueryProgress) { sampleHeap() }})
				if err != nil {
					b.Fatal(err)
				}
				if q.Count() != uint64(count) {
					b.Fatal("incomplete all-match query")
				}
				b.ReportMetric(float64(count)/time.Since(start).Seconds(), "filter-packets/s")
				b.ReportMetric(float64(ds.Resources().DiskBytes)/float64(count*256), "disk/raw-ratio")
				start = time.Now()
				page, err := q.Page(ctx, offline.PageRequest{Token: token, Limit: 64, MaxBytes: 128 << 10})
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(time.Since(start).Nanoseconds()), "first-page-ns")
				if err := page.Close(); err != nil {
					b.Fatal(err)
				}
				start = time.Now()
				for i := 0; i < 100; i++ {
					row := uint64((i * 7919) % (count - 64))
					page, err := q.Page(ctx, offline.PageRequest{Token: token, Row: row, Limit: 64, MaxBytes: 128 << 10})
					if err != nil {
						b.Fatal(err)
					}
					if len(page.Rows) == 0 || uint64(page.Rows[0].ID) != row {
						b.Fatal("wrong random row")
					}
					if err := page.Close(); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(time.Since(start).Nanoseconds())/100, "random-page-ns")
				start = time.Now()
				for i := 0; i < 100; i++ {
					if _, err := ds.Detail(ctx, token, offline.PacketID((i*7919)%count)); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(time.Since(start).Nanoseconds())/100, "detail-ns")
				cancelCtx, cancel := context.WithCancel(ctx)
				var cancelledAt time.Time
				token.Query++
				_, err = ds.Query(cancelCtx, offline.QuerySpec{Token: token, Match: func(offline.Summary) bool {
					if cancelledAt.IsZero() {
						cancelledAt = time.Now()
						cancel()
					}
					return true
				}})
				cancel()
				if !errors.Is(err, context.Canceled) {
					b.Fatalf("cancellation: %v", err)
				}
				b.ReportMetric(float64(time.Since(cancelledAt).Nanoseconds()), "query-cancel-cleanup-ns")
				runtime.GC()
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				b.ReportMetric(float64(memory.HeapAlloc), "live-heap-B")
				b.ReportMetric(float64(memory.HeapSys), "heap-system-B")
				b.ReportMetric(float64(peakHeap), "sampled-peak-heap-B")
				if path := os.Getenv("LIPPYCAT_PHASE6_HEAP_PROFILE"); path != "" {
					f, err := os.Create(path)
					if err != nil {
						b.Fatal(err)
					}
					if err := pprof.WriteHeapProfile(f); err != nil {
						b.Fatal(err)
					}
					if err := f.Close(); err != nil {
						b.Fatal(err)
					}
				}
				if err := q.Close(); err != nil {
					b.Fatal(err)
				}
				if err := ds.Close(); err != nil {
					b.Fatal(err)
				}
				if err := storage.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
