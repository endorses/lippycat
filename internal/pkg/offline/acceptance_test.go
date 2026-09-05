package offline_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// Exercise only the public API: no retained packet slice is used as a reference.
func TestCompleteDatasetBeyondDisplayRetention(t *testing.T) {
	ctx := context.Background()
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 128 << 20, CacheBytes: 2 << 20, MaxRecordBytes: 64 << 10, MaxSources: 1}
	storage, err := offline.NewStorage(limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := storage.Close(); err != nil {
			t.Error(err)
		}
	})
	source := offline.SourcePosition{Path: "/captures/full.pcap"}
	builder, err := storage.NewBuilder(11, []offline.SourcePosition{source})
	if err != nil {
		t.Fatal(err)
	}
	const count = 12017
	for i := 0; i < count; i++ {
		source.Sequence = uint64(i)
		p := types.PacketDisplay{Timestamp: time.Unix(int64(i), 123).UTC(), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "1234", DstPort: "53", Protocol: "UDP", Transport: 17, Length: 4, RawData: []byte{byte(i), byte(i >> 8), 2, 3}, Info: fmt.Sprint(i), LinkType: layers.LinkTypeRaw}
		if err := builder.Append(ctx, offline.Detail{ID: offline.PacketID(i), Source: source, CapturedLength: 4, OriginalLength: 4, Packet: p}); err != nil {
			t.Fatal(err)
		}
	}
	dataset, err := builder.Finish(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stats := dataset.Statistics()
	if dataset.Count() != count || stats.Packets != count || stats.Bytes != 4*count {
		t.Fatalf("incomplete totals: %+v", stats)
	}
	token := offline.Token{Dataset: 11, Query: 1, Request: 1}
	all, err := dataset.Query(ctx, offline.QuerySpec{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if all.Count() != count {
		t.Fatalf("all count %d", all.Count())
	}
	page, err := all.Page(ctx, offline.PageRequest{Token: token, Row: count - 2, Limit: 2, MaxBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.Rows[1].ID != count-1 {
		t.Fatalf("last page %+v", page)
	}
	if err := page.Close(); err != nil {
		t.Fatal(err)
	}
	if err := all.Close(); err != nil {
		t.Fatal(err)
	}
	token.Query++
	query, err := dataset.Query(ctx, offline.QuerySpec{Token: token, Match: func(s offline.Summary) bool { return s.ID == 0 || s.ID == count/2 || s.ID == count-1 }})
	if err != nil {
		t.Fatal(err)
	}
	if query.Count() != 3 || query.Statistics().Bytes != 12 {
		t.Fatalf("filtered stats %+v", query.Statistics())
	}
	seen := 0
	err = query.Iterate(ctx, func(d offline.Detail) error {
		expected := []offline.PacketID{0, count / 2, count - 1}[seen]
		if d.ID != expected || d.Packet.RawData[0] != byte(expected) || d.Source.Sequence != uint64(expected) || d.Packet.LinkType != layers.LinkTypeRaw || d.CapturedLength != 4 || d.OriginalLength != 4 || d.Source.Path != "/captures/full.pcap" {
			return fmt.Errorf("wrong detail at %d: %+v", seen, d)
		}
		seen++
		return nil
	})
	if err != nil || seen != 3 {
		t.Fatalf("iteration %d: %v", seen, err)
	}
	if err := query.Close(); err != nil {
		t.Fatal(err)
	}
	usage := dataset.Resources()
	if usage.CachedBytes+usage.PinnedBytes+usage.PrefetchBytes+usage.InFlightBytes > limits.CacheBytes {
		t.Fatalf("budget exceeded: %+v", usage)
	}
	if err := dataset.Close(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkCompleteDataset(b *testing.B) {
	for _, count := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				ctx := context.Background()
				storage, err := offline.NewStorage(offline.ResourceLimits{Directory: b.TempDir(), DiskBytes: 128 << 20, CacheBytes: 2 << 20, MaxRecordBytes: 64 << 10, MaxSources: 1})
				if err != nil {
					b.Fatal(err)
				}
				source := offline.SourcePosition{Path: "benchmark.pcap"}
				builder, err := storage.NewBuilder(1, []offline.SourcePosition{source})
				if err != nil {
					b.Fatal(err)
				}
				packet := types.PacketDisplay{Timestamp: time.Unix(0, 0).UTC(), Protocol: "UDP", Transport: 17, Length: 256, RawData: make([]byte, 256), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "1234", DstPort: "53"}
				for i := 0; i < count; i++ {
					source.Sequence = uint64(i)
					if err := builder.Append(ctx, offline.Detail{ID: offline.PacketID(i), Source: source, CapturedLength: 256, OriginalLength: 256, Packet: packet}); err != nil {
						b.Fatal(err)
					}
				}
				ds, err := builder.Finish(ctx)
				if err != nil {
					b.Fatal(err)
				}
				q, err := ds.Query(ctx, offline.QuerySpec{Token: offline.Token{Dataset: 1, Query: 1}})
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(ds.Resources().DiskBytes)/float64(count), "disk-B/packet")
				runtime.GC()
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				b.ReportMetric(float64(memory.HeapAlloc), "live-heap-B")
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
