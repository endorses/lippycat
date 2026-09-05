//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// writePhase6MixedSources streams interleaved DNS and ordinary UDP packets over
// two fixed flows. Source timestamps are individually monotonic. No packet-count
// sized fixture slice is retained. Optional directory permits terminal smoke reuse.
func writePhase6MixedSources(b *testing.B, dir string, count, sources int) []string {
	b.Helper()
	frames := [][]byte{benchmarkDNSReplayFrame(b, 10000), benchmarkDNSReplayFrame(b, 10001)}
	// Change the second destination port to an unrecognized application port.
	packet := gopacket.NewPacket(frames[1], layers.LayerTypeEthernet, gopacket.Default)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	udp.DstPort = 40000
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		b.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("phase-six-ordinary-udp-payload"))); err != nil {
		b.Fatal(err)
	}
	frames[1] = buffer.Bytes()
	paths := make([]string, sources)
	for source := 0; source < sources; source++ {
		paths[source] = filepath.Join(dir, fmt.Sprintf("mixed-%d.pcap", source))
		f, err := os.Create(paths[source])
		if err != nil {
			b.Fatal(err)
		}
		writer := pcapgo.NewWriter(f)
		if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			b.Fatal(err)
		}
		for i := source; i < count; i += sources {
			frame := frames[i%2]
			if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
				b.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			b.Fatal(err)
		}
	}
	return paths
}

func BenchmarkPhase6OfflineIndex(b *testing.B) {
	for _, count := range []int{100000, 1000000} {
		for _, sources := range []int{1, 8} {
			b.Run(fmt.Sprintf("packets_%d/sources_%d", count, sources), func(b *testing.B) {
				b.StopTimer()
				dir := b.TempDir()
				if configured := os.Getenv("LIPPYCAT_PHASE6_FIXTURE_DIR"); configured != "" {
					dir = configured
				}
				paths := writePhase6MixedSources(b, dir, count, sources)
				var sourceBytes int64
				for _, path := range paths {
					info, err := os.Stat(path)
					if err != nil {
						b.Fatal(err)
					}
					sourceBytes += info.Size()
				}
				b.StartTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					storage, err := offline.NewStorage(offline.ResourceLimits{Directory: b.TempDir(), DiskBytes: 4 << 30, CacheBytes: 2 << 20, MaxRecordBytes: 64 << 10, MaxSources: 8})
					if err != nil {
						b.Fatal(err)
					}
					start := time.Now()
					var peakHeap uint64
					sampleHeap := func(offline.Progress) {
						var memory runtime.MemStats
						runtime.ReadMemStats(&memory)
						if memory.HeapAlloc > peakHeap {
							peakHeap = memory.HeapAlloc
						}
					}
					session, err := indexOfflineDataset(context.Background(), storage, 1, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 10000, MaxCalls: 1000}, sampleHeap)
					if err != nil {
						b.Fatal(err)
					}
					b.ReportMetric(float64(count)/time.Since(start).Seconds(), "index-packets/s")
					if session.Dataset.Count() != uint64(count) {
						b.Fatal("incomplete indexed dataset")
					}
					stats := session.Dataset.Statistics()
					if len(stats.Protocols) < 2 {
						b.Fatalf("fixture not mixed: %+v", stats.Protocols)
					}
					b.ReportMetric(float64(session.Dataset.Resources().DiskBytes)/float64(sourceBytes), "disk/pcap-ratio")
					b.ReportMetric(float64(len(session.EventStore.Events())), "retained-events")
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
					if err := session.Close(); err != nil {
						b.Fatal(err)
					}
					cancelCtx, cancel := context.WithCancel(context.Background())
					var cancelledAt time.Time
					candidate, cancelErr := indexOfflineDataset(cancelCtx, storage, 2, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 10000, MaxCalls: 1000}, func(progress offline.Progress) {
						if progress.LogicalPackets >= 1024 && cancelledAt.IsZero() {
							cancelledAt = time.Now()
							cancel()
						}
					})
					cancel()
					if !errors.Is(cancelErr, context.Canceled) || candidate != nil || cancelledAt.IsZero() {
						b.Fatalf("index cancellation: candidate=%v err=%v", candidate, cancelErr)
					}
					b.ReportMetric(float64(time.Since(cancelledAt).Nanoseconds()), "index-cancel-cleanup-ns")
					if storage.Resources().DiskBytes != 0 {
						b.Fatal("cancelled index retained disk")
					}
					if err := storage.Close(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
