//go:build tui || all

package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

// BenchmarkOfflineAcceptance runs the completed-dataset acceptance endpoints.
// Use scripts/benchmark-offline-acceptance.py for fresh-process repetitions.
// Controlled density predicates exercise match representations separately;
// they do not claim representative user-filter selectivity on arbitrary traffic.
func BenchmarkOfflineAcceptance(b *testing.B) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		b.Skip("set LIPPYCAT_BENCH_PCAP to a local capture")
	}
	require.Equal(b, 1, b.N, "acceptance requires -benchtime=1x and fresh processes")
	ctx := context.Background()
	open := FreezeOfflineOpen([]string{path}, os.Getenv("LIPPYCAT_BENCH_BPF"), 10000)
	open.Limits.Directory = b.TempDir()
	backend := os.Getenv("LIPPYCAT_BENCH_BACKEND")
	switch backend {
	case "", "legacy":
	case "compact":
	default:
		b.Fatalf("unknown benchmark backend %q", backend)
	}
	b.Logf("backend=%s", backend)
	cfg, err := json.Marshal(map[string]any{"inputs": open.Config.Inputs, "bpf": open.Config.BPFFilter, "voip": open.Config.VoIP, "event_capacity": open.Config.EventCapacity, "max_calls": open.Config.MaxCalls, "esp_enabled": open.Config.ESP.Enabled, "tls_keylog_enabled": open.Config.TLSKeylog != "", "limits": open.Limits, "analysis_profile": open.Config.Analysis.AnalysisProfile, "sip_config": open.Config.SIPConfig})
	require.NoError(b, err)
	b.Logf("frozen_configuration=%s", cfg)
	b.Log("endpoints: completed base and application readiness coincide; render is PacketList.View at 120x40, excluding terminal I/O; cold cache, persistent reuse, and Wireshark comparison unavailable")
	storage, err := offline.NewStorage(open.Limits)
	require.NoError(b, err)
	defer func() { require.NoError(b, storage.Close()) }()
	metrics := make(map[string]float64)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	var peakDisk uint64
	session, err := indexOfflineDatasetBackend(ctx, storage, 1, open.Config, func(p offline.Progress) {
		peakDisk = max(peakDisk, p.DiskBytes)
	}, func(phase string, duration time.Duration) { metrics[phase+"-ns"] += float64(duration.Nanoseconds()) }, backend == "compact", backend == "compact")
	require.NoError(b, err)
	defer func() { require.NoError(b, session.Close()) }()
	metrics["full-ready-ns"] = float64(time.Since(started).Nanoseconds())
	ds := session.Dataset
	runtime.ReadMemStats(&after)
	metrics["readiness-allocated-B"] = float64(after.TotalAlloc - before.TotalAlloc)
	metrics["packets"] = float64(ds.Count())
	metrics["events-arrived"] = float64(session.EventStore.Stats().Arrived)
	metrics["completed-disk-B"] = float64(ds.Resources().DiskBytes)
	token := offline.Token{Dataset: ds.Generation(), Query: 1}
	q, err := offline.AllPackets(ctx, ds, token)
	require.NoError(b, err)
	defer func() { require.NoError(b, q.Close()) }()
	t := time.Now()
	page, err := q.Page(ctx, offline.PageRequest{Token: token, Limit: 64, MaxBytes: 8 << 20})
	require.NoError(b, err)
	metrics["first-page-ns"] = float64(time.Since(t).Nanoseconds())
	packets := make([]types.PacketDisplay, len(page.Rows))
	for i, row := range page.Rows {
		packets[i] = row.DisplayFields()
	}
	t = time.Now()
	list := components.NewPacketList()
	list.SetSize(120, 40)
	list.SetVirtualPackets(ds.Count(), 0, packets)
	require.NotEmpty(b, list.View(true, false))
	metrics["first-packet-list-render-ns"] = float64(time.Since(t).Nanoseconds())
	metrics["first-useful-page-from-open-ns"] = float64(time.Since(started).Nanoseconds())
	require.NoError(b, page.Close())
	for _, family := range []string{"controlled-density"} {
		for _, density := range []string{"sparse", "dense", "all"} {
			for repetition := 0; repetition < 2; repetition++ {
				token.Query++
				t = time.Now()
				query, err := ds.Query(ctx, offline.QuerySpec{Token: token, Match: func(s offline.Summary) bool {
					switch density {
					case "sparse":
						return uint64(s.ID)%1000 == 0
					case "dense":
						return uint64(s.ID)%10 != 0
					default:
						return true
					}
				}})
				require.NoError(b, err)
				label := fmt.Sprintf("%s-%s-%d", family, density, repetition+1)
				metrics[label+"-ns"] = float64(time.Since(t).Nanoseconds())
				metrics[label+"-matches"] = float64(query.Count())
				require.Equal(b, query.Count(), query.Statistics().Packets)
				expected := ds.Count()
				if density == "sparse" {
					expected = (ds.Count() + 999) / 1000
				}
				if density == "dense" {
					expected = ds.Count() - (ds.Count()+9)/10
				}
				require.Equal(b, expected, query.Count())
				peakDisk = max(peakDisk, storage.Resources().DiskBytes)
				metrics[label+"-query-disk-B"] = float64(storage.Resources().DiskBytes) - metrics["completed-disk-B"]
				if query.Count() > 0 {
					p, err := query.Page(ctx, offline.PageRequest{Token: token, Row: query.Count() / 2, Limit: 1, MaxBytes: 8 << 20})
					require.NoError(b, err)
					require.Len(b, p.Rows, 1)
					require.NoError(b, p.Close())
				}
				require.NoError(b, query.Close())
			}
		}
	}

	sourceText, protocolText := "192.0.2.1", "DNS"
	if len(packets) > 0 {
		sourceText, protocolText = packets[0].SrcIP, packets[0].Protocol
	}
	for _, workload := range []struct {
		name   string
		filter filters.Filter
	}{
		{"base-source", filters.NewTextFilter(sourceText, []string{"src"})},
		{"application-protocol", filters.NewTextFilter(protocolText, []string{"protocol"})},
		{"application-info", filters.NewTextFilter("query", []string{"info"})},
		{"application-http-metadata", filters.NewMetadataFilter("http")},
	} {
		b.Logf("filter %s: %s", workload.name, workload.filter.String())
		var firstCount uint64
		for repetition := 0; repetition < 2; repetition++ {
			token.Query++
			t = time.Now()
			spec := offline.QuerySpec{Token: token, Match: func(s offline.Summary) bool { return workload.filter.Match(s) }}
			if backend == "compact" {
				chain := filters.NewFilterChain()
				chain.Add(workload.filter)
				spec.Expression, err = chain.OfflineExpression()
				require.NoError(b, err)
				require.NotNil(b, spec.Expression, "acceptance workload must exercise structured expressions")
			}
			result, err := ds.Query(ctx, spec)
			require.NoError(b, err)
			metrics[fmt.Sprintf("%s-%d-ns", workload.name, repetition+1)] = float64(time.Since(t).Nanoseconds())
			metrics[workload.name+"-matches"] = float64(result.Count())
			require.Equal(b, result.Count(), result.Statistics().Packets)
			if repetition == 0 {
				firstCount = result.Count()
			} else {
				require.Equal(b, firstCount, result.Count())
			}
			peakDisk = max(peakDisk, storage.Resources().DiskBytes)
			require.NoError(b, result.Close())
		}
	}
	if ds.Count() > 0 {
		const samples = 32
		t = time.Now()
		var pageSamples, detailSamples []float64
		for i := 0; i < samples; i++ {
			sampleStart := time.Now()
			p, err := q.Page(ctx, offline.PageRequest{Token: q.Token(), Row: uint64(i*7919) % ds.Count(), Limit: 1, MaxBytes: 8 << 20})
			require.NoError(b, err)
			require.Len(b, p.Rows, 1)
			require.NoError(b, p.Close())
			pageSamples = append(pageSamples, float64(time.Since(sampleStart).Nanoseconds()))
		}
		metrics["random-page-mean-ns"] = float64(time.Since(t).Nanoseconds()) / samples
		t = time.Now()
		var related offline.Flow
		for i := 0; i < samples; i++ {
			sampleStart := time.Now()
			detail, err := ds.Detail(ctx, q.Token(), offline.PacketID(uint64(i*7919)%ds.Count()))
			require.NoError(b, err)
			detailSamples = append(detailSamples, float64(time.Since(sampleStart).Nanoseconds()))
			src, e1 := netip.ParseAddrPort(netipJoin(detail.Packet.SrcIP, detail.Packet.SrcPort))
			dst, e2 := netip.ParseAddrPort(netipJoin(detail.Packet.DstIP, detail.Packet.DstPort))
			if !related.Source.IsValid() && e1 == nil && e2 == nil {
				related = offline.Flow{Source: src, Destination: dst, Transport: detail.Packet.Transport, Node: detail.Packet.NodeID}
			}
		}
		metrics["random-detail-mean-ns"] = float64(time.Since(t).Nanoseconds()) / samples
		for name, values := range map[string][]float64{"random-page": pageSamples, "random-detail": detailSamples} {
			sort.Float64s(values)
			metrics[name+"-p50-ns"] = values[15]
			metrics[name+"-p95-ns"] = values[30]
		}
		for repetition := 0; repetition < 2; repetition++ {
			token.Query++
			t = time.Now()
			rq, err := ds.Related(ctx, token, related)
			require.NoError(b, err)
			metrics[fmt.Sprintf("related-%d-ns", repetition+1)] = float64(time.Since(t).Nanoseconds())
			metrics["related-matches"] = float64(rq.Count())
			require.Equal(b, rq.Count(), rq.Statistics().Packets)
			require.NoError(b, rq.Close())
		}
		if !related.Source.IsValid() {
			b.Log("related flow unavailable: invalid flow rejection measured")
		}
	}
	if ds.Count() > 0 {
		exportPath := open.Limits.Directory + "/acceptance-export.pcap"
		t = time.Now()
		count, err := exportOfflinePCAP(ctx, exportPath, func(ctx context.Context, visit func(offline.RawRecord) error) error {
			return offline.IterateRaw(ctx, q, visit)
		})
		require.NoError(b, err)
		require.Equal(b, ds.Count(), count)
		elapsed := time.Since(t)
		info, err := os.Stat(exportPath)
		require.NoError(b, err)
		metrics["export-ns"] = float64(elapsed.Nanoseconds())
		// Classic PCAP has one 24-byte header and a 16-byte header per
		// record. Check bounds before subtracting the framing overhead.
		require.GreaterOrEqual(b, info.Size(), int64(24))
		fileBytes := uint64(info.Size())
		require.LessOrEqual(b, count, (fileBytes-24)/16)
		effectiveBytes := fileBytes - 24 - count*16
		metrics["export-B/s"] = float64(effectiveBytes) / elapsed.Seconds()
		metrics["export-file-B/s"] = float64(fileBytes) / elapsed.Seconds()
		metrics["export-output-B"] = float64(info.Size())

	} else {
		b.Log("export unavailable: empty datasets have no effective link type")
	}
	var completedWithExport uint64
	require.NoError(b, filepath.WalkDir(open.Limits.Directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			completedWithExport += uint64(info.Size())
		}
		return nil
	}))
	metrics["accounted-peak-disk-B"] = float64(storage.Peaks().DiskBytes)
	metrics["accounted-peak-memory-B"] = float64(storage.Peaks().MemoryBytes)
	metrics["accounted-temporary-query-extra-B"] = float64(storage.Peaks().DiskBytes) - metrics["completed-disk-B"]
	metrics["sampled-combined-disk-lower-bound-B"] = float64(max(storage.Peaks().DiskBytes, completedWithExport))
	metrics["sampled-accounted-peak-disk-B"] = float64(peakDisk)
	metrics["sampled-temporary-query-extra-B"] = float64(peakDisk) - metrics["completed-disk-B"]
	runtime.ReadMemStats(&after)
	metrics["cumulative-allocated-B"] = float64(after.TotalAlloc - before.TotalAlloc)
	runtime.GC()
	runtime.ReadMemStats(&after)
	metrics["retained-heap-B"] = float64(after.HeapAlloc)
	resources := ds.Resources()
	metrics["accounted-memory-B"] = float64(resources.CachedBytes + resources.PinnedBytes + resources.PrefetchBytes + resources.InFlightBytes)
	for name, value := range metrics {
		b.ReportMetric(value, name)
	}
}

func netipJoin(address, port string) string {
	if addr, err := netip.ParseAddr(address); err == nil && addr.Is6() {
		return "[" + address + "]:" + port
	}
	return address + ":" + port
}

func TestOfflineAcceptancePhaseTimings(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	storage := testOfflineStorage(t)
	seen := make(map[string]time.Duration)
	session, err := indexOfflineDatasetObserved(context.Background(), storage, 1, FreezeOfflineOpen(paths, "", 8).Config, nil, func(name string, duration time.Duration) { seen[name] += duration })
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	for _, phase := range []string{"setup", "identity", "analysis_setup", "scan", "ordering", "analysis_and_storage", "finalization"} {
		require.Positive(t, seen[phase], phase)
	}
	require.Equal(t, uint64(1077), session.Dataset.Count())
}
