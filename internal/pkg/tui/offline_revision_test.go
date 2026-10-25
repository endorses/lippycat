//go:build tui || all

package tui

import (
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/stretchr/testify/require"
)

func TestOfflineProgressiveBaseAndCompletedParity(t *testing.T) {
	ctx := context.Background()
	paths := append(writeOrderedBridgeFixtures(t), writeCompactProtocolFixture(t))
	paths = append(paths, writeLocatorSIPFixtures(t, "external")...)
	storage := testOfflineStorage(t)
	cfg := OfflineAnalysisConfig{Inputs: paths, VoIP: true, EventCapacity: 8, SIPConfig: *voip.GetConfig()}
	var base *offlineIndexedSession
	var baseReady, completedReady bool
	owner, completed, err := indexOfflineProgressiveDataset(ctx, storage, 501, cfg, func(p offline.Progress) {
		if p.State == offline.Ready {
			switch p.Token.Revision {
			case offline.BaseRevision:
				baseReady = true
			case offline.CompletedRevision:
				require.NotNil(t, base, "analysis cannot publish before base ownership transfer")
				completedReady = true
			}
		}
	}, func(s *offlineIndexedSession) error {
		base = s
		require.True(t, baseReady)
		require.False(t, completedReady)
		require.Equal(t, offline.BaseRevision, s.Dataset.Revision())
		require.EqualValues(t, 1086, s.Dataset.Count())
		require.Nil(t, s.EventDataset)
		require.Zero(t, s.EventStore.Stats().Arrived)
		require.Empty(t, s.Calls)
		require.Nil(t, s.TLSDecryptor)
		// Whole-file navigation and effective raw-byte access are usable before
		// any application metadata, call state, or EOF event has been built.
		query, err := offline.AllPackets(ctx, s.Dataset, offline.Token{Dataset: 501, Revision: offline.BaseRevision})
		require.NoError(t, err)
		require.Equal(t, s.Dataset.Count(), query.Count())
		require.NoError(t, query.Iterate(ctx, func(detail offline.Detail) error {
			require.Empty(t, detail.Packet.Protocol)
			require.Empty(t, detail.Packet.Info)
			require.Nil(t, detail.Packet.DNSData)
			require.Nil(t, detail.Packet.VoIPData)
			require.Nil(t, detail.Packet.TLSData)
			require.Nil(t, detail.Packet.HTTPData)
			require.Nil(t, detail.Packet.EmailData)
			require.Nil(t, detail.Packet.RADIUSData)
			require.Zero(t, detail.Packet.CaptureID)
			require.NotEmpty(t, detail.Packet.RawData)
			return nil
		}))
		require.NoError(t, query.Close())
		return nil
	})
	require.NoError(t, err)
	require.Same(t, base, owner)
	defer func() { require.NoError(t, owner.Close()) }()
	require.True(t, completedReady)
	require.Equal(t, offline.BaseRevision, owner.Dataset.Revision(), "published base remains immutable")
	require.Nil(t, owner.EventDataset)
	require.Zero(t, owner.EventStore.Stats().Arrived)
	require.Equal(t, offline.CompletedRevision, completed.Revision)
	require.NotSame(t, owner.Dataset, completed.Dataset)
	require.NotSame(t, owner.EventStore, completed.EventStore)
	require.NotSame(t, owner.Tracker, completed.Tracker)
	require.Equal(t, owner.Dataset.Count(), completed.Dataset.Count())
	require.Equal(t, uint64(1086), completed.AnalysisStats.Observed)
	require.Positive(t, completed.EventDataset.Count())
	require.LessOrEqual(t, len(completed.EventStore.Events()), 8)
	select {
	case <-owner.AnalysisDone():
	default:
		t.Fatal("analysis returned without joining workers")
	}
	baseline, err := indexOfflineDataset(ctx, storage, 502, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, baseline.Close()) }()
	for id := offline.PacketID(0); uint64(id) < owner.Dataset.Count(); id++ {
		b, err := owner.Dataset.Detail(ctx, offline.Token{Dataset: 501, Revision: offline.BaseRevision}, id)
		require.NoError(t, err)
		a, err := completed.Dataset.Detail(ctx, offline.Token{Dataset: 501, Revision: offline.CompletedRevision}, id)
		require.NoError(t, err)
		want, err := baseline.Dataset.Detail(ctx, offline.Token{Dataset: 502, Revision: offline.CompletedRevision}, id)
		require.NoError(t, err)
		require.NoError(t, offlineOracleRecord(want, a))
		require.NoError(t, offlineOracleMetadata(want, a))
		require.Equal(t, b.Source, a.Source)
		require.Equal(t, b.ID, a.ID)
		require.Equal(t, baseProjection(a.Packet), b.Packet)
	}
	// Delivery identities and EOF rows retain their arrival order across the
	// independent analysis build. Random flow UIDs use the existing bijection.
	want, err := offline.AllEvents(ctx, baseline.EventDataset, offline.Token{Dataset: 502, Revision: offline.CompletedRevision})
	require.NoError(t, err)
	defer func() { require.NoError(t, want.Close()) }()
	got, err := offline.AllEvents(ctx, completed.EventDataset, offline.Token{Dataset: 501, Revision: offline.CompletedRevision})
	require.NoError(t, err)
	defer func() { require.NoError(t, got.Close()) }()
	require.Equal(t, want.Count(), got.Count())
	uids := offlineOracleUIDs{forward: map[string]string{}, reverse: map[string]string{}}
	require.NoError(t, want.Iterate(ctx, func(record offline.EventRecord) error {
		detail, err := completed.EventDataset.Detail(ctx, offline.Token{Dataset: 501, Revision: offline.CompletedRevision}, record.ID)
		if err != nil {
			return err
		}
		return errors.Join(uids.compare(record.Event, detail.Record.Event), detail.Close())
	}))
	// The retained ring is independently bounded; compare its exact delivery
	// identity without relying on capture-global random flow IDs.
	we, ge := baseline.EventStore.Events(), completed.EventStore.Events()
	require.Len(t, ge, len(we))
	for i := range we {
		require.Equal(t, we[i].Event.Kind(), ge[i].Event.Kind())
		require.Equal(t, we[i].Event.Envelope().EventID, ge[i].Event.Envelope().EventID)
		require.Equal(t, we[i].Event.Envelope().EventSequence, ge[i].Event.Envelope().EventSequence)
	}
}

func baseProjection(packet types.PacketDisplay) types.PacketDisplay {
	packet.Protocol, packet.Info = "", ""
	packet.VoIPData, packet.DNSData, packet.TLSData = nil, nil, nil
	packet.HTTPData, packet.EmailData, packet.RADIUSData = nil, nil, nil
	return packet
}

func TestOfflineProgressiveFailureOrCancelPreservesBase(t *testing.T) {
	for _, mode := range []string{"analysis-error", "base-cancel", "analysis-cancel", "callback-error"} {
		t.Run(mode, func(t *testing.T) {
			storage := testOfflineStorage(t)
			cfg := OfflineAnalysisConfig{Inputs: []string{writeOfflineEventFlows(t, 32)}, EventCapacity: 1}
			if mode == "analysis-error" {
				cfg.TLSKeylog = filepath.Join(t.TempDir(), "missing.keys")
			}
			var published *offlineIndexedSession
			var completedReady bool
			callbackErr := errors.New("base consumer rejected publication")
			session, snapshot, err := indexOfflineProgressiveDataset(context.Background(), storage, 503, cfg, func(p offline.Progress) {
				if p.Token.Revision == offline.CompletedRevision {
					completedReady = completedReady || p.State == offline.Ready
					if mode == "analysis-cancel" && p.State == offline.Indexing {
						published.CancelAnalysis()
					}
				}
			}, func(s *offlineIndexedSession) error {
				published = s
				if mode == "base-cancel" {
					s.CancelAnalysis()
				}
				if mode == "callback-error" {
					return callbackErr
				}
				return nil
			})
			require.Error(t, err)
			if mode == "base-cancel" || mode == "analysis-cancel" {
				require.ErrorIs(t, err, context.Canceled)
			}
			if mode == "callback-error" {
				require.ErrorIs(t, err, callbackErr)
			}
			require.Same(t, published, session)
			require.Nil(t, snapshot)
			require.False(t, completedReady)
			require.EqualValues(t, 32, session.Dataset.Count())
			detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 503, Revision: offline.BaseRevision}, 31)
			require.NoError(t, err)
			require.NotEmpty(t, detail.Packet.RawData)
			require.Empty(t, detail.Packet.Protocol)
			require.Zero(t, session.EventStore.Stats().Arrived)
			require.NoError(t, session.Close())
			require.NoError(t, session.Close())
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}

func TestOfflineProgressiveCloseJoinsCancelledAnalysis(t *testing.T) {
	storage := testOfflineStorage(t)
	path := writeOfflineEventFlows(t, 8)
	ready := make(chan *offlineIndexedSession, 1)
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, _, err := indexOfflineProgressiveDataset(context.Background(), storage, 504, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1}, nil, func(s *offlineIndexedSession) error {
			ready <- s
			<-release
			return nil
		})
		result <- err
	}()
	var session *offlineIndexedSession
	select {
	case session = <-ready:
	case err := <-result:
		t.Fatalf("indexing failed before base: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("base publication did not finish")
	}
	cancelled := make(chan struct{})
	require.NoError(t, session.registerViewCloser(offlineEventCloserFunc(func() error { return nil }), func() { close(cancelled) }))
	closed := make(chan error, 2)
	go func() { closed <- session.Close() }()
	<-cancelled // Close requests cancellation before waiting on the analysis callback.
	go func() { closed <- session.Close() }()
	select {
	case <-closed:
		t.Fatal("session closed while analysis still owned replay")
	default:
	}
	close(release)
	require.ErrorIs(t, <-result, context.Canceled)
	require.NoError(t, <-closed)
	require.NoError(t, <-closed)
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineSessionCancelsAllOwnersBeforeJoiningAndRetries(t *testing.T) {
	session := &offlineIndexedSession{}
	var mu sync.Mutex
	cancelled := make(map[int]bool)
	closeCalls := 0
	for i := 0; i < 2; i++ {
		i := i
		require.NoError(t, session.registerViewCloser(offlineEventCloserFunc(func() error {
			mu.Lock()
			defer mu.Unlock()
			require.True(t, cancelled[0])
			require.True(t, cancelled[1])
			closeCalls++
			if i == 0 && closeCalls == 1 {
				return errors.New("retryable close")
			}
			return nil
		}), func() { mu.Lock(); cancelled[i] = true; mu.Unlock() }))
	}
	require.ErrorContains(t, session.Close(), "retryable close")
	require.Error(t, session.registerViewCloser(offlineEventCloserFunc(func() error { t.Error("rejected ownership was closed"); return nil }), nil))
	require.NoError(t, session.Close())
	require.Equal(t, 3, closeCalls, "only the failed owner is retained for cleanup retry")
}

func TestOfflineProgressiveReadinessAndAbandonedCompletedOwnership(t *testing.T) {
	storage := testOfflineStorage(t)
	path := writeOfflineEventFlows(t, 513)
	started := time.Now()
	var baseElapsed, usefulElapsed, queryElapsed, pageElapsed, renderElapsed time.Duration
	session, snapshot, err := indexOfflineProgressiveDataset(context.Background(), storage, 505, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1}, nil, func(s *offlineIndexedSession) error {
		baseElapsed = time.Since(started)
		require.EqualValues(t, 513, s.Dataset.Count())
		token := offline.Token{Dataset: 505, Revision: offline.BaseRevision, Query: 1}
		step := time.Now()
		query, err := offline.AllPackets(context.Background(), s.Dataset, token)
		require.NoError(t, err)
		queryElapsed = time.Since(step)
		step = time.Now()
		page, err := query.Page(context.Background(), offline.PageRequest{Token: token, Limit: 64, MaxBytes: 8 << 20})
		require.NoError(t, err)
		pageElapsed = time.Since(step)
		packets := make([]types.PacketDisplay, len(page.Rows))
		for i, row := range page.Rows {
			packets[i] = row.DisplayFields()
			packets[i].CaptureID = uint64(row.ID) + 1
		}
		step = time.Now()
		list := components.NewPacketList()
		list.SetSize(120, 40)
		list.SetAnalysisPending(true)
		list.SetVirtualPackets(query.Count(), 0, packets)
		require.NotEmpty(t, list.View(true, false))
		renderElapsed = time.Since(step)
		usefulElapsed = time.Since(started)
		require.NoError(t, page.Close())
		require.NoError(t, query.Close())
		return nil
	})
	completedElapsed := time.Since(started)
	require.NoError(t, err)
	require.EqualValues(t, 513, snapshot.EventDataset.Count(), "all connection events released at EOF are persisted")
	var delivered int
	q, err := offline.AllEvents(context.Background(), snapshot.EventDataset, offline.Token{Dataset: 505, Revision: offline.CompletedRevision})
	require.NoError(t, err)
	require.NoError(t, q.Iterate(context.Background(), func(r offline.EventRecord) error {
		_, ok := r.Event.(events.ConnEvent)
		require.True(t, ok)
		delivered++
		return nil
	}))
	require.Equal(t, 513, delivered)
	require.NoError(t, q.Close())
	t.Logf("readiness observation: fixture=513-generated-UDP-flows sources=1 base=%s first_useful_page=%s completed=%s base_query=%s base_page_64=%s PacketList_120x40_render=%s disk=%d peak_disk=%d peak_memory=%d", baseElapsed, usefulElapsed, completedElapsed, queryElapsed, pageElapsed, renderElapsed, storage.Resources().DiskBytes, storage.Peaks().DiskBytes, storage.Peaks().MemoryBytes)
	t.Logf("measurement scope: PacketList.View at 120x40; excludes terminal I/O and Tea event-loop delivery; first page measured synchronously in base callback before analysis; generated sources freshly written (OS cache warm/uncontrolled); no persistent index reuse; limits disk=64MiB cache=16MiB max_record=1MiB sources=64; EventCapacity=1; backing=source; no BPF/VoIP/TLS-keylog; host=%s/%s CPUs=%d GOMAXPROCS=%d Go=%s GOCACHE=%s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), runtime.Version(), os.Getenv("GOCACHE"))
	if os.Getenv("LIPPYCAT_BENCH_PCAP") == "" {
		t.Log("private representative fixture unavailable: LIPPYCAT_BENCH_PCAP is unset")
	}
	// The UI may discard the completion message. Closing the original base
	// session still disposes the completed metadata, events, and shared bytes.
	require.NoError(t, session.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineProgressiveCandidateQuotaFailurePreservesBase(t *testing.T) {
	path := writeOfflineEventFlows(t, 513)
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 64 << 20, CacheBytes: 4 << 20, MaxRecordBytes: 8 << 10, MaxSources: 1}
	storage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	cfg := OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1}
	var baseDisk uint64
	baseline, _, err := indexOfflineProgressiveDataset(context.Background(), storage, 506, cfg, nil, func(s *offlineIndexedSession) error {
		baseDisk = storage.Peaks().DiskBytes
		s.CancelAnalysis()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, baseline.Close())
	require.NoError(t, storage.Close())
	// Both complete base metadata and the ordering stream fit. The independent
	// analysis revision must respect that same configured disk quota and fail
	// without changing or removing the published base.
	limits.Directory, limits.DiskBytes = t.TempDir(), baseDisk
	limited, err := offline.NewStorage(limits)
	require.NoError(t, err)
	defer func() { require.NoError(t, limited.Close()) }()
	var base *offlineIndexedSession
	session, completed, err := indexOfflineProgressiveDataset(context.Background(), limited, 507, cfg, nil, func(s *offlineIndexedSession) error { base = s; return nil })
	require.NotNil(t, session)
	defer func() { require.NoError(t, session.Close()) }()
	require.ErrorContains(t, err, "disk budget exhausted")
	require.Same(t, base, session)
	require.Nil(t, completed)
	detail, err := base.Dataset.Detail(context.Background(), offline.Token{Dataset: 507, Revision: offline.BaseRevision}, 512)
	require.NoError(t, err)
	require.NotEmpty(t, detail.Packet.RawData)
	require.EqualValues(t, 513, base.Dataset.Count())
	require.NoError(t, session.Close())
	require.Zero(t, limited.Resources().DiskBytes)
	require.Zero(t, limited.Resources().InFlightBytes)
}

func TestOfflineProgressiveReusesFrozenBackingsAndEmptyEOF(t *testing.T) {
	for _, mode := range []string{"source-replaced", "snapshot-removed", "gzip-removed", "empty", "bpf-empty"} {
		t.Run(mode, func(t *testing.T) {
			path := writeCompactProtocolFixture(t)
			cfg := OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1}
			want := uint64(5)
			switch mode {
			case "snapshot-removed":
				cfg.BackingPolicy = offline.BackingSnapshot
			case "gzip-removed":
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				f, err := os.Create(path + ".gz")
				require.NoError(t, err)
				w := gzip.NewWriter(f)
				_, err = w.Write(data)
				require.NoError(t, err)
				require.NoError(t, w.Close())
				require.NoError(t, f.Close())
				path += ".gz"
				cfg.Inputs = []string{path}
			case "empty":
				require.NoError(t, os.Truncate(path, 24))
				want = 0
			case "bpf-empty":
				cfg.BPFFilter = "host 192.0.2.254"
				want = 0
			}
			storage := testOfflineStorage(t)
			session, completed, err := indexOfflineProgressiveDataset(context.Background(), storage, 508, cfg, nil, func(s *offlineIndexedSession) error {
				require.Equal(t, want, s.Dataset.Count())
				switch mode {
				case "source-replaced":
					require.NoError(t, os.Rename(path, path+".original"))
					require.NoError(t, os.WriteFile(path, []byte("replacement is not a capture"), 0600))
				case "snapshot-removed", "gzip-removed":
					require.NoError(t, os.Remove(path))
				}
				return nil
			})
			require.NotNil(t, session)
			defer func() { require.NoError(t, session.Close()) }()
			require.NoError(t, err)
			require.Equal(t, want, completed.Dataset.Count())
			if want == 0 {
				require.Zero(t, completed.EventDataset.Count())
				require.Empty(t, completed.Calls)
			} else {
				a, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 508, Revision: offline.BaseRevision}, 0)
				require.NoError(t, err)
				b, err := completed.Dataset.Detail(context.Background(), offline.Token{Dataset: 508, Revision: offline.CompletedRevision}, 0)
				require.NoError(t, err)
				require.Equal(t, a.Packet.RawData, b.Packet.RawData)
				require.NotNil(t, b.Packet.DNSData)
			}
			require.NoError(t, session.Close())
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}
