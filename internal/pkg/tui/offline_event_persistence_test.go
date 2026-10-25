//go:build tui || all

package tui

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func writeOfflineEventFlows(t *testing.T, count int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event-history.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriterNanos(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i := 0; i < count; i++ {
		raw := goldenUDPPacket(t, layers.UDPPort(20000+i), 32001, []byte("offline EOF event"))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	require.NoError(t, f.Close())
	return path
}

func TestOfflineIndexerPublishesCompleteEventHistoryBeyondRing(t *testing.T) {
	const count = 2049
	path := writeOfflineEventFlows(t, count)
	storage := testOfflineStorage(t)
	cfg := OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 8}
	session, err := indexOfflineDataset(context.Background(), storage, 71, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	require.NotNil(t, session.EventDataset)
	require.EqualValues(t, count, session.Dataset.Count())
	require.EqualValues(t, count, session.EventDataset.Count())
	require.EqualValues(t, 8, session.EventStore.Stats().Retained)
	require.EqualValues(t, count-8, session.EventStore.Stats().Evicted)
	require.Zero(t, session.EventStore.Stats().TransportLost)
	oldest, err := session.EventDataset.Detail(context.Background(), offline.Token{Revision: offline.CompletedRevision, Dataset: 71}, 1)
	require.NoError(t, err)
	oldestEvent := oldest.Record.Event
	require.NoError(t, oldest.Close())
	for _, retained := range session.EventStore.Events() {
		require.NotEqual(t, oldestEvent.Envelope().EventID, retained.Event.Envelope().EventID)
	}
	predicate, err := eventquery.Compile("event_sequence:=" + strconv.FormatUint(oldestEvent.Envelope().EventSequence, 10))
	require.NoError(t, err)
	query, err := session.EventDataset.Query(context.Background(), offline.EventQuerySpec{Token: offline.Token{Revision: offline.CompletedRevision, Dataset: 71, Query: 2}, Match: predicate})
	require.NoError(t, err)
	require.EqualValues(t, 1, query.Count())
	page, err := query.Page(context.Background(), offline.PageRequest{Token: query.Token(), Limit: 1, MaxBytes: 16 << 10})
	require.NoError(t, err)
	require.Len(t, page.Rows, 1)
	require.Equal(t, oldestEvent, page.Rows[0].Event)
	require.NoError(t, page.Close())
	require.NoError(t, query.Close())
	// Compare with completed legacy analysis at a capacity large enough to
	// retain its entire result, including the producer-assigned identities.
	cfg.EventCapacity = count + 1
	baseline, err := indexOfflineLegacyDataset(context.Background(), storage, 72, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, baseline.Close()) }()
	want := baseline.EventStore.Events()
	require.Len(t, want, count)
	all, err := offline.AllEvents(context.Background(), session.EventDataset, offline.Token{Revision: offline.CompletedRevision, Dataset: 71, Query: 3})
	require.NoError(t, err)
	defer func() { require.NoError(t, all.Close()) }()
	uids := offlineOracleUIDs{forward: map[string]string{}, reverse: map[string]string{}}
	var i int
	require.NoError(t, all.Iterate(context.Background(), func(record offline.EventRecord) error {
		if record.ID != offline.EventRowID(i+1) {
			return fmt.Errorf("event row %d has arrival ID %d", i, record.ID)
		}
		// Delivery identity and metadata are exact. The established oracle
		// compares random flow UIDs by bijection; protobuf timestamps preserve
		// the capture instant in UTC rather than time.Local's location pointer.
		expected := want[i].Event.(events.ConnEvent)
		expected.EventEnvelope.Timestamp = expected.EventEnvelope.Timestamp.UTC()
		if err := uids.compare(expected, record.Event); err != nil {
			return err
		}
		i++
		return nil
	}))
	require.Equal(t, count, i)
	require.NoError(t, all.Close())
	for _, id := range []offline.PacketID{0, count - 1} {
		want, err := baseline.Dataset.Detail(context.Background(), offline.Token{Revision: offline.CompletedRevision, Dataset: 72}, id)
		require.NoError(t, err)
		got, err := session.Dataset.Detail(context.Background(), offline.Token{Revision: offline.CompletedRevision, Dataset: 71}, id)
		require.NoError(t, err)
		require.NoError(t, offlineOracleRecord(want, got))
	}
}

func TestOfflineIndexerPersistsCanonicalECHAndDNSNotice(t *testing.T) {
	hello := goldenTLSClientHello()
	// This controlled ClientHello has an empty session ID and one cipher;
	// its extension vector starts at byte 50, after record/handshake headers.
	extensionLength := binary.BigEndian.Uint16(hello[50:52])
	hello = append(hello, 0xfe, 0x0d, 0, 3, 0, 1, 2)
	binary.BigEndian.PutUint16(hello[50:52], extensionLength+7)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	size := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(size>>16), byte(size>>8), byte(size)
	eth, ip := goldenEthernetIPv4(layers.IPProtocolTCP)
	syn := &layers.TCP{SrcPort: 49154, DstPort: 443, Seq: 1000, SYN: true}
	require.NoError(t, syn.SetNetworkLayerForChecksum(ip))
	data := &layers.TCP{SrcPort: 49154, DstPort: 443, Seq: 1001, ACK: true, PSH: true}
	require.NoError(t, data.SetNetworkLayerForChecksum(ip))
	records := [][]byte{goldenSerialize(t, eth, ip, syn), goldenSerialize(t, eth, ip, data, gopacket.Payload(hello)), goldenDNSPacket(t), goldenDNSPacket(t)}
	path := filepath.Join(t.TempDir(), "ech-notice.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriterNanos(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, raw := range records {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	require.NoError(t, f.Close())
	policy := eventconfig.Default()
	dns := policy.EffectiveDNS()
	dns.DetectTunneling, dns.Threshold, dns.Debounce = true, 0, time.Minute
	policy.DNS = &dns
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 80, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1, Analysis: LocalEventAnalysisOptions{Policy: &policy}}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	query, err := offline.AllEvents(context.Background(), session.EventDataset, offline.Token{Revision: offline.CompletedRevision, Dataset: 80, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	var hellos, offered uint64
	var notices, observations int
	require.NoError(t, query.Iterate(context.Background(), func(record offline.EventRecord) error {
		require.True(t, events.HasValidDeliveryIdentity(record.Event.Envelope()))
		switch e := record.Event.(type) {
		case events.TLSEvent:
			hellos, offered = hellos+e.ClientHelloCount, offered+e.ECHOfferedCount
		case events.DNSEvent:
			observations++
		case events.NoticeEvent:
			notices++
			require.Equal(t, "example.test", e.DNS.Domain)
			require.EqualValues(t, 1, e.DNS.Queries)
			require.Equal(t, "watch-local", e.DetectorNodeID)
			require.NotEmpty(t, e.DetectorGeneration)
		}
		return nil
	}))
	require.EqualValues(t, 1, hellos)
	require.EqualValues(t, 1, offered)
	require.Equal(t, 2, observations)
	require.Equal(t, 1, notices, "capture-clock debounce survives persistence")
	require.Greater(t, session.EventDataset.Count(), session.EventStore.Stats().Retained)
}

func TestOfflineIndexerEventQuotaFailureNeverPublishesReady(t *testing.T) {
	path := writeOfflineEventFlows(t, 513)
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 8 << 20, CacheBytes: 4 << 20, MaxRecordBytes: 8 << 10, MaxSources: 1}
	baselineStorage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	var beforeEOF uint64
	cfg := OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 1}
	baseline, err := indexOfflineDataset(context.Background(), baselineStorage, 90, cfg, func(p offline.Progress) {
		if p.State == offline.Finalizing {
			beforeEOF = baselineStorage.Peaks().DiskBytes
		}
	})
	require.NoError(t, err)
	require.Greater(t, beforeEOF, limits.MaxRecordBytes)
	require.NoError(t, baseline.Close())
	require.NoError(t, baselineStorage.Close())
	// The complete packet streams already fit at Finalizing. Restrict the
	// remainder so the ensuing EOF connection history fails its append budget.
	limits.Directory, limits.DiskBytes = t.TempDir(), beforeEOF+limits.MaxRecordBytes
	storage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	defer func() { require.NoError(t, storage.Close()) }()
	var ready, finalizing bool
	session, err := indexOfflineDataset(context.Background(), storage, 91, cfg, func(p offline.Progress) {
		ready = ready || p.State == offline.Ready
		finalizing = finalizing || p.State == offline.Finalizing
	})
	require.ErrorContains(t, err, "persist offline event history")
	require.ErrorContains(t, err, "disk budget exhausted")
	require.True(t, finalizing)
	require.False(t, ready)
	require.Nil(t, session)
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineIndexerEventCancellationRetainsCleanupOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires directory permissions to prevent removal")
	}
	directory := t.TempDir()
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: directory, DiskBytes: 64 << 20, CacheBytes: 16 << 20, MaxRecordBytes: 1 << 20, MaxSources: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, storage.Close()) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var eventDirectory string
	var ready bool
	session, err := indexOfflineDataset(ctx, storage, 92, OfflineAnalysisConfig{Inputs: []string{writeOfflineEventFlows(t, 10)}, EventCapacity: 1}, func(p offline.Progress) {
		ready = ready || p.State == offline.Ready
		if eventDirectory != "" {
			return
		}
		entries, err := os.ReadDir(directory)
		require.NoError(t, err)
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "lippycat-events-") {
				eventDirectory = filepath.Join(directory, entry.Name())
				require.NoError(t, os.Chmod(eventDirectory, 0500))
				cancel()
				return
			}
		}
	})
	require.NotEmpty(t, eventDirectory)
	require.NoError(t, os.Chmod(eventDirectory, 0700))
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "remove private offline event session")
	require.False(t, ready)
	require.NotNil(t, session)
	require.Nil(t, session.Dataset)
	require.Nil(t, session.EventDataset)
	require.NotNil(t, session.eventBuilder)
	require.Positive(t, storage.Resources().DiskBytes)
	require.NoError(t, session.Close())
	require.NoError(t, session.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

type offlineEventCloserFunc func() error

func (f offlineEventCloserFunc) Close() error { return f() }

func TestOfflineSessionJoinsEventOwnersBeforeStorageAndRetriesFailure(t *testing.T) {
	storage := testOfflineStorage(t)
	builder, err := storage.NewEventBuilder(100)
	require.NoError(t, err)
	require.NoError(t, builder.Append(context.Background(), offlineSinkMetadataKinds()[0]))
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	query, err := offline.AllEvents(context.Background(), dataset, offline.Token{Revision: offline.CompletedRevision, Dataset: 100, Query: 1})
	require.NoError(t, err)
	pin, err := offline.PinEventQuery(query)
	require.NoError(t, err)
	session := &offlineIndexedSession{EventDataset: dataset}
	closeErr := errors.New("reader could not close")
	attempts := 0
	require.NoError(t, session.registerEventCloser(offlineEventCloserFunc(func() error {
		attempts++
		if attempts == 1 {
			return closeErr
		}
		return errors.Join(pin.Close(), query.Close())
	})))
	finished := make(chan error, 1)
	go func() { finished <- session.Close() }()
	select {
	case err := <-finished:
		require.ErrorIs(t, err, closeErr)
	case <-time.After(2 * time.Second):
		t.Fatal("failed reader close blocked behind its own retained pin")
	}
	require.Positive(t, storage.Resources().DiskBytes)
	page, err := pin.Page(context.Background(), offline.PageRequest{Token: query.Token(), Limit: 1, MaxBytes: 16 << 10})
	require.NoError(t, err)
	require.Len(t, page.Rows, 1)
	require.NoError(t, page.Close())
	require.Error(t, session.registerEventCloser(offlineEventCloserFunc(func() error { t.Error("rejected closer ownership transferred"); return nil })))
	require.NoError(t, session.Close())
	require.NoError(t, session.Close())
	require.Equal(t, 2, attempts)
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineSessionConcurrentEventOwnerRegistrationAndClose(t *testing.T) {
	session := &offlineIndexedSession{}
	var closed atomic.Uint64
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			closer := offlineEventCloserFunc(func() error { closed.Add(1); return nil })
			if err := session.registerEventCloser(closer); err != nil {
				require.NoError(t, closer.Close(), "rejected registration retains caller ownership")
			}
		}()
	}
	require.NoError(t, session.Close())
	workers.Wait()
	require.NoError(t, session.Close())
	require.EqualValues(t, 32, closed.Load())
}
