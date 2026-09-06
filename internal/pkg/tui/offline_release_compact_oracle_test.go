//go:build tui || all

package tui

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Inject the migration candidate explicitly. Phase 0 intentionally exercises two
// independent legacy builds; this is an oracle sanity check, NOT compact parity.
// Future compact tests call runOfflineCompactOracle with their actual builder.
type offlineOracleBuilder func(context.Context, *offline.Storage, offline.DatasetGeneration, OfflineAnalysisConfig, func(offline.Progress)) (*offlineIndexedSession, error)

var offlineOracleFields = strings.Fields(`src srcip dst dstip srcport dstport protocol info node nodeid interface length len
voip sip rtp dns tls http email sip.user sip.from sip.to sip.callid sip.method sip.codec sip.fromtag sip.totag sip.imsi sip.imei sip.status
rtp.seq rtp.sequence rtp.ssrc dns.query dns.name dns.type dns.ttl dns.latency tls.sni tls.ja3 http.host http.path http.method http.status http.contentlength
sip.unknown rtp.unknown dns.unknown tls.unknown http.unknown email.unknown unknown timestamp transport`)

func offlineOracleEqual(category string, want, got any) error {
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("%s mismatch", category)
	}
	return nil
}

func offlineOracleRecord(want, got offline.Detail) error {
	if want.ID != got.ID || want.Source != got.Source || !want.Packet.Timestamp.Equal(got.Packet.Timestamp) || want.CapturedLength != got.CapturedLength || want.OriginalLength != got.OriginalLength || want.Packet.Length != got.Packet.Length || want.Packet.LinkType != got.Packet.LinkType || sha256.Sum256(want.Packet.RawData) != sha256.Sum256(got.Packet.RawData) {
		return fmt.Errorf("logical record %d identity/source/time/length/link/raw digest mismatch", want.ID)
	}
	return nil
}

func offlineOracleMetadata(want, got offline.Detail) error {
	want.Token, got.Token = offline.Token{}, offline.Token{}
	want.Packet.RawData, got.Packet.RawData = nil, nil
	return offlineOracleEqual(fmt.Sprintf("detail metadata %d", want.ID), want, got)
}

func offlineOracleSummary(want, got offline.Summary) error {
	if err := offlineOracleEqual("summary ID", want.ID, got.ID); err != nil {
		return err
	}
	if err := offlineOracleEqual("list fields", want.DisplayFields(), got.DisplayFields()); err != nil {
		return err
	}
	if want.RecordType() != got.RecordType() {
		return fmt.Errorf("record type mismatch")
	}
	for _, field := range offlineOracleFields {
		if want.GetStringField(field) != got.GetStringField(field) || want.GetNumericField(field) != got.GetNumericField(field) || want.HasField(field) != got.HasField(field) {
			return fmt.Errorf("field accessor %q mismatch", field)
		}
	}
	return nil
}

func runOfflineCompactOracle(t *testing.T, cfg OfflineAnalysisConfig, candidate offlineOracleBuilder) {
	t.Helper()
	require.NotNil(t, candidate, "supply an actual candidate; never silently fall back to legacy")
	ctx := context.Background()
	build := func(fn offlineOracleBuilder, generation offline.DatasetGeneration) *offlineIndexedSession {
		storage, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 4 << 30, CacheBytes: 64 << 20, MaxRecordBytes: 8 << 20, MaxSources: 64})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, storage.Close()) })
		session, err := fn(ctx, storage, generation, cfg, nil)
		if session != nil {
			t.Cleanup(func() { require.NoError(t, session.Close()) })
		}
		require.NoError(t, err)
		return session
	}
	legacy, compact := build(indexOfflineLegacyDataset, 901), build(candidate, 902)
	require.Equal(t, legacy.Dataset.Count(), compact.Dataset.Count(), "logical count")
	require.NoError(t, offlineOracleEqual("dataset statistics", legacy.Dataset.Statistics(), compact.Dataset.Statistics()))
	numeric, err := filters.NewNumericComparisonFilter("length", ">=64")
	require.NoError(t, err)
	bpf, err := filters.NewBPFFilter("udp port 32001")
	require.NoError(t, err)
	stack := filters.NewFilterChain()
	stack.Add(numeric)
	stack.Add(filters.NewNodeFilter("Local"))
	filterCases := []struct {
		name   string
		filter interface{ Match(filters.Filterable) bool }
	}{
		{"all", nil}, {"text", filters.NewTextFilter("offline", nil)}, {"numeric", numeric},
		{"metadata", filters.NewMetadataFilter("voip")}, {"node", filters.NewNodeFilter("Local")},
		{"sip", filters.NewVoIPFilter("from", "alice")}, {"bpf", bpf},
		{"boolean", filters.NewBooleanFilter(filters.OpOR, numeric, filters.NewMetadataFilter("dns"), "length or dns")}, {"stack", stack},
	}
	for i, tc := range filterCases {
		t.Run(tc.name, func(t *testing.T) {
			query := func(ds offline.Dataset) offline.Query {
				spec := offline.QuerySpec{Token: offline.Token{Dataset: ds.Generation(), Query: offline.QueryGeneration(i + 1)}}
				if tc.filter != nil {
					spec.Match = func(s offline.Summary) bool { return tc.filter.Match(s) }
				}
				q, err := ds.Query(ctx, spec)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, q.Close()) })
				return q
			}
			a, b := query(legacy.Dataset), query(compact.Dataset)
			require.Equal(t, a.Count(), b.Count(), "filter count")
			require.NoError(t, offlineOracleEqual("filter statistics", a.Statistics(), b.Statistics()))
			// A single row per lease permits different backend page byte accounting;
			// all records are checked without retaining a private capture in memory.
			for row := uint64(0); row < a.Count(); row++ {
				pa, err := a.Page(ctx, offline.PageRequest{Token: a.Token(), Row: row, Limit: 1, MaxBytes: 8 << 20})
				require.NoError(t, err)
				pb, err := b.Page(ctx, offline.PageRequest{Token: b.Token(), Row: row, Limit: 1, MaxBytes: 8 << 20})
				if err != nil {
					require.NoError(t, pa.Close())
					require.NoError(t, err)
				}
				if len(pa.Rows) != 1 || len(pb.Rows) != 1 {
					require.NoError(t, pa.Close())
					require.NoError(t, pb.Close())
					t.Fatal("expected one row")
				}
				summaryErr := offlineOracleSummary(pa.Rows[0], pb.Rows[0])
				id := pa.Rows[0].ID
				require.NoError(t, pa.Close())
				require.NoError(t, pb.Close())
				require.NoError(t, summaryErr, "query row %d", row)

				if i == 0 {
					da, err := legacy.Dataset.Detail(ctx, a.Token(), id)
					require.NoError(t, err)
					db, err := compact.Dataset.Detail(ctx, b.Token(), id)
					require.NoError(t, err)
					require.NoError(t, offlineOracleRecord(da, db))
					require.NoError(t, offlineOracleMetadata(da, db))
					// The stored summary must also agree with the finalized detail projection.
					page, err := b.Page(ctx, offline.PageRequest{Token: b.Token(), Row: row, Limit: 1, MaxBytes: 8 << 20})
					require.NoError(t, err)
					projectionErr := offlineOracleSummary(offline.NewSummary(db.ID, db.Packet), page.Rows[0])
					require.NoError(t, page.Close())
					require.NoError(t, projectionErr)
				}
			}
			compareOfflineOracleExports(t, a, b)
		})
	}
	ae, be := legacy.EventStore.Events(), compact.EventStore.Events()
	require.Len(t, be, len(ae), "retained event count")
	uids := offlineOracleUIDs{forward: map[string]string{}, reverse: map[string]string{}}
	for i := range ae {
		// ArrivedAt is UI wall-clock ingestion time, not normalized event metadata.
		require.Equal(t, ae[i].ArrivalSequence, be[i].ArrivalSequence)
		require.NoError(t, uids.compare(ae[i].Event, be[i].Event), "event %d", i)
	}
	require.NoError(t, offlineOracleEqual("event counters", legacy.EventStore.Stats(), compact.EventStore.Stats()))
	// Call aggregation returns map values, so compare by stable call identity.
	calls := func(in []types.CallInfo) []types.CallInfo {
		out := append([]types.CallInfo(nil), in...)
		sort.Slice(out, func(i, j int) bool { return out[i].CallID < out[j].CallID })
		return out
	}
	require.NoError(t, offlineOracleEqual("calls", calls(legacy.Calls), calls(compact.Calls)))
	t.Logf("compared every logical record: packets=%d retained_events=%d arrived_events=%d calls=%d", legacy.Dataset.Count(), len(ae), legacy.EventStore.Stats().Arrived, len(legacy.Calls))
}

func compareOfflineOracleExports(t *testing.T, a, b offline.Query) {
	t.Helper()
	paths := []string{filepath.Join(t.TempDir(), "legacy.pcap"), filepath.Join(t.TempDir(), "candidate.pcap")}
	na, ea := exportOfflinePCAP(context.Background(), paths[0], func(ctx context.Context, visit func(offline.RawRecord) error) error {
		return offline.IterateRaw(ctx, a, visit)
	})
	nb, eb := exportOfflinePCAP(context.Background(), paths[1], func(ctx context.Context, visit func(offline.RawRecord) error) error {
		return offline.IterateRaw(ctx, b, visit)
	})
	require.Equal(t, na, nb, "export count")
	if ea != nil || eb != nil {
		require.Error(t, ea)
		require.Error(t, eb)
		require.Equal(t, ea.Error(), eb.Error())
		require.True(t, (a.Count() == 0 && ea.Error() == "no packets to save") || strings.HasPrefix(ea.Error(), "cannot export mixed link types"), "unexpected export failure: %v", ea)
		return
	}
	require.Equal(t, a.Count(), na)
	require.Equal(t, b.Count(), nb)
	readers := make([]*pcapgo.Reader, 2)
	for i, p := range paths {
		f, err := os.Open(p)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, f.Close()) })
		readers[i], err = pcapgo.NewReader(f)
		require.NoError(t, err)
	}
	require.Equal(t, readers[0].LinkType(), readers[1].LinkType())
	for row := uint64(0); ; row++ {
		ra, ca, ea := readers[0].ReadPacketData()
		rb, cb, eb := readers[1].ReadPacketData()
		if ea == io.EOF {
			require.ErrorIs(t, eb, io.EOF)
			require.Equal(t, na, row)
			break
		}
		require.NoError(t, ea)
		require.NoError(t, eb)
		require.Equal(t, ca, cb, "export capture metadata at %d", row)
		require.Equal(t, sha256.Sum256(ra), sha256.Sum256(rb), "export bytes at %d", row)
	}
}

func TestOfflineCompactOracleLegacySanity(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	// Duplicate arguments and equal timestamps retain distinct source identity.
	paths = append(paths, paths[0])
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32, MaxCalls: 32, SIPConfig: *voip.GetConfig()}, indexOfflineLegacyDataset)
}

func TestOfflineCompactOraclePrivateLegacySanity(t *testing.T) {
	path := os.Getenv("LIPPYCAT_BENCH_PCAP")
	if path == "" {
		t.Skip("set LIPPYCAT_BENCH_PCAP for the private-capture differential oracle")
	}
	frozen := FreezeOfflineOpen([]string{path}, "", 10000)
	runOfflineCompactOracle(t, frozen.Config, indexOfflineLegacyDataset)
}

// Independent pcapgo reference is valid only for these untransformed fixtures.
// Physical-frame comparison is NOT a valid oracle for normalized real captures.
func TestOfflineCompactOracleIndependentLogicalReference(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	paths = append(paths, paths[0])
	var reference []offline.Detail
	for source, path := range paths {
		f, err := os.Open(path)
		require.NoError(t, err)
		r, err := pcapgo.NewReader(f)
		require.NoError(t, err)
		for seq := uint64(0); ; seq++ {
			raw, ci, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			reference = append(reference, offline.Detail{Source: offline.SourcePosition{ArgumentIndex: uint32(source), Path: path, Sequence: seq}, CapturedLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), Packet: types.PacketDisplay{RawData: raw, Timestamp: ci.Timestamp, Length: ci.Length, LinkType: r.LinkType()}})
		}
		require.NoError(t, f.Close())
	}
	sort.SliceStable(reference, func(i, j int) bool { return reference[i].Packet.Timestamp.Before(reference[j].Packet.Timestamp) })
	ds, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 901, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, ds.Close()) }()
	require.EqualValues(t, len(reference), ds.Dataset.Count())
	for i, want := range reference {
		want.ID = offline.PacketID(i)
		got, err := ds.Dataset.Detail(context.Background(), offline.Token{Dataset: 901}, want.ID)
		require.NoError(t, err)
		require.NoError(t, offlineOracleRecord(want, got))
	}
}

func TestOfflineCompactOracleDetectsMismatches(t *testing.T) {
	original := offline.Detail{ID: 3, Source: offline.SourcePosition{ArgumentIndex: 1, Sequence: 2}, CapturedLength: 1, OriginalLength: 2, Packet: types.PacketDisplay{RawData: []byte{1}, Timestamp: time.Unix(1700000000, 123), Length: 2, LinkType: layers.LinkTypeEthernet}}
	mutations := map[string]func(*offline.Detail){"order": func(d *offline.Detail) { d.ID++ }, "source": func(d *offline.Detail) { d.Source.ArgumentIndex++ }, "sequence": func(d *offline.Detail) { d.Source.Sequence++ }, "timestamp": func(d *offline.Detail) { d.Packet.Timestamp = d.Packet.Timestamp.Add(time.Nanosecond) }, "capture length": func(d *offline.Detail) { d.CapturedLength++ }, "original length": func(d *offline.Detail) { d.OriginalLength++ }, "link": func(d *offline.Detail) { d.Packet.LinkType = layers.LinkTypeRaw }, "raw": func(d *offline.Detail) { d.Packet.RawData = []byte{2} }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			mutate(&changed)
			require.Error(t, offlineOracleRecord(original, changed))
		})
	}
	changed := original
	changed.Packet.Info = "different"
	require.Error(t, offlineOracleMetadata(original, changed))
	require.Error(t, offlineOracleSummary(offline.NewSummary(3, original.Packet), offline.NewSummary(3, changed.Packet)))
	require.Error(t, offlineOracleEqual("filter IDs", []offline.PacketID{1, 2}, []offline.PacketID{2, 1}))
	require.Error(t, offlineOracleEqual("statistics", offline.Statistics{Packets: 1}, offline.Statistics{Packets: 2}))
	require.Error(t, offlineOracleEqual("calls", []types.CallInfo{{CallID: "a"}}, []types.CallInfo{{CallID: "b"}}))
}

// Keep a nontrivial finalized stateful fixture in the differential corpus.
func TestOfflineCompactOracleSIPFinalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sip-gap.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriterNanos(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: oracle-eof\r\nContent-Length: 0\r\n\r\n")
	for i, payload := range [][]byte{[]byte("x\r\n"), message} {
		env := offlineSIPPacket(t, uint32(100+i*100), payload, time.Unix(1700000000+int64(i), 123))
		p := env.Packet()
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: env.CaptureTime, CaptureLength: len(p.Data()), Length: len(p.Data())}, p.Data()))
	}
	require.NoError(t, f.Close())
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, MaxCalls: 32, SIPConfig: *voip.GetConfig()}, func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		session, err := indexOfflineDataset(ctx, storage, generation, cfg, report)
		if err != nil {
			return session, err
		}
		if len(session.Calls) != 1 || session.Calls[0].CallID != "oracle-eof" || session.Dataset.Statistics().Protocols["SIP"] == 0 {
			return session, fmt.Errorf("SIP EOF fixture did not finalize expected call")
		}
		detail, err := session.Dataset.Detail(ctx, offline.Token{Dataset: generation}, 1)
		if err != nil {
			return session, err
		}
		if detail.Packet.VoIPData == nil || detail.Packet.VoIPData.CallID != "oracle-eof" || detail.Packet.Info != "INVITE sip:bob@example.com SIP/2.0" {
			return session, fmt.Errorf("SIP EOF fixture missing finalized detail")
		}
		return session, nil
	})
}

// flowid.newUID intentionally uses crypto/rand for per-session flow identities.
// Compare that field through a bijection, preserving reuse and distinctness;
// File observation prefixes also vary randomly between analyzer instances. Only
// those prefixes are normalized; sequence suffixes and relationships stay exact.
// EventID, ProducerSessionID, sequence, CommunityID and other payload stay exact.
// The maps are bounded by the configured retained event capacity.
type offlineOracleUIDs struct {
	forward, reverse         map[string]string
	fileForward, fileReverse map[string]string
}

// fileID validates the generated F + 12 uppercase hex + 16 uppercase hex form.
// A prefix mapping is retained only for IDs referenced by retained events, so
// its size is bounded by twice the retained event history (including parents).
func (u *offlineOracleUIDs) fileID(path, a, b string, optional bool) error {
	if optional && a == "" && b == "" {
		return nil
	}
	valid := func(id string) bool {
		if len(id) != 29 || id[0] != 'F' {
			return false
		}
		for _, c := range id[1:] {
			if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	if !valid(a) || !valid(b) {
		return fmt.Errorf("%s generated shape mismatch", path)
	}
	if a[13:] != b[13:] {
		return fmt.Errorf("%s sequence mismatch", path)
	}
	x, y := a[1:13], b[1:13]
	if old, ok := u.fileForward[x]; ok && old != y {
		return fmt.Errorf("%s prefix reuse mismatch", path)
	}
	if old, ok := u.fileReverse[y]; ok && old != x {
		return fmt.Errorf("%s prefix collision mismatch", path)
	}
	if u.fileForward == nil {
		u.fileForward, u.fileReverse = map[string]string{}, map[string]string{}
	}
	u.fileForward[x], u.fileReverse[y] = y, x
	return nil
}

func (u *offlineOracleUIDs) compare(a, b events.Event) error {
	switch left := a.(type) {
	case events.FileMetadataEvent:
		if right, ok := b.(events.FileMetadataEvent); ok {
			if err := u.fileID("FileMetadataEvent.FileID", left.FileID, right.FileID, false); err != nil {
				return err
			}
			if err := u.fileID("FileMetadataEvent.ParentFileID", left.ParentFileID, right.ParentFileID, true); err != nil {
				return err
			}
			left.FileID, right.FileID = left.FileID[13:], right.FileID[13:]
			if left.ParentFileID != "" {
				left.ParentFileID, right.ParentFileID = left.ParentFileID[13:], right.ParentFileID[13:]
			}
			a, b = left, right
		}
	case events.FileContentEvent:
		if right, ok := b.(events.FileContentEvent); ok {
			if err := u.fileID("FileContentEvent.FileID", left.FileID, right.FileID, false); err != nil {
				return err
			}
			left.FileID, right.FileID = left.FileID[13:], right.FileID[13:]
			a, b = left, right
		}
	}
	x, y := a.Envelope().UID, b.Envelope().UID
	if (x == "") != (y == "") {
		return fmt.Errorf("flow UID presence mismatch")
	}
	if old, ok := u.forward[x]; ok && old != y {
		return fmt.Errorf("flow UID reuse mismatch")
	}
	if old, ok := u.reverse[y]; ok && old != x {
		return fmt.Errorf("flow UID collision mismatch")
	}
	u.forward[x], u.reverse[y] = y, x
	strip := func(e events.Event) events.Event {
		switch e := e.(type) {
		case events.ConnEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.DNSEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.TLSEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.HTTPEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.SMTPEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.FileMetadataEvent:
			e.EventEnvelope.UID = ""
			return e
		case events.FileContentEvent:
			e.EventEnvelope.UID = ""
			return e
		default:
			return e // New event representations must explicitly extend this list.
		}
	}
	if err := offlineOracleEqual("normalized event", strip(a), strip(b)); err != nil {
		return fmt.Errorf("%T: %w", a, err)
	}
	return nil
}

func TestOfflineCompactOracleEventMismatch(t *testing.T) {
	newMap := func() *offlineOracleUIDs {
		return &offlineOracleUIDs{forward: map[string]string{}, reverse: map[string]string{}}
	}
	a := events.NewConnEvent(events.Envelope{UID: "random-a", EventID: "stable", EventSequence: 1})
	b := events.NewConnEvent(events.Envelope{UID: "random-b", EventID: "stable", EventSequence: 1})
	u := newMap()
	require.NoError(t, u.compare(a, b))
	require.NoError(t, u.compare(a, b))
	changed := b
	changed.Service = "changed"
	require.Error(t, newMap().compare(a, changed))
	changed = b
	changed.EventEnvelope.EventID = "wrong"
	require.Error(t, newMap().compare(a, changed))
	changed = b
	changed.EventEnvelope.UID = "another-flow"
	require.Error(t, u.compare(a, changed))
	changed = a
	changed.EventEnvelope.UID = "another-flow"
	require.Error(t, u.compare(changed, b))
}

func TestOfflineCompactOracleFileIdentity(t *testing.T) {
	id := func(prefix string, sequence uint64) string { return fmt.Sprintf("F%s%016X", prefix, sequence) }
	const leftPrefix, rightPrefix, otherPrefix = "012345ABCDEF", "ABCDEF012345", "999999999999"
	metadata := func(prefix string, sequence uint64) events.FileMetadataEvent {
		e := events.NewFileMetadataEvent(events.Envelope{EventID: "stable"})
		e.FileID = id(prefix, sequence)
		return e
	}
	newMap := func() *offlineOracleUIDs {
		return &offlineOracleUIDs{forward: map[string]string{}, reverse: map[string]string{}}
	}
	a, b := metadata(leftPrefix, 1), metadata(rightPrefix, 1)
	u := newMap()
	require.NoError(t, u.compare(a, b))
	childA, childB := metadata(leftPrefix, 2), metadata(rightPrefix, 2)
	childA.ParentFileID, childB.ParentFileID = a.FileID, b.FileID
	require.NoError(t, u.compare(childA, childB))
	contentA, contentB := events.NewFileContentEvent(events.Envelope{}), events.NewFileContentEvent(events.Envelope{})
	contentA.FileID, contentB.FileID = childA.FileID, childB.FileID
	contentA.Content, contentB.Content = []byte("fixture"), []byte("fixture")
	require.NoError(t, u.compare(contentA, contentB))
	require.Len(t, u.fileForward, 1)
	require.Len(t, u.fileReverse, 1)

	require.ErrorContains(t, newMap().compare(a, metadata(rightPrefix, 2)), "sequence")
	require.ErrorContains(t, u.compare(a, metadata(otherPrefix, 1)), "reuse")
	require.ErrorContains(t, u.compare(metadata(otherPrefix, 1), b), "collision")
	for _, malformed := range []string{"", "F123", strings.ToLower(b.FileID), "FZBCDEF0123450000000000000001"} {
		changed := b
		changed.FileID = malformed
		require.ErrorContains(t, newMap().compare(a, changed), "shape")
	}
	changedChild := childB
	changedChild.ParentFileID = id(rightPrefix, 2)
	require.ErrorContains(t, u.compare(childA, changedChild), "ParentFileID sequence")
	changedChild.ParentFileID = id(otherPrefix, 1)
	require.ErrorContains(t, u.compare(childA, changedChild), "ParentFileID prefix reuse")
	changedChild.ParentFileID = ""
	require.ErrorContains(t, u.compare(childA, changedChild), "ParentFileID generated shape")
	changedContent := contentB
	changedContent.FileID = id(otherPrefix, 2)
	require.ErrorContains(t, u.compare(contentA, changedContent), "prefix reuse")
	changedContent.FileID = id(rightPrefix, 1)
	require.ErrorContains(t, u.compare(contentA, changedContent), "sequence")
	changedContent = contentB
	changedContent.Content = []byte("changed")
	require.Error(t, u.compare(contentA, changedContent))

	// Distinct analyzer prefixes remain distinct even when counters coincide.
	require.NoError(t, u.compare(metadata(otherPrefix, 1), metadata("888888888888", 1)))
	require.Len(t, u.fileForward, 2)
}

func TestOfflineCompactOracleMetadataPresence(t *testing.T) {
	packets := []types.PacketDisplay{
		{},
		{VoIPData: &types.VoIPMetadata{}}, {VoIPData: &types.VoIPMetadata{IsRTP: true}},
		{DNSData: &types.DNSMetadata{}}, {TLSData: &types.TLSMetadata{}},
		{HTTPData: &types.HTTPMetadata{}}, {EmailData: &types.EmailMetadata{}},
	}
	storage := testOfflineStorage(t)
	builder, err := storage.NewBuilder(903, []offline.SourcePosition{{Path: "metadata-fixture"}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, builder.Close()) })
	for i, p := range packets {
		p.Timestamp = time.Unix(1700000000+int64(i), 0).UTC()
		packets[i] = p
		require.NoError(t, builder.Append(context.Background(), offline.Detail{Source: offline.SourcePosition{Path: "metadata-fixture", Sequence: uint64(i)}, Packet: p}))
	}
	ds, err := builder.Finish(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, ds.Close()) }()
	q, err := ds.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: 903, Query: 1}})
	require.NoError(t, err)
	defer func() { require.NoError(t, q.Close()) }()
	for i, p := range packets {
		d, err := ds.Detail(context.Background(), offline.Token{Dataset: 903}, offline.PacketID(i))
		require.NoError(t, err)
		require.NoError(t, offlineOracleMetadata(offline.Detail{ID: offline.PacketID(i), Source: offline.SourcePosition{Path: "metadata-fixture", Sequence: uint64(i)}, Packet: p}, d))
		page, err := q.Page(context.Background(), offline.PageRequest{Token: q.Token(), Row: uint64(i), Limit: 1, MaxBytes: 1 << 20})
		require.NoError(t, err)
		if len(page.Rows) != 1 {
			require.NoError(t, page.Close())
			t.Fatal("expected metadata fixture row")
		}
		summaryErr := offlineOracleSummary(offline.NewSummary(offline.PacketID(i), p), page.Rows[0])
		require.NoError(t, page.Close())
		require.NoError(t, summaryErr)
		if i > 0 {
			require.Error(t, offlineOracleSummary(offline.NewSummary(0, types.PacketDisplay{}), offline.NewSummary(0, p)), "nil versus empty metadata must differ")
		}
	}
}
