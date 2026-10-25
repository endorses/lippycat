package offline

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type revisionFixtureRow struct {
	detail     Detail
	provenance PacketProvenance
}

func normalizedRevisionFixture(t *testing.T, policy BackingPolicy, compressed, derived bool) (*Storage, *diskDataset, []revisionFixtureRow, string) {
	t.Helper()
	ctx := context.Background()
	s := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	path := filepath.Join(t.TempDir(), "source")
	data := []byte{0, 1, 2, 3, 4, 5}
	physical := data
	if compressed {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		_, err := writer.Write(data)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		physical = encoded.Bytes()
	}
	require.NoError(t, os.WriteFile(path, physical, 0600))
	r := s.NewBackingRegistry()
	input, err := r.Open(ctx, path, 0, policy, compressed)
	require.NoError(t, err)
	require.NoError(t, input.Close())
	b, err := s.NewCompactBaseBuilder(41, []SourcePosition{{Path: path}}, r)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	rows := make([]revisionFixtureRow, 3)
	for i := range rows {
		raw := data[i*2 : i*2+2]
		loc, err := r.Locator(input.ID, int64(i*2), raw)
		require.NoError(t, err)
		if derived && i == 1 {
			raw = []byte{9, 8}
			loc, err = r.AppendDerived(ctx, 0, raw)
			require.NoError(t, err)
		}
		rows[i] = revisionFixtureRow{
			detail: Detail{Source: SourcePosition{Path: path, Sequence: uint64(i)}, CapturedLength: 2, OriginalLength: 9, Packet: types.PacketDisplay{
				Timestamp: time.Unix(int64(i), 123), SrcIP: fmt.Sprintf("192.0.2.%d", i+1), DstIP: "198.51.100.1", SrcPort: "40000", DstPort: "53", Transport: 17,
				NodeID: "Local", Interface: "eth0", Length: 2, LinkType: layers.LinkTypeEthernet, RawData: raw,
				// Even accidental application data cannot leak into the base.
				Protocol: "DNS", Info: "analysis", DNSData: &types.DNSMetadata{QueryName: "secret.example"}, RADIUSData: &types.RADIUSMetadata{},
			}},
			provenance: PacketProvenance{Locator: loc, Derived: derived && i == 1, PhysicalOrdinal: uint64(i + 1), OriginalCapture: gopacket.CaptureInfo{CaptureLength: 2, Length: 9}, OriginalLinkType: layers.LinkTypeEthernet},
		}
		require.NoError(t, b.AppendCompact(ctx, rows[i].detail, rows[i].provenance))
	}
	dataset, err := b.Finish(ctx)
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	return s, d, rows, path
}

func completeRevisionFixture(t *testing.T, s *Storage, base Dataset, rows []revisionFixtureRow, decodes *atomic.Int64) *diskDataset {
	t.Helper()
	b, err := s.NewCompactRevisionBuilder(base, CompletedRevision, func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		if decodes != nil {
			decodes.Add(1)
		}
		packet := summary.DisplayFields()
		packet.RawData = append([]byte(nil), raw...)
		return packet, ctx.Err()
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	for _, row := range rows {
		require.NoError(t, b.AppendCompact(context.Background(), row.detail, row.provenance))
	}
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	return d
}

func TestCompactBaseRevisionHasOnlyNormalizedMetadata(t *testing.T) {
	s, base, _, _ := normalizedRevisionFixture(t, BackingSnapshot, false, false)
	require.Equal(t, BaseRevision, base.Revision())
	token := Token{Dataset: base.Generation(), Revision: BaseRevision, Query: 1}
	detail, err := base.Detail(context.Background(), token, 1)
	require.NoError(t, err)
	require.Equal(t, token, detail.Token)
	require.Equal(t, "192.0.2.2", detail.Packet.SrcIP)
	require.Equal(t, []byte{2, 3}, detail.Packet.RawData)
	require.Empty(t, detail.Packet.Protocol)
	require.Empty(t, detail.Packet.Info)
	require.Nil(t, detail.Packet.DNSData)
	require.Nil(t, detail.Packet.RADIUSData)
	query, err := AllPackets(context.Background(), base, token)
	require.NoError(t, err)
	require.EqualValues(t, 3, query.Count())
	require.NoError(t, query.Close())
	var manifest struct {
		Revision AnalysisRevision
		Compact  compactCompletion
	}
	data, err := os.ReadFile(filepath.Join(base.dir, "manifest"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, BaseRevision, manifest.Revision)
	require.True(t, manifest.Compact.BaseComplete)
	require.False(t, manifest.Compact.AnalysisComplete)
	require.Zero(t, manifest.Compact.AnalysisRevision)
	refs, err := base.compactOffsets(0)
	require.NoError(t, err)
	var header [compactBlockHeaderBytes]byte
	_, err = base.summaries.ReadAt(header[:], int64(refs[0]))
	require.NoError(t, err)
	require.EqualValues(t, BaseRevision, binary.LittleEndian.Uint64(header[32:40]))
	require.Error(t, s.Close(), "storage cannot remove active revision backing handles")
	_, err = base.Detail(context.Background(), token, 0)
	require.NoError(t, err, "rejected storage close must leave the base usable")
}

func TestCompactBaseQueryReadinessRejectsUnknownApplicationFields(t *testing.T) {
	_, base, _, _ := normalizedRevisionFixture(t, BackingSource, false, false)
	for _, tc := range []struct {
		spec  ExpressionSpec
		ready bool
	}{
		{ExpressionSpec{Op: "all"}, true}, {ExpressionSpec{Op: "none"}, true},
		{ExpressionSpec{Op: "equal", Fields: []string{"src"}, Text: "192.0.2.2"}, true},
		{ExpressionSpec{Op: "node", Text: "Local"}, true},
		{ExpressionSpec{Op: "numeric", Fields: []string{"length"}, Number: 2, Comparison: "="}, true},
		{ExpressionSpec{Op: "has", Fields: []string{"srcport"}}, true},
		{ExpressionSpec{Op: "equal", Fields: []string{"protocol"}, Text: "DNS"}, false},
		{ExpressionSpec{Op: "contains", Fields: []string{"info"}, Text: "analysis"}, false},
		{ExpressionSpec{Op: "has", Fields: []string{"dns"}}, false},
		{ExpressionSpec{Op: "text", Fields: []string{"src"}, Text: "192.0.2"}, false},
		{ExpressionSpec{Op: "equal", Fields: []string{"unknown"}, Text: ""}, false},
	} {
		t.Run(tc.spec.Op+fmt.Sprint(tc.spec.Fields), func(t *testing.T) {
			expression, err := NewExpression(tc.spec)
			require.NoError(t, err)
			before := base.Resources().DiskBytes
			q, err := base.Query(context.Background(), QuerySpec{Token: Token{Dataset: base.Generation(), Revision: BaseRevision, Query: 2}, Expression: expression})
			if !tc.ready {
				require.ErrorIs(t, err, ErrAnalysisPending)
				require.Nil(t, q)
				require.Equal(t, before, base.Resources().DiskBytes)
				return
			}
			require.NoError(t, err)
			require.NoError(t, q.Close())
		})
	}
	q, err := base.Query(context.Background(), QuerySpec{Token: Token{Dataset: 41, Revision: BaseRevision}, Match: func(Summary) bool { t.Fatal("opaque predicate ran before analysis"); return true }})
	require.Nil(t, q)
	require.ErrorIs(t, err, ErrAnalysisPending)
	child, err := NewExpression(ExpressionSpec{Op: "has", Fields: []string{"tls"}})
	require.NoError(t, err)
	boolean, err := NewExpression(ExpressionSpec{Op: "not", Children: []*Expression{child}})
	require.NoError(t, err)
	require.ErrorIs(t, CheckQueryReadiness(BaseRevision, QuerySpec{Expression: boolean}), ErrAnalysisPending)
	ready, err := NewExpression(ExpressionSpec{Op: "equal", Fields: []string{"srcport"}, Text: "40000"})
	require.NoError(t, err)
	boolean, err = NewExpression(ExpressionSpec{Op: "and", Children: []*Expression{ready, ready}})
	require.NoError(t, err)
	require.NoError(t, CheckQueryReadiness(BaseRevision, QuerySpec{Expression: boolean}))
	q, err = base.Related(context.Background(), Token{Dataset: 41, Revision: BaseRevision, Query: 3}, Flow{
		Source: netip.MustParseAddrPort("192.0.2.2:40000"), Destination: netip.MustParseAddrPort("198.51.100.1:53"), Transport: 17, Node: "Local",
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, q.Count(), "related flow depends on normalized tuple and transport only")
	position, found, err := q.Position(context.Background(), 1)
	require.NoError(t, err)
	require.True(t, found)
	require.Zero(t, position)
	require.NoError(t, q.Close())
}

func TestCompactRevisionExactTokensAndImmutableQueries(t *testing.T) {
	s, base, rows, _ := normalizedRevisionFixture(t, BackingSource, false, false)
	completed := completeRevisionFixture(t, s, base, rows, nil)
	require.Equal(t, CompletedRevision, completed.Revision())
	for _, d := range []*diskDataset{base, completed} {
		token := Token{Dataset: d.Generation(), Revision: d.Revision(), Query: 5, Request: 7}
		q, err := AllPackets(context.Background(), d, token)
		require.NoError(t, err)
		wrong := token
		wrong.Revision = 1 - token.Revision
		_, err = AllPackets(context.Background(), d, wrong)
		require.Error(t, err)
		_, err = d.Query(context.Background(), QuerySpec{Token: wrong})
		require.Error(t, err)
		errorDetail, detailErr := d.Detail(context.Background(), wrong, 0)
		err = detailErr
		require.Error(t, err)
		require.Equal(t, wrong, errorDetail.Token)
		_, err = d.PinDetail(context.Background(), wrong, 0)
		require.Error(t, err)
		page, err := q.Page(context.Background(), PageRequest{Token: wrong, Limit: 1, MaxBytes: 32 << 10})
		require.Error(t, err)
		require.Equal(t, wrong, page.Token)
		require.Empty(t, page.Rows)
		page, err = q.Page(context.Background(), PageRequest{Token: token, Limit: 1, MaxBytes: 32 << 10})
		require.NoError(t, err)
		if d.Revision() == BaseRevision {
			require.Empty(t, page.Rows[0].GetStringField("protocol"))
		} else {
			require.Equal(t, "DNS", page.Rows[0].GetStringField("protocol"))
		}
		require.NoError(t, page.Close())
		require.NoError(t, q.Close())
	}
	var manifest struct {
		Revision AnalysisRevision
		Compact  compactCompletion
	}
	data, err := os.ReadFile(filepath.Join(completed.dir, "manifest"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, CompletedRevision, manifest.Revision)
	require.True(t, manifest.Compact.AnalysisComplete)
	q, err := completed.Query(context.Background(), QuerySpec{Token: Token{Dataset: 41, Revision: CompletedRevision, Query: 6}, Match: func(s Summary) bool { return s.ID != 1 }})
	require.NoError(t, err)
	for _, tc := range []struct {
		id    PacketID
		row   uint64
		found bool
	}{{0, 0, true}, {1, 0, false}, {2, 1, true}, {3, 0, false}} {
		row, found, err := q.Position(context.Background(), tc.id)
		require.NoError(t, err)
		require.Equal(t, tc.found, found)
		if found {
			require.Equal(t, tc.row, row)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = q.Position(ctx, 0)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, q.Close())
	_, _, err = q.Position(context.Background(), 0)
	require.Error(t, err)
}

func TestCompactRevisionsRetainValidatedSharedBackingAcrossBaseClose(t *testing.T) {
	for _, tc := range []struct {
		name                string
		policy              BackingPolicy
		compressed, derived bool
	}{{"source", BackingSource, false, false}, {"snapshot", BackingSnapshot, false, false}, {"gzip", BackingSource, true, false}, {"derived", BackingSnapshot, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, base, rows, path := normalizedRevisionFixture(t, tc.policy, tc.compressed, tc.derived)
			registry := base.compact.registry
			b, err := s.NewCompactRevisionBuilder(base, CompletedRevision, func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
				p := summary.DisplayFields()
				p.RawData = append([]byte(nil), raw...)
				return p, ctx.Err()
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, b.Close()) })
			baseDir := base.dir
			require.NoError(t, base.Close())
			_, err = os.Stat(baseDir)
			require.ErrorIs(t, err, os.ErrNotExist)
			// Replacing the argument must never cause a revision to reopen it.
			require.NoError(t, os.Rename(path, path+".original"))
			require.NoError(t, os.WriteFile(path, []byte("new unrelated source"), 0600))
			for _, row := range rows {
				require.NoError(t, b.AppendCompact(context.Background(), row.detail, row.provenance))
			}
			dataset, err := b.Finish(context.Background())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, dataset.Close()) })
			for i, row := range rows {
				got, err := dataset.Detail(context.Background(), Token{Dataset: 41, Revision: CompletedRevision}, PacketID(i))
				require.NoError(t, err)
				require.Equal(t, row.detail.Packet.RawData, got.Packet.RawData)
				require.Equal(t, "DNS", got.Packet.Protocol)
			}
			require.NotEmpty(t, registry.entries)
			require.NoError(t, dataset.Close())
			require.Empty(t, registry.entries)
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestCompactBaseRawPinSurvivesCompletedPublicationAndClose(t *testing.T) {
	s, base, rows, _ := normalizedRevisionFixture(t, BackingSnapshot, false, true)
	q, err := AllPackets(context.Background(), base, Token{Dataset: 41, Revision: BaseRevision, Query: 1})
	require.NoError(t, err)
	pin, err := PinQuery(q)
	require.NoError(t, err)
	defer pin.Close()
	var decodes atomic.Int64
	completed := completeRevisionFixture(t, s, base, rows, &decodes)
	decodes.Store(0)
	closed := make(chan error, 1)
	go func() { closed <- base.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("base closed while raw pin was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	require.Equal(t, BaseRevision, pin.Token().Revision)
	visits := 0
	require.NoError(t, pin.IterateRaw(context.Background(), func(raw RawRecord) error {
		require.Equal(t, rows[visits].detail.Packet.RawData, raw.RawData)
		visits++
		return nil
	}))
	require.Equal(t, 3, visits)
	require.Zero(t, decodes.Load())
	_, err = completed.Detail(context.Background(), Token{Dataset: 41, Revision: CompletedRevision}, 0)
	require.NoError(t, err)
	require.NoError(t, pin.Close())
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("base close did not join released raw pin")
	}
	_, err = completed.Detail(context.Background(), Token{Dataset: 41, Revision: CompletedRevision}, 2)
	require.NoError(t, err)
}

func TestCompactRevisionIncompleteBuildKeepsBaseAndAccounting(t *testing.T) {
	s, base, rows, _ := normalizedRevisionFixture(t, BackingSnapshot, false, false)
	before := s.Resources().DiskBytes
	b, err := s.NewCompactRevisionBuilder(base, CompletedRevision, func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		p := summary.DisplayFields()
		p.RawData = raw
		return p, ctx.Err()
	})
	require.NoError(t, err)
	require.NoError(t, b.AppendCompact(context.Background(), rows[0].detail, rows[0].provenance))
	_, err = b.Finish(context.Background())
	require.ErrorContains(t, err, "complete base count")
	require.NoError(t, b.Close())
	require.Equal(t, before, s.Resources().DiskBytes)
	_, err = base.Detail(context.Background(), Token{Dataset: 41, Revision: BaseRevision}, 0)
	require.NoError(t, err)
	_, err = s.NewCompactRevisionBuilder(base, BaseRevision, nil)
	require.Error(t, err)
	_, err = s.NewCompactRevisionBuilder(base, CompletedRevision, nil)
	require.Error(t, err)
	base.compact.registry.mu.Lock()
	require.Equal(t, 1, base.compact.registry.compactOwners)
	base.compact.registry.mu.Unlock()
}

func TestCompactRevisionHeaderRejectsOtherRevision(t *testing.T) {
	_, base, _, _ := normalizedRevisionFixture(t, BackingSource, false, false)
	f, err := os.OpenFile(base.summaries.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	var revision [8]byte
	binary.LittleEndian.PutUint64(revision[:], uint64(CompletedRevision))
	_, err = f.WriteAt(revision[:], 24)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = base.Detail(context.Background(), Token{Dataset: 41, Revision: BaseRevision}, 0)
	require.ErrorContains(t, err, "header/version")
}

func TestCompactRevisionFinalBackingCleanupRemainsRetryable(t *testing.T) {
	s, base, rows, _ := normalizedRevisionFixture(t, BackingSnapshot, false, false)
	completed := completeRevisionFixture(t, s, base, rows, nil)
	registry := base.compact.registry
	path := registry.entries[0].scratch.path
	require.NoError(t, base.Close())
	require.NoError(t, os.Rename(path, path+".held"))
	require.NoError(t, os.Mkdir(path, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "block-removal"), []byte{1}, 0600))
	require.Error(t, completed.Close())
	require.NotEmpty(t, registry.entries)
	require.Positive(t, s.Resources().DiskBytes)
	require.NoError(t, os.RemoveAll(path))
	require.NoError(t, os.Rename(path+".held", path))
	require.NoError(t, completed.Close())
	require.Empty(t, registry.entries)
	require.Zero(t, s.Resources().DiskBytes)
	require.NoError(t, completed.Close())
}

func TestCompactRevisionsShareSourceMutationFailureAfterCachedReads(t *testing.T) {
	s, base, rows, path := normalizedRevisionFixture(t, BackingSource, false, false)
	completed := completeRevisionFixture(t, s, base, rows, nil)
	queries := make([]Query, 0, 2)
	for _, d := range []*diskDataset{base, completed} {
		token := Token{Dataset: d.Generation(), Revision: d.Revision(), Query: 4}
		_, err := d.Detail(context.Background(), token, 0)
		require.NoError(t, err)
		q, err := AllPackets(context.Background(), d, token)
		require.NoError(t, err)
		queries = append(queries, q)
		t.Cleanup(func() { require.NoError(t, q.Close()) })
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	// Preserve size and mtime so per-record digest enforcement must detect it.
	require.NoError(t, os.WriteFile(path, []byte{9, 1, 2, 3, 4, 5}, 0600))
	require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
	for _, d := range []*diskDataset{base, completed} {
		_, err := d.Detail(context.Background(), Token{Dataset: 41, Revision: d.Revision()}, 0)
		require.ErrorIs(t, err, ErrSourceChanged)
	}
	for _, q := range queries {
		visits := 0
		err := IterateRaw(context.Background(), q, func(RawRecord) error { visits++; return nil })
		require.ErrorIs(t, err, ErrSourceChanged)
		require.Zero(t, visits)
	}
}

func TestCompactBaseCompressionOverlapAndScanBindExactRevision(t *testing.T) {
	s, original, rows, _ := normalizedRevisionFixture(t, BackingSource, false, false)
	s.limits.CacheBytes, s.limits.MaxRecordBytes, s.limits.DiskBytes = 64<<20, 1<<20, 64<<20
	b, err := s.NewCompactBaseBuilder(42, original.compact.sources, original.compact.registry)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	for i := 0; i < compactRows*3+5; i++ {
		row := rows[0]
		row.detail.Source.Sequence = uint64(i)
		require.NoError(t, b.AppendCompact(context.Background(), row.detail, row.provenance))
	}
	require.NotNil(t, b.d.compact.overlap)
	require.True(t, b.d.compact.overlap.pending)
	require.EqualValues(t, BaseRevision, binary.LittleEndian.Uint64(b.d.compact.overlap.header[32:40]))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataset.Close()) })
	expression, err := NewExpression(ExpressionSpec{Op: "equal", Fields: []string{"src"}, Text: "192.0.2.1"})
	require.NoError(t, err)
	q, err := dataset.Query(context.Background(), QuerySpec{Token: Token{Dataset: 42, Revision: BaseRevision, Query: 1}, Expression: expression})
	require.NoError(t, err)
	require.EqualValues(t, compactRows*3+5, q.Count())
	require.NoError(t, q.Close())
	value, err := dataset.Detail(context.Background(), Token{Dataset: 42, Revision: BaseRevision}, compactRows*3)
	require.NoError(t, err)
	require.Empty(t, value.Packet.Protocol)
}

func TestCompactCompletedRevisionFailureCancellationAndQuotaPreserveBase(t *testing.T) {
	for _, cause := range []string{"decoder", "cancel", "quota"} {
		t.Run(cause, func(t *testing.T) {
			s, base, rows, _ := normalizedRevisionFixture(t, BackingSnapshot, false, false)
			before := s.Resources()
			sentinel := errors.New("application analysis failed")
			decode := func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
				if cause == "decoder" {
					return types.PacketDisplay{}, sentinel
				}
				p := summary.DisplayFields()
				p.RawData = raw
				return p, ctx.Err()
			}
			if cause == "quota" {
				s.limits.DiskBytes = before.DiskBytes
			}
			b, err := s.NewCompactRevisionBuilder(base, CompletedRevision, decode)
			if cause == "quota" {
				require.Error(t, err)
				require.Nil(t, b)
			} else {
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(context.Background())
				if cause == "cancel" {
					cancel()
				}
				err = b.AppendCompact(ctx, rows[0].detail, rows[0].provenance)
				cancel()
				if cause == "cancel" {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, sentinel)
				}
				_, err = b.Finish(context.Background())
				require.Error(t, err)
				require.NoError(t, b.Close())
			}
			require.Equal(t, before.DiskBytes, s.Resources().DiskBytes)
			require.Equal(t, before.InFlightBytes, s.Resources().InFlightBytes)
			value, err := base.Detail(context.Background(), Token{Dataset: 41, Revision: BaseRevision}, 0)
			require.NoError(t, err)
			require.Equal(t, rows[0].detail.Packet.RawData, value.Packet.RawData)
			require.Empty(t, value.Packet.Protocol)
		})
	}
}

func TestCompactBaseBuilderRejectsApplicationAmendments(t *testing.T) {
	for _, narrow := range []bool{false, true} {
		s, original, rows, _ := normalizedRevisionFixture(t, BackingSnapshot, false, false)
		b, err := s.NewCompactBaseBuilder(42, original.compact.sources, original.compact.registry)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, b.Close()) })
		require.NoError(t, b.AppendCompact(context.Background(), rows[0].detail, rows[0].provenance))
		if narrow {
			err = b.AmendVoIP(context.Background(), 0, "SIP", "late analysis", &types.VoIPMetadata{CallID: "application"})
		} else {
			err = b.UpdateDetail(context.Background(), 0, func(*Detail) error { t.Fatal("base ran an application amendment callback"); return nil })
		}
		require.ErrorIs(t, err, ErrAnalysisPending)
		_, err = b.Finish(context.Background())
		require.ErrorIs(t, err, ErrAnalysisPending)
		require.NoError(t, b.Close())
	}
}
