package offline

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func compactQueryFixture(t *testing.T, count int) *diskDataset {
	t.Helper()
	storage, builder, detail, provenance := compactReviewBuilder(t)
	storage.limits.DiskBytes = 64 << 20
	for i := 0; i < count; i++ {
		detail.Source.Sequence = uint64(i)
		detail.Packet.SrcIP = "::ffff:192.0.2.1"
		detail.Packet.DstIP = "198.51.100.2"
		detail.Packet.SrcPort = "5060"
		detail.Packet.DstPort = "5061"
		detail.Packet.Info = fmt.Sprintf("record-%d", i)
		detail.Packet.NodeID = "node-a"
		detail.Packet.VoIPData = nil
		if i%3 == 0 {
			detail.Packet.VoIPData = &types.VoIPMetadata{User: "alice"}
		}
		require.NoError(t, builder.AppendCompact(context.Background(), detail, provenance))
	}
	if count > 1000 {
		require.NoError(t, builder.UpdateDetail(context.Background(), 1000, func(d *Detail) error {
			d.Packet.Info = "amended"
			d.Packet.VoIPData = &types.VoIPMetadata{User: "alice"}
			return nil
		}))
	}
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	return d
}

func TestCompactQueryRepresentationsPagesPinsAndStatistics(t *testing.T) {
	d := compactQueryFixture(t, 2051)
	for _, kind := range []string{"sparse", "dense", "all", "implicit", "expression", "amended"} {
		t.Run(kind, func(t *testing.T) {
			spec := QuerySpec{Token: Token{Dataset: 17, Query: 2}}
			switch kind {
			case "sparse":
				spec.Match = func(s Summary) bool { return s.ID%127 == 0 }
			case "dense":
				spec.Match = func(s Summary) bool { return s.ID%7 != 0 }
			case "all":
				spec.Match = func(Summary) bool { return true }
			case "expression":
				var err error
				spec.Expression, err = NewExpression(ExpressionSpec{Op: "equal", Fields: []string{"sip.user"}, Text: "alice"})
				require.NoError(t, err)
			case "amended":
				var err error
				spec.Expression, err = NewExpression(ExpressionSpec{Op: "equal", Fields: []string{"info"}, Text: "amended"})
				require.NoError(t, err)
			}
			var want []PacketID
			stats := newStatisticsAccumulator()
			for id := PacketID(0); uint64(id) < d.count; id++ {
				summary, held, err := d.readSummary(context.Background(), id)
				require.NoError(t, err)
				if (spec.Match == nil || spec.Match(summary)) && (spec.Expression == nil || spec.Expression.Match(summary)) {
					want = append(want, id)
					stats.Add(summary)
				}
				d.storage.releaseMemory(held)
			}
			baseline := d.Resources().DiskBytes
			baselineMemory := d.Resources().InFlightBytes
			query, err := d.Query(context.Background(), spec)
			require.NoError(t, err)
			q := query.(*diskQuery)
			require.EqualValues(t, len(want), q.Count())
			require.Equal(t, stats.Snapshot(), q.Statistics())
			if kind == "all" || kind == "implicit" {
				require.True(t, q.identity)
				require.Empty(t, q.path)
				require.Equal(t, baseline, d.Resources().DiskBytes)
			} else {
				require.False(t, q.identity)
			}
			random := rand.New(rand.NewSource(71))
			for j := 0; j < 20; j++ {
				start := random.Intn(len(want))
				page, err := q.Page(context.Background(), PageRequest{Token: spec.Token, Row: uint64(start), Limit: 13, MaxBytes: 1 << 20})
				require.NoError(t, err)
				for i, row := range page.Rows {
					require.Equal(t, want[start+i], row.ID)
				}
				require.NoError(t, page.Close())
			}
			pin, err := PinQuery(q)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- q.Close() }()
			var ids []PacketID
			require.NoError(t, pin.IterateRaw(context.Background(), func(r RawRecord) error { ids = append(ids, r.ID); return nil }))
			require.Equal(t, want, ids)
			require.NoError(t, pin.Close())
			require.NoError(t, <-done)
			require.Equal(t, baseline, d.Resources().DiskBytes)
			require.Equal(t, baselineMemory, d.Resources().InFlightBytes)
		})
	}
}

func TestCompactQueryCancellationAndBufferedDiskAdmission(t *testing.T) {
	d := compactQueryFixture(t, 2051)
	old, err := AllPackets(context.Background(), d, Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	defer func() { require.NoError(t, old.Close()) }()
	baseline := d.Resources().DiskBytes
	baselineMemory := d.Resources().InFlightBytes
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q, err := d.Query(ctx, QuerySpec{Token: Token{Dataset: 17, Query: 2}, Match: func(Summary) bool { return true }, Progress: func(p QueryProgress) {
		if p.Scanned == 1024 {
			cancel()
		}
	}})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, q)
	require.Equal(t, baseline, d.Resources().DiskBytes)
	require.Equal(t, baselineMemory, d.Resources().InFlightBytes)
	diskLimit := d.storage.limits.DiskBytes
	d.storage.limits.DiskBytes = baseline + queryHeaderBytes + queryEntryBytes*5
	q, err = d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 17, Query: 3}, Match: func(s Summary) bool { return s.ID != 100 }})
	d.storage.limits.DiskBytes = diskLimit
	require.Error(t, err)
	require.Nil(t, q)
	require.Equal(t, baseline, d.Resources().DiskBytes)
	page, err := old.Page(context.Background(), PageRequest{Token: old.Token(), Limit: 1, MaxBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, page.Close())
	files, err := os.ReadDir(d.dir)
	require.NoError(t, err)
	for _, file := range files {
		require.NotContains(t, file.Name(), "query-")
	}
}

func TestCompactRelatedTypedComparison(t *testing.T) {
	d := compactQueryFixture(t, 4)
	for _, tc := range []struct {
		flow  Flow
		count uint64
	}{
		{Flow{Source: netip.MustParseAddrPort("192.0.2.1:5060"), Destination: netip.MustParseAddrPort("198.51.100.2:5061"), Transport: 17}, 4},
		{Flow{Source: netip.MustParseAddrPort("198.51.100.2:5061"), Destination: netip.MustParseAddrPort("[::ffff:192.0.2.1]:5060"), Node: "node-a"}, 4},
		{Flow{Source: netip.MustParseAddrPort("192.0.2.1:5060"), Destination: netip.MustParseAddrPort("198.51.100.2:5061"), Node: "other"}, 0},
		{Flow{Source: netip.MustParseAddrPort("192.0.2.1:0"), Destination: netip.MustParseAddrPort("198.51.100.2:5061")}, 0},
		{Flow{}, 0},
	} {
		q, err := d.Related(context.Background(), Token{Dataset: 17, Query: 2}, tc.flow)
		require.NoError(t, err)
		require.Equal(t, tc.count, q.Count())
		require.NoError(t, q.Close())
	}
}

func TestCompactAllMatchNeedsNoQueryDiskAndLateMissMaterializesPrefix(t *testing.T) {
	d := compactQueryFixture(t, 33)
	baseline := d.Resources().DiskBytes
	diskLimit := d.storage.limits.DiskBytes
	d.storage.limits.DiskBytes = baseline
	for _, expression := range []bool{false, true} {
		spec := QuerySpec{Token: Token{Dataset: 17, Query: 1}, Match: func(Summary) bool { return true }}
		if expression {
			var err error
			spec.Expression, err = NewExpression(ExpressionSpec{Op: "all"})
			require.NoError(t, err)
		}
		q, err := d.Query(context.Background(), spec)
		require.NoError(t, err)
		require.True(t, q.(*diskQuery).identity)
		require.Equal(t, baseline, d.Resources().DiskBytes)
		require.NoError(t, q.Close())
	}
	d.storage.limits.DiskBytes = diskLimit
	q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 17, Query: 2}, Match: func(s Summary) bool { return s.ID != 32 }})
	require.NoError(t, err)
	require.EqualValues(t, 32, q.Count())
	page, err := q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 33, MaxBytes: 1 << 20})
	require.NoError(t, err)
	require.Len(t, page.Rows, 32)
	for i, row := range page.Rows {
		require.EqualValues(t, i, row.ID)
	}
	require.NoError(t, page.Close())
	require.NoError(t, q.Close())
}

func TestCompactQueryRejectsCorruptDirectoryAndReleasesScratch(t *testing.T) {
	d := compactQueryFixture(t, 33)
	baseline := d.Resources()
	writable, err := os.OpenFile(d.offsets.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = writable.WriteAt([]byte{255}, compactHeaderBytes+17*compactIndexBytes)
	require.NoError(t, err)
	require.NoError(t, writable.Close())
	q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 17, Query: 1}, Match: func(s Summary) bool { return s.ID%2 == 0 }})
	require.ErrorContains(t, err, "checksum")
	require.Nil(t, q)
	require.Equal(t, baseline.DiskBytes, d.Resources().DiskBytes)
	require.Equal(t, baseline.InFlightBytes, d.Resources().InFlightBytes)
}
