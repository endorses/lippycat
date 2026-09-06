package offline

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompactRecordedEndsMatchFrozenCodec(t *testing.T) {
	for presence := 0; presence < 256; presence++ {
		for _, length := range []int{0, 25, 4000} {
			r := compactRow{Info: strings.Repeat("x", length), Timestamp: time.Unix(-15, 999999999), Derived: true, Locator: Locator{Offset: 1234, Digest: [32]byte{1, 2}}, Projection: compactProjection{Presence: uint8(presence), User: "alice", SNI: "host.test", Host: "host.test", QueryName: "dns.test", ContentLength: -1}}
			ends := make([]uint32, len(compactRowWires))
			got, err := encodeCompactRowWithEnds(&r, 1<<20, 16, make([]byte, 0, 1024), ends)
			want, wantErr := encodeCompactValue(r, 1<<20)
			require.Equal(t, wantErr == nil, err == nil)
			if err != nil {
				continue
			}
			require.Equal(t, append(make([]byte, 16), want...), got)
			parts, err := compactSplitRow(1, got, 1<<20)
			require.NoError(t, err)
			start := uint32(0)
			for i, end := range ends {
				require.Equal(t, parts[i], got[start:end])
				start = end
			}
			require.EqualValues(t, len(got), start)
			for _, budget := range []uint64{compactRowMemory - 1, compactRowMemory, 1024, 8192} {
				_, a := encodeCompactRowWithEnds(&r, budget, 16, make([]byte, 0, 1024), ends)
				_, b := encodeCompactRow(&r, budget, 16)
				require.Equal(t, a == nil, b == nil)
			}
		}
	}
}

func TestCompactRecordedBlocksMatchParsedBlocks(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	s.limits.MaxRecordBytes = 1 << 20
	var rows [][]byte
	var allEnds []uint32
	for i := range compactRows {
		row := compactRow{Info: strings.Repeat("row", i), Projection: compactProjection{Presence: uint8(i % 32), User: "alice", QueryName: "dns.test"}}
		ends := make([]uint32, len(compactRowWires))
		encoded, err := encodeCompactRowWithEnds(&row, s.limits.MaxRecordBytes, 16, nil, ends)
		require.NoError(t, err)
		rows = append(rows, encoded)
		allEnds = append(allEnds, ends...)
	}
	off, size, err := b.writeCompactBlock(b.d.summaries, 1, 0, rows)
	require.NoError(t, err)
	off2, size2, err := b.writeCompactBlockWithEnds(b.d.summaries, 1, 0, rows, allEnds)
	require.NoError(t, err)
	require.Equal(t, size, size2)
	first, second := make([]byte, size), make([]byte, size2)
	_, err = b.d.summaries.ReadAt(first, int64(off))
	require.NoError(t, err)
	_, err = b.d.summaries.ReadAt(second, int64(off2))
	require.NoError(t, err)
	require.True(t, bytes.Equal(first, second))
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactRecordedEndsReleasedAfterFailedFlush(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	s.limits.MaxRecordBytes = 1 << 20
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.NotEmpty(t, b.d.compact.rowEnds)
	require.NoError(t, b.d.summaries.Close())
	require.Error(t, b.flushCompact())
	require.Error(t, b.Close())
	require.Nil(t, b.d.compact.rowEnds)
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactRecordedEndsWaitForEmptyBlockAfterPoolPressure(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	s.limits.MaxRecordBytes = 1 << 20
	rowScratch := s.limits.MaxRecordBytes*5 + 4096
	held, err := s.ReserveTransient(context.Background(), s.MemoryLimit()-s.Resources().InFlightBytes-rowScratch-(64<<10))
	require.NoError(t, err)
	detail.Packet.Info = "before-pool"
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.Nil(t, b.d.compact.rowEnds)
	require.NoError(t, held.Close())
	detail.Packet.Info = "after-pressure"
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.Nil(t, b.d.compact.rowEnds, "pending rows were encoded without boundaries")
	for i := 2; i <= compactRows; i++ {
		detail.Source.Sequence = uint64(i)
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NotEmpty(t, b.d.compact.rowEnds, "pool may initialize after the first block flush")
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	first, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	require.Equal(t, "before-pool", first.Packet.Info)
	last, err := dataset.Detail(context.Background(), Token{Dataset: 17}, PacketID(compactRows))
	require.NoError(t, err)
	require.EqualValues(t, compactRows, last.Source.Sequence)
	require.NoError(t, dataset.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}
