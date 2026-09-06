package offline

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactRowIntoPreservesBytesAndBudgets(t *testing.T) {
	buffer := bytes.Repeat([]byte{0xa5}, compactRowSlotBytes)
	for _, length := range []int{0, 10, 1000, 4000, 5} {
		row := compactRow{Info: strings.Repeat("x", length), Projection: compactProjection{Presence: 31, CallID: "call", SNI: "example.test", Host: "example.test"}}
		for _, prefix := range []int{0, 16} {
			want, err := encodeCompactRow(&row, 1<<20, prefix)
			require.NoError(t, err)
			got, err := encodeCompactRowInto(&row, 1<<20, prefix, buffer[:0])
			require.NoError(t, err)
			require.Equal(t, want, got)
			if len(want) <= cap(buffer) {
				require.Same(t, &buffer[0], &got[0])
			} else {
				require.NotSame(t, &buffer[0], &got[0])
			}
		}
		for budget := uint64(0); budget < 8192; budget += 127 {
			_, wantErr := encodeCompactRow(&row, budget, 16)
			_, gotErr := encodeCompactRowInto(&row, budget, 16, buffer[:0])
			require.Equal(t, wantErr == nil, gotErr == nil)
		}
	}
}

func TestCompactRowPoolPreservesRowsAcrossFlushes(t *testing.T) {
	for _, max := range []uint64{64 << 10, 1 << 20} {
		s, b, detail, provenance := compactReviewBuilder(t)
		s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, max
		const count = compactRows*2 + 3
		want := make([]string, count)
		for i := range count {
			want[i] = fmt.Sprintf("row-%d", i)
			if i%7 == 0 {
				want[i] += strings.Repeat("large", 800)
			}
			detail.Packet.Info, detail.Source.Sequence = want[i], uint64(i)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
			require.Len(t, b.d.compact.rowPool, compactRows*compactRowSlotBytes)
		}
		dataset, err := b.Finish(context.Background())
		require.NoError(t, err)
		require.Nil(t, b.d.compact.rowPool, "publication releases construction buffers")
		for i := range count {
			got, err := dataset.Detail(context.Background(), Token{Dataset: 17}, PacketID(i))
			require.NoError(t, err)
			require.Equal(t, want[i], got.Packet.Info)
			require.EqualValues(t, i, got.Source.Sequence)
		}
		require.NoError(t, dataset.Close())
		require.Zero(t, s.Resources().InFlightBytes)
	}
}

func TestCompactRowPoolFallsBackUnderMemoryPressure(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	rowScratch := s.limits.MaxRecordBytes*5 + 4096
	held, err := s.ReserveTransient(context.Background(), s.MemoryLimit()-s.Resources().InFlightBytes-rowScratch-(64<<10))
	require.NoError(t, err)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.Nil(t, b.d.compact.rowPool)
	require.Positive(t, b.d.compact.rowMemory)
	require.NoError(t, held.Close())
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	require.NoError(t, dataset.Close())
	require.Zero(t, s.Resources().InFlightBytes)

	s, b, detail, provenance = compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.Nil(t, b.d.compact.rowPool, "small caches retain the original allocation path")
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactRowPoolFailedFlushReleasesOnCleanup(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.NoError(t, b.d.summaries.Close())
	require.Error(t, b.flushCompact())
	require.Len(t, b.d.compact.rowPool, compactRows*compactRowSlotBytes)
	require.Zero(t, b.d.compact.rowMemory)
	require.Error(t, b.Close(), "injected closed handle remains a cleanup error")
	require.Nil(t, b.d.compact.rowPool)
	require.Zero(t, s.Resources().InFlightBytes)
}

func BenchmarkCompactRowBufferReuse(b *testing.B) {
	row := compactRow{Info: "normal UDP payload", Protocol: "UDP", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprint(reuse), func(b *testing.B) {
			var buffer []byte
			if reuse {
				buffer = make([]byte, 0, compactRowSlotBytes)
			}
			b.ReportAllocs()
			for range b.N {
				if _, err := encodeCompactRowInto(&row, 1<<20, 16, buffer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
