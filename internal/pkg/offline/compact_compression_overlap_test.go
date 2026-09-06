package offline

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactCompressionOverlapMatchesSerialFiles(t *testing.T) {
	var streams [][]byte
	for _, serial := range []bool{true, false} {
		s, b, detail, provenance := compactReviewBuilder(t)
		s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
		b.d.compact.overlapDisabled = serial
		for i := 0; i < compactRows*3+5; i++ {
			detail.Packet.Info = fmt.Sprintf("row-%d", i)
			detail.Source.Sequence = uint64(i)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
		}
		if !serial {
			require.NotNil(t, b.d.compact.overlap)
			require.True(t, b.d.compact.overlap.pending)
		}
		require.NoError(t, b.flushCompact())
		for j, f := range []*os.File{b.d.summaries, b.d.details, b.d.offsets} {
			got, err := os.ReadFile(f.Name())
			require.NoError(t, err)
			if serial {
				streams = append(streams, got)
			} else {
				require.Equal(t, streams[j], got)
			}
		}
		dataset, err := b.Finish(context.Background())
		require.NoError(t, err)
		require.Nil(t, b.d.compact.overlap)
		require.NoError(t, dataset.Close())
		require.Zero(t, s.Resources().InFlightBytes)
	}
}

func TestCompactCompressionOverlapEmptyBatchBarrierAndClose(t *testing.T) {
	for _, finish := range []bool{false, true} {
		s, b, detail, provenance := compactReviewBuilder(t)
		s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
		for range compactRows {
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
		}
		require.NoError(t, b.queueCompactRows())
		require.Empty(t, b.d.compact.rows)
		require.True(t, b.d.compact.overlap.pending)
		if finish {
			d, err := b.Finish(context.Background())
			require.NoError(t, err)
			_, err = d.Detail(context.Background(), Token{Dataset: 17}, compactRows-1)
			require.NoError(t, err)
			require.NoError(t, d.Close())
		} else {
			require.NoError(t, b.Close())
		}
		require.Zero(t, s.Resources().InFlightBytes)
		require.Zero(t, s.Resources().DiskBytes)
	}
}

func TestCompactCompressionOverlapOwnsInputAndRawFallback(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	raw := make([]byte, 8192)
	// Deterministic pseudo-random bytes defeat BestSpeed compression.
	var x uint32 = 123
	for i := range raw {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		raw[i] = byte(x)
	}
	want := bytes.Clone(raw)
	require.True(t, b.startCompactCompression(raw, 0, 1, 1))
	clear(raw)
	w := b.d.compact.overlap
	<-w.done
	require.NoError(t, w.err)
	require.Equal(t, want, w.stored)
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactCompressionOverlapPendingWriteFailure(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.queueCompactRows())
	require.NoError(t, b.d.summaries.Close())
	_, err := b.Finish(context.Background())
	require.Error(t, err)
	firstErr := err
	_, err = b.Finish(context.Background())
	require.Equal(t, firstErr, err)
	require.Equal(t, firstErr, b.AppendCompact(context.Background(), detail, provenance))
	require.Error(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
	require.Zero(t, s.Resources().DiskBytes)
}

func TestCompactCompressionOverlapRetiresUnderRowPressure(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.queueCompactRows())
	w := b.d.compact.overlap
	require.NotNil(t, w)
	rowScratch := s.limits.MaxRecordBytes*5 + 4096
	held, err := s.ReserveTransient(context.Background(), s.MemoryLimit()-s.Resources().InFlightBytes-rowScratch+w.held/2)
	require.NoError(t, err)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.Nil(t, b.d.compact.overlap)
	require.True(t, b.d.compact.overlapDisabled)
	require.NoError(t, held.Close())
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, compactRows+1, d.Count())
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactCompressionOverlapCancelledFinishJoinsOnClose(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.queueCompactRows())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.Finish(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().InFlightBytes)
	require.Zero(t, s.Resources().DiskBytes)
}

func TestCompactCompressionOverlapAmendmentBarrier(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows + 1 {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.True(t, b.d.compact.overlap.pending)
	require.NoError(t, b.AmendVoIP(context.Background(), 0, "SIP", "finalized", &types.VoIPMetadata{CallID: "call"}))
	require.Nil(t, b.d.compact.overlap)
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	got, err := d.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	require.Equal(t, "finalized", got.Packet.Info)
	require.Equal(t, "call", got.Packet.VoIPData.CallID)
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactCompressionOverlapDrainsBeforeDiskRejection(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.queueCompactRows())
	require.Positive(t, b.d.compact.overlap.disk)
	held := s.limits.DiskBytes - s.Resources().DiskBytes
	require.NoError(t, s.reserveDisk(held))
	// The pending block's pessimistic reservation is sufficient to commit its
	// actual compressed bytes and the new row even with no initially free disk.
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.False(t, b.d.compact.overlap.pending)
	s.releaseDisk(held)
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactCompressionOverlapMetadataTransition(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes, s.limits.MaxRecordBytes = 64<<20, 1<<20
	for range compactRows + 1 {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.True(t, b.d.compact.overlap.pending)
	detail.Packet.VoIPData = &types.VoIPMetadata{CallID: "retained-override"}
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	require.False(t, b.d.compact.overlap.pending)
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	got, err := d.Detail(context.Background(), Token{Dataset: 17}, compactRows+1)
	require.NoError(t, err)
	require.Equal(t, "retained-override", got.Packet.VoIPData.CallID)
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}
