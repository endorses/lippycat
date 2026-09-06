package offline

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestAsyncCompactWriterSnapshotBarrierAndAmendment(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	w, err := NewAsyncCompactWriter(context.Background(), s, b)
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()
	originalRaw := cloneCompactSlice(detail.Packet.RawData)
	for i := 0; i < 140; i++ {
		detail.Source.Sequence = uint64(i)
		detail.Packet.TLSData = &types.TLSMetadata{SNI: "original", CipherSuites: []uint16{1}, ALPNProtocols: []string{}}
		require.NoError(t, w.Append(detail, provenance))
		// Mutation after Append must never race with or change the worker's snapshot.
		detail.Packet.TLSData.SNI = "changed"
		detail.Packet.TLSData.CipherSuites[0] = 99
		if len(detail.Packet.RawData) > 0 {
			detail.Packet.RawData[0] ^= 1
			copy(detail.Packet.RawData, originalRaw)
		}
	}
	require.NoError(t, w.Drain())
	require.NoError(t, b.AmendVoIP(context.Background(), 0, "SIP", "finalized", &types.VoIPMetadata{CallID: "call"}))
	require.NoError(t, w.Close())
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, dataset.Close()) }()
	for _, id := range []PacketID{0, 1, 139} {
		got, err := dataset.Detail(context.Background(), Token{Dataset: 17}, id)
		require.NoError(t, err)
		require.EqualValues(t, id, got.Source.Sequence)
		require.Equal(t, originalRaw, got.Packet.RawData)
		require.Equal(t, "original", got.Packet.TLSData.SNI)
		require.Equal(t, []uint16{1}, got.Packet.TLSData.CipherSuites)
		require.NotNil(t, got.Packet.TLSData.ALPNProtocols)
		if id == 0 {
			require.Equal(t, "call", got.Packet.VoIPData.CallID)
		}
	}
}

func TestAsyncCompactWriterFailureCancellationAndSmallCache(t *testing.T) {
	t.Run("small-cache", func(t *testing.T) {
		s, b, _, _ := compactReviewBuilder(t)
		s.limits.CacheBytes = 128 << 10
		before := s.Resources()
		w, err := NewAsyncCompactWriter(context.Background(), s, b)
		require.NoError(t, err)
		require.Nil(t, w)
		require.Equal(t, before, s.Resources())
	})
	for _, cancelParent := range []bool{false, true} {
		name := "builder-error"
		if cancelParent {
			name = "cancel-parent"
		}
		t.Run(name, func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			s.limits.CacheBytes = 64 << 20
			baseline := s.Resources().InFlightBytes
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w, err := NewAsyncCompactWriter(ctx, s, b)
			require.NoError(t, err)
			if cancelParent {
				cancel()
			} else {
				provenance.Locator.Digest[0] ^= 1
			}
			err = w.Append(detail, provenance)
			if cancelParent {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.NoError(t, err)
				require.Error(t, w.Drain())
			}
			closeErr := w.Close()
			if !cancelParent {
				require.ErrorContains(t, closeErr, "locator")
			}
			require.Equal(t, baseline, s.Resources().InFlightBytes)
			require.Error(t, w.Append(detail, provenance))
			require.Error(t, w.Drain())
			require.NoError(t, b.Close())
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestAsyncCompactWriterLargeRecordMatchesSynchronous(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	detail.Packet.Info = strings.Repeat("large presentation ", 1500)
	// Establish that the exact same large detail fits the synchronous path.
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	w, err := NewAsyncCompactWriter(context.Background(), s, b)
	require.NoError(t, err)
	require.NotNil(t, w)
	defer func() { require.NoError(t, w.Close()) }()
	detail.Source.Sequence = 1
	require.NoError(t, w.Append(detail, provenance))
	require.NoError(t, w.Close())
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, dataset.Close()) }()
	first, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	second, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 1)
	require.NoError(t, err)
	require.Equal(t, first.Packet, second.Packet)
}

func TestAsyncCompactWriterInsufficientScratchHeadroomUsesSynchronous(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	s.limits.CacheBytes = 32 << 20
	s.limits.MaxRecordBytes = 8 << 20
	before := s.Resources()
	writer, err := NewAsyncCompactWriter(context.Background(), s, b)
	require.NoError(t, err)
	require.Nil(t, writer)
	require.Equal(t, before, s.Resources())
}

func TestAsyncCompactWriterReusesPoisonedRawSlabs(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	original := cloneCompactSlice(detail.Packet.RawData)
	decode := b.d.compact.decode
	b.d.compact.decode = func(ctx context.Context, raw []byte, summary Summary) (types.PacketDisplay, error) {
		if !bytes.Equal(raw, original) || len(raw) != cap(raw) {
			return types.PacketDisplay{}, fmt.Errorf("reused slab exposed stale bytes or excess capacity")
		}
		return decode(ctx, raw, summary)
	}
	w, err := NewAsyncCompactWriter(context.Background(), s, b)
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()
	// Force raw capacity boundaries before the 32-job limit with the small
	// source fixture. The full physical slabs remain conservatively charged.
	w.rawCapacity = 64
	for i := 0; i < 3; i++ {
		batch := <-w.free
		batch.raw = batch.raw[:0:w.rawCapacity]
		w.free <- batch
	}
	for round := 0; round < 4; round++ {
		for i := 0; i < 97; i++ {
			detail.Source.Sequence = uint64(round*97 + i)
			require.NoError(t, w.Append(detail, provenance))
		}
		require.NoError(t, w.Drain())
		// Acquire all free batches after the barrier, poisoning the complete
		// underlying capacities before returning them for the next replay.
		var batches [3]*compactAppendBatch
		for i := range batches {
			batches[i] = <-w.free
			require.Len(t, batches[i].raw, 0)
			require.Equal(t, w.rawCapacity, cap(batches[i].raw))
			for j := range batches[i].raw[:cap(batches[i].raw)] {
				batches[i].raw[:cap(batches[i].raw)][j] = 0xa5
			}
		}
		for _, batch := range batches {
			w.free <- batch
		}
	}
	require.NoError(t, w.Close())
	require.Nil(t, w.free)
	require.Nil(t, w.jobs)
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 388, dataset.Count())
	require.NoError(t, dataset.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}
