package offline

import (
	"context"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactScanReaderReuseIntegrityAndAdmission(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 64 << 20
	for i := 0; i < 2051; i++ {
		detail.Source.Sequence = uint64(i)
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	ctx := context.Background()
	baseline := d.Resources().InFlightBytes
	r, err := newCompactScanReader(ctx, d)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	var firstOff, firstSize uint64
	for _, id := range []PacketID{0, 1000, 2000, 0} {
		var entry [compactIndexBytes]byte
		_, err := d.offsets.ReadAt(entry[:], compactHeaderBytes+int64(id)*compactIndexBytes)
		require.NoError(t, err)
		wantChecksum, err := d.compactIndexChecksum(entry[:32], id)
		require.NoError(t, err)
		gotChecksum, err := r.IndexChecksum(entry[:32], id)
		require.NoError(t, err)
		require.Equal(t, wantChecksum, gotChecksum)
		off, n := binary.LittleEndian.Uint64(entry[:8]), binary.LittleEndian.Uint64(entry[8:16])
		if id == 0 {
			firstOff, firstSize = off, n
		}
		// The independent random path and scan path share wire integrity validation,
		// but use different allocation/decompression/cache implementations.
		want, held, err := d.compactWholeBlock(ctx, d.summaries, off, n, 1, id)
		require.NoError(t, err)
		got, err := r.Read(ctx, d.summaries, off, n, 1, id)
		require.NoError(t, err)
		require.Equal(t, want, got)
		d.storage.releaseMemory(held)
	}
	input, output, inflater := &r.input[0], &r.output[0], r.inflater
	_, err = r.Read(ctx, d.summaries, firstOff, firstSize, 1, 0)
	require.NoError(t, err)
	require.Same(t, input, &r.input[0])
	require.Same(t, output, &r.output[0])
	require.Same(t, inflater, r.inflater)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = r.Read(cancelled, d.summaries, firstOff, firstSize, 1, 0)
	require.ErrorIs(t, err, context.Canceled)
	// A prior cache hit must not hide corrupt source blocks from a sequential scan.
	file, err := os.OpenFile(d.summaries.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte{0xff}, int64(firstOff)+40)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	_, err = r.Read(ctx, d.summaries, firstOff, firstSize, 1, 0)
	require.ErrorContains(t, err, "checksum")
	require.NoError(t, r.Close())
	require.Equal(t, baseline, d.Resources().InFlightBytes)
	_, err = r.Read(ctx, d.summaries, firstOff, firstSize, 1, 0)
	require.ErrorContains(t, err, "closed")
	_, err = newCompactScanReader(cancelled, d)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, baseline, d.Resources().InFlightBytes)
}

func TestCompactSmallCacheUncompressedLifecycle(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 128 << 10
	s.limits.MaxRecordBytes = 16 << 10
	for i := 0; i < 32; i++ {
		detail.Source.Sequence = uint64(i)
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	defer func() { require.NoError(t, d.Close()) }()
	q, err := d.Query(context.Background(), QuerySpec{Token: Token{Dataset: 17, Query: 1}, Match: func(s Summary) bool { return s.ID%3 == 0 }})
	require.NoError(t, err)
	defer func() { require.NoError(t, q.Close()) }()
	require.EqualValues(t, 11, q.Count())
	page, err := q.Page(context.Background(), PageRequest{Token: q.Token(), Limit: 4, MaxBytes: 16 << 10})
	require.NoError(t, err)
	page.Close()
	_, err = d.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	var records int
	require.NoError(t, IterateRaw(context.Background(), q, func(RawRecord) error { records++; return nil }))
	require.Equal(t, 11, records)
}
