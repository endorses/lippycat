package offline

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactScanReaderDetailsHeaderCache(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	for i := 0; i < 3; i++ {
		detail.Source.Sequence = uint64(i)
		detail.Packet.VoIPData = &types.VoIPMetadata{User: "synthetic"}
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.UpdateDetail(context.Background(), 1, func(d *Detail) error {
		d.Packet.VoIPData = &types.VoIPMetadata{User: "amended"}
		return nil
	}))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	baseline := s.Resources().InFlightBytes
	r, err := newCompactScanReader(context.Background(), d)
	require.NoError(t, err)
	reservation := s.limits.MaxRecordBytes*3 + compactBlockHeaderBytes*4 + 1024 + uint64(unsafe.Sizeof([compactDetailsHeaderCacheSlots]compactScanHeader{}))
	require.Equal(t, baseline+reservation, s.Resources().InFlightBytes)
	entries := make([][compactIndexBytes]byte, 3)
	for id := range entries {
		_, err := d.offsets.ReadAt(entries[id][:], compactHeaderBytes+int64(id)*compactIndexBytes)
		require.NoError(t, err)
		require.NotZero(t, binary.LittleEndian.Uint64(entries[id][16:24]))
	}
	for _, id := range []PacketID{0, 1, 2, 0, 1, 2} {
		got, err := r.IndexChecksum(entries[id][:32], id)
		require.NoError(t, err)
		require.Equal(t, entries[id][32:], got[:])
	}
	// Three distinct details blocks, including the amendment, were read once
	// each despite alternating references after the cache was populated.
	require.EqualValues(t, 3, r.nextDetail)
	var cached int
	for _, header := range r.detailHeaders {
		if header.valid {
			cached++
		}
	}
	require.Equal(t, 3, cached)
	require.NoError(t, r.Close())
	require.Equal(t, baseline, s.Resources().InFlightBytes)

	// A fresh scan must authenticate a header corrupted before its first use.
	r, err = newCompactScanReader(context.Background(), d)
	require.NoError(t, err)
	off := binary.LittleEndian.Uint64(entries[1][16:24])
	writable, err := os.OpenFile(d.details.Name(), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = writable.WriteAt([]byte{0xff}, int64(off)+40)
	require.NoError(t, err)
	require.NoError(t, writable.Close())
	got, err := r.IndexChecksum(entries[1][:32], 1)
	require.NoError(t, err)
	require.NotEqual(t, entries[1][32:], got[:])
	_, err = r.Read(context.Background(), d.details, off, binary.LittleEndian.Uint64(entries[1][24:32]), 4, 1)
	require.ErrorContains(t, err, "checksum")
	require.NoError(t, r.Close())
	require.Equal(t, baseline, s.Resources().InFlightBytes)
}

func TestCompactScanReaderDetailsCacheAdmission(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	baseline := s.Resources().InFlightBytes
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = newCompactScanReader(cancelled, d)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, baseline, s.Resources().InFlightBytes)
	reservation := s.limits.MaxRecordBytes*3 + compactBlockHeaderBytes*4 + 1024 + uint64(unsafe.Sizeof([compactDetailsHeaderCacheSlots]compactScanHeader{}))
	s.limits.CacheBytes = baseline + reservation - 1
	_, err = newCompactScanReader(context.Background(), d)
	require.ErrorContains(t, err, "budget exhausted")
	require.Equal(t, baseline, s.Resources().InFlightBytes)
}

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
