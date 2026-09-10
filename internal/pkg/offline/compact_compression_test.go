package offline

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func compactCompressedFixture(t *testing.T) (*Storage, *diskDataset, Detail) {
	t.Helper()
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 32 << 20
	s.limits.MaxRecordBytes = 512 << 10
	detail.Packet.Info = strings.Repeat("repeated searchable text ", 8)
	for i := 0; i < 128; i++ {
		detail.Source.Sequence = uint64(i)
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	d := dataset.(*diskDataset)
	t.Cleanup(func() { require.NoError(t, d.Close()) })
	refs, err := d.compactOffsets(0)
	require.NoError(t, err)
	var header [compactBlockHeaderBytes]byte
	_, err = d.summaries.ReadAt(header[:], int64(refs[0]))
	require.NoError(t, err)
	require.EqualValues(t, 1, binary.LittleEndian.Uint16(header[22:]))
	require.Greater(t, binary.LittleEndian.Uint64(header[24:]), refs[1]-compactBlockHeaderBytes)
	require.Nil(t, d.compact.compressor, "completion releases compressor state")
	s.discardDatasetCache(d)
	return s, d, detail
}

func TestCompactCompressionSchemaMinorRejection(t *testing.T) {
	for _, minor := range []uint16{0, 1, 3, 65535} {
		t.Run(fmt.Sprintf("minor-%d", minor), func(t *testing.T) {
			s, b, detail, provenance := compactReviewBuilder(t)
			require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
			var encoded [2]byte
			binary.LittleEndian.PutUint16(encoded[:], minor)
			_, err := b.d.summaries.WriteAt(encoded[:], 10)
			require.NoError(t, err)
			_, err = b.Finish(context.Background())
			require.ErrorContains(t, err, "header/version")
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
			require.NoError(t, b.Close())
			require.Zero(t, s.Resources().DiskBytes)
			require.Zero(t, s.Resources().InFlightBytes)
		})
	}
}

func TestCompactCompressionFailedBuildReleasesBuffers(t *testing.T) {
	s, b, detail, provenance := compactReviewBuilder(t)
	s.limits.CacheBytes = 32 << 20
	s.limits.MaxRecordBytes = 512 << 10
	for i := 0; i < 128; i++ {
		require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	}
	require.NoError(t, b.flushCompact())
	c := b.d.compact
	require.NotNil(t, c.compressor)
	require.NotEmpty(t, c.blockBuffer)
	require.NotEmpty(t, c.compressionBuffer)
	require.NoError(t, b.AppendCompact(context.Background(), detail, provenance))
	// Buffered disk admission is released at flush. Leave no space beyond the
	// already-written files so the next physical write fails after buffer reuse.
	s.limits.DiskBytes = s.Resources().DiskBytes - c.rowDisk
	_, err := b.Finish(context.Background())
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
	require.True(t, os.IsNotExist(err))
	require.NoError(t, b.Close())
	require.Nil(t, c.compressor)
	require.Empty(t, c.blockBuffer)
	require.Empty(t, c.compressionBuffer)
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestCompactCompressionAdmissionAndRawFallback(t *testing.T) {
	t.Run("compressor-admission", func(t *testing.T) {
		s, b, _, _ := compactReviewBuilder(t)
		s.limits.CacheBytes = 16 << 20
		held := s.limits.CacheBytes - s.Resources().InFlightBytes - 1
		require.NoError(t, s.reserveMemory(context.Background(), held))
		defer s.releaseMemory(held)
		before := s.Resources()
		_, _, err := b.compressCompact(make([]byte, 4096))
		require.Error(t, err)
		require.Equal(t, before, s.Resources())
		require.Nil(t, b.d.compact.compressor)
	})
	t.Run("buffer-growth", func(t *testing.T) {
		s, b, _, _ := compactReviewBuilder(t)
		buffer, err := b.compactBuffer(&b.d.compact.blockBuffer, 128)
		require.NoError(t, err)
		buffer[0] = 42
		oldCapacity := cap(buffer)
		held := s.limits.CacheBytes - s.Resources().InFlightBytes - 1
		require.NoError(t, s.reserveMemory(context.Background(), held))
		defer s.releaseMemory(held)
		before := s.Resources()
		_, err = b.compactBuffer(&b.d.compact.blockBuffer, oldCapacity+1)
		require.Error(t, err)
		require.Equal(t, before, s.Resources())
		require.Equal(t, oldCapacity, cap(b.d.compact.blockBuffer))
		require.EqualValues(t, 42, b.d.compact.blockBuffer[0])
	})
	t.Run("incompressible", func(t *testing.T) {
		s, b, _, _ := compactReviewBuilder(t)
		s.limits.CacheBytes = 16 << 20
		payload := make([]byte, 8192)
		_, err := rand.New(rand.NewSource(42)).Read(payload)
		require.NoError(t, err)
		stored, flags, err := b.compressCompact(payload)
		require.NoError(t, err)
		require.Zero(t, flags)
		require.Equal(t, payload, stored)
		require.Same(t, &payload[0], &stored[0])
		// A writer whose previous bounded output overflowed remains reusable.
		stored, flags, err = b.compressCompact(make([]byte, len(payload)))
		require.NoError(t, err)
		require.EqualValues(t, 1, flags)
		require.Less(t, len(stored), len(payload))
		require.NoError(t, b.Close())
		require.Zero(t, s.Resources().InFlightBytes)
	})
}

func TestCompactCompressedBlockRoundtrip(t *testing.T) {
	s, d, want := compactCompressedFixture(t)
	before := s.Resources().InFlightBytes
	for _, id := range []PacketID{127, 0, 63, 12, 127, 0} {
		got, err := d.Detail(context.Background(), Token{Dataset: 17}, id)
		require.NoError(t, err, "id=%d", id)
		require.Equal(t, want.Packet, got.Packet)
		require.EqualValues(t, id, got.Source.Sequence)
		require.Equal(t, before, s.Resources().InFlightBytes)
	}
	refs, err := d.compactOffsets(0)
	require.NoError(t, err)
	cached := s.cached(cacheKey{dataset: d, id: PacketID(refs[0]), kind: 17})
	require.NotEmpty(t, cached)
	require.Equal(t, refs[1], binary.LittleEndian.Uint64(cached), "cache retains physical reference size")
	require.EqualValues(t, len(cached)-8-compactBlockHeaderBytes, binary.LittleEndian.Uint64(cached[8+24:]), "cache owns expanded block")
	_, held, err := d.compactBlock(context.Background(), d.summaries, refs[0], refs[1]-1, 1, 0)
	require.Error(t, err, "cached expanded block still validates physical reference size")
	require.Zero(t, held)
	require.Equal(t, before, s.Resources().InFlightBytes)
	q, err := AllPackets(context.Background(), d, Token{Dataset: 17, Query: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, q.Close()) })
	count := 0
	err = IterateRaw(context.Background(), q, func(raw RawRecord) error {
		require.EqualValues(t, count, raw.ID)
		require.Equal(t, want.Packet.RawData, raw.RawData)
		require.Equal(t, want.Packet.Timestamp, raw.Timestamp)
		require.Equal(t, want.Packet.LinkType, raw.LinkType)
		count++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 128, count)
}

func TestCompactCompressedBlockMalformedAndBudget(t *testing.T) {
	for _, mode := range []string{"expanded-too-small", "expanded-too-large", "expanded-over-budget", "flags", "truncated", "trailing", "checksum", "read-budget"} {
		t.Run(mode, func(t *testing.T) {
			s, d, _ := compactCompressedFixture(t)
			refs, err := d.compactOffsets(0)
			require.NoError(t, err)
			block := make([]byte, refs[1])
			_, err = d.summaries.ReadAt(block, int64(refs[0]))
			require.NoError(t, err)
			n := binary.LittleEndian.Uint64(block[24:])
			switch mode {
			case "expanded-too-small":
				binary.LittleEndian.PutUint64(block[24:], n-1)
			case "expanded-too-large":
				binary.LittleEndian.PutUint64(block[24:], n+1)
			case "expanded-over-budget":
				binary.LittleEndian.PutUint64(block[24:], s.limits.MaxRecordBytes+1)
			case "flags":
				binary.LittleEndian.PutUint16(block[22:], 2)
			case "truncated":
				block = block[:len(block)-1]
			case "trailing":
				block = append(block, 0)
			case "checksum":
				block[40] ^= 1
			case "read-budget":
				s.limits.CacheBytes = s.Resources().InFlightBytes + 1
			}
			f, err := os.OpenFile(d.summaries.Name(), os.O_RDWR, 0)
			require.NoError(t, err)
			_, err = f.WriteAt(block, int64(refs[0]))
			require.NoError(t, err)
			require.NoError(t, f.Truncate(int64(refs[0])+int64(len(block))))
			require.NoError(t, f.Close())
			before := s.Resources().InFlightBytes
			_, held, err := d.compactBlock(context.Background(), d.summaries, refs[0], uint64(len(block)), 1, 0)
			require.Error(t, err)
			require.Zero(t, held)
			require.Equal(t, before, s.Resources().InFlightBytes)
			require.Zero(t, s.Resources().CachedBytes)
		})
	}
}

func TestCompactCompressionPreservesStandardDeflateCompatibility(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	s.limits.CacheBytes = 32 << 20
	payload := bytes.Repeat([]byte("schema-2 compatible column payload\x00"), 512)
	var legacy bytes.Buffer
	writer, err := flate.NewWriter(&legacy, flate.BestSpeed)
	require.NoError(t, err)
	_, err = writer.Write(payload)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	current, flags, err := b.compressCompact(payload)
	require.NoError(t, err)
	require.EqualValues(t, 1, flags)
	for _, compressed := range [][]byte{legacy.Bytes(), current} {
		block := append(make([]byte, compactBlockHeaderBytes), compressed...)
		decoded, err := inflateCompact(block, uint64(len(payload)))
		require.NoError(t, err)
		require.Equal(t, payload, decoded[compactBlockHeaderBytes:])
		_, err = inflateCompact(append(block, 0), uint64(len(payload)))
		require.Error(t, err, "both codecs reject trailing bytes")
	}
}
