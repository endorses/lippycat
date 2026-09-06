package offline

import (
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"io"

	fastflate "github.com/klauspost/compress/flate"
)

// BestSpeed's window, hash table, tokens and Huffman state fit within this
// conservative reservation. One writer is reused per builder, never per row.
const compactCompressorMemory = 2 << 20
const compactInflaterMemory = 256 << 10

var errCompactCompressionFull = errors.New("compact compression does not shrink block")

type compactCompressionBuffer struct{ data []byte }

func (w *compactCompressionBuffer) Write(p []byte) (int, error) {
	if len(p) > cap(w.data)-len(w.data) {
		return 0, errCompactCompressionFull
	}
	w.data = append(w.data, p...)
	return len(p), nil
}

// Compression is optional for small budgets and blocks. Its output cannot grow
// past the admitted payload capacity; incompressible blocks keep raw columns.
func (b *Builder) compressCompact(payload []byte) ([]byte, uint16, error) {
	c := b.d.compact
	if len(payload) < 4096 || b.d.storage.limits.CacheBytes < 16<<20 {
		return payload, 0, nil
	}
	if c.compressor == nil {
		if err := b.reserveCompactMemory(context.Background(), compactCompressorMemory); err != nil {
			return nil, 0, err
		}
		w, err := fastflate.NewWriter(io.Discard, fastflate.BestSpeed)
		if err != nil {
			b.d.storage.releaseMemory(compactCompressorMemory)
			return nil, 0, err
		}
		c.compressor = w
	}
	buffer, err := b.compactBuffer(&c.compressionBuffer, len(payload))
	if err != nil {
		return nil, 0, err
	}
	w := &compactCompressionBuffer{data: buffer[:0:len(payload)]}
	c.compressor.Reset(w)
	_, err = c.compressor.Write(payload)
	err = errors.Join(err, c.compressor.Close())
	c.compressor.Reset(io.Discard) // Do not retain the output after admission ends.
	if errors.Is(err, errCompactCompressionFull) {
		return payload, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if len(w.data) >= len(payload) {
		return payload, 0, nil
	}
	return w.data, 1, nil
}

// Reuse bounded block buffers, charging new capacity before growth and retaining
// its charge until finalization. Input rows never alias either scratch buffer.
func (b *Builder) compactBuffer(target *[]byte, n int) ([]byte, error) {
	if cap(*target) < n {
		capacity := n
		if uint64(n) <= b.d.storage.limits.MaxRecordBytes/2 {
			capacity = n * 2
		}
		if err := b.reserveCompactMemory(context.Background(), uint64(capacity)); err != nil {
			return nil, err
		}
		buffer := make([]byte, capacity)
		b.d.storage.releaseMemory(uint64(cap(*target)))
		*target = buffer
	}
	return (*target)[:n], nil
}

func (d *diskDataset) releaseCompactBuffers() {
	d.stopCompactCompression()
	c := d.compact
	d.storage.releaseMemory(uint64(cap(c.blockBuffer)+cap(c.compressionBuffer)+cap(c.rowPool)) + uint64(cap(c.columnEnds)+cap(c.rowEnds))*4)
	c.blockBuffer, c.compressionBuffer, c.columnEnds, c.rowPool, c.rowEnds = nil, nil, nil, nil, nil
}

func (d *diskDataset) releaseCompactCompressor() {
	if d.compact.compressor != nil {
		d.compact.compressor = nil
		d.storage.releaseMemory(compactCompressorMemory)
	}
}

// Decode into a pre-admitted exact-size allocation. Read one additional byte
// to reject both expansion beyond the header and incomplete DEFLATE trailers.
func inflateCompact(p []byte, n uint64) ([]byte, error) {
	source := bytes.NewReader(p[compactBlockHeaderBytes:])
	r := flate.NewReader(source)
	result := make([]byte, compactBlockHeaderBytes+int(n))
	copy(result, p[:compactBlockHeaderBytes])
	_, err := io.ReadFull(r, result[compactBlockHeaderBytes:])
	if err == nil {
		var extra [1]byte
		count, tailErr := r.Read(extra[:])
		if count != 0 || tailErr != io.EOF || source.Len() != 0 {
			err = errors.New("compact invalid compressed payload length")
		}
	}
	return result, errors.Join(err, r.Close())
}
