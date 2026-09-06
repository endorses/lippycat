package offline

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"

	"github.com/klauspost/compress/flate"
)

const compactOverlapBytes = 256 << 10

// One owned block may compress while the builder encodes the next row batch.
// The goroutine never touches files, accounting, or other builder state.
type compactCompressionOverlap struct {
	payload, output []byte
	entries         [compactRows * compactIndexBytes]byte
	header          [compactBlockHeaderBytes]byte
	compressor      *flate.Writer
	done            chan struct{}
	pending         bool
	disk, held      uint64
	count           int
	first           PacketID
	stored          []byte
	err             error
}

func (b *Builder) startCompactCompression(payload []byte, first PacketID, count, columns int) bool {
	c := b.d.compact
	if c.overlapDisabled || len(payload) < 4096 || len(payload) > compactOverlapBytes || count > compactRows || b.d.storage.limits.CacheBytes < 32<<20 {
		return false
	}
	w := c.overlap
	if w == nil {
		held := uint64(2*compactOverlapBytes+compactCompressorMemory) + uint64(reflect.TypeOf(compactCompressionOverlap{}).Size()) + 256
		// Leave a full block-construction allowance alongside optional state.
		// The current row already owns its normal five-record reservation.
		headroom := b.d.storage.limits.MaxRecordBytes + 4096
		if b.d.storage.reserveMemory(context.Background(), held+headroom) != nil {
			return false
		}
		b.d.storage.releaseMemory(headroom)
		compressor, err := flate.NewWriter(io.Discard, flate.BestSpeed)
		if err != nil {
			b.d.storage.releaseMemory(held)
			return false
		}
		w = &compactCompressionOverlap{payload: make([]byte, compactOverlapBytes), output: make([]byte, compactOverlapBytes), compressor: compressor, held: held}
		c.overlap = w
	}
	copy(w.payload, payload)
	w.pending, w.first, w.count, w.err = true, first, count, nil
	w.done = make(chan struct{})
	clear(w.entries[:])
	clear(w.header[:])
	copy(w.header[:], "LCB2")
	binary.LittleEndian.PutUint16(w.header[4:], 1)
	binary.LittleEndian.PutUint16(w.header[6:], compactBlockHeaderBytes)
	binary.LittleEndian.PutUint64(w.header[8:], uint64(first))
	binary.LittleEndian.PutUint32(w.header[16:], uint32(count))
	binary.LittleEndian.PutUint16(w.header[20:], uint16(columns))
	binary.LittleEndian.PutUint64(w.header[24:], uint64(len(payload)))
	binary.LittleEndian.PutUint64(w.header[32:], 1)
	n := len(payload)
	go func() {
		defer close(w.done)
		raw := w.payload[:n]
		digest := sha256.Sum256(raw)
		copy(w.header[40:], digest[:])
		output := compactCompressionBuffer{data: w.output[:0:n]}
		w.compressor.Reset(&output)
		_, err := w.compressor.Write(raw)
		err = errors.Join(err, w.compressor.Close())
		w.compressor.Reset(io.Discard)
		w.stored = raw
		if errors.Is(err, errCompactCompressionFull) {
			return
		}
		if err != nil {
			w.err = err
			return
		}
		if len(output.data) < n {
			w.stored = output.data
			binary.LittleEndian.PutUint16(w.header[22:], 1)
		}
	}()
	return true
}

// Called only by the serialized builder owner, including its strong barriers.
func (b *Builder) finishCompactCompression() (finishErr error) {
	defer func() {
		if finishErr != nil {
			b.failure = finishErr
		}
	}()
	if b.failure != nil {
		return b.failure
	}
	if b.d.compact == nil {
		return nil
	}
	w := b.d.compact.overlap
	if w == nil || !w.pending {
		return nil
	}
	<-w.done
	w.pending = false
	if w.err != nil {
		return w.err
	}
	b.d.storage.releaseDisk(w.disk)
	w.disk = 0
	off, err := b.d.summaries.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if err = b.write(b.d.summaries, w.header[:]); err != nil {
		return err
	}
	if err = b.write(b.d.summaries, w.stored); err != nil {
		return err
	}
	size := uint64(compactBlockHeaderBytes + len(w.stored))
	checksums := compactScanReader{dataset: b.d, held: w.held}
	for i := 0; i < w.count; i++ {
		entry := w.entries[i*compactIndexBytes : (i+1)*compactIndexBytes]
		binary.LittleEndian.PutUint64(entry, uint64(off))
		binary.LittleEndian.PutUint64(entry[8:], size)
		checksum, e := checksums.IndexChecksum(entry[:32], w.first+PacketID(i))
		if e != nil {
			return e
		}
		copy(entry[32:], checksum[:])
	}
	if err = b.write(b.d.offsets, w.entries[:w.count*compactIndexBytes]); err != nil {
		return err
	}
	b.summaryEnd += size
	w.stored = nil
	return nil
}

// Shutdown waits even when cancelled: compression owns bounded in-memory input
// and cannot block on the builder mutex, file I/O, or a completion receiver.
func (d *diskDataset) stopCompactCompression() {
	if d.compact == nil {
		return
	}
	w := d.compact.overlap
	if w == nil {
		return
	}
	if w.pending {
		<-w.done
	}
	d.storage.releaseDisk(w.disk)
	d.storage.releaseMemory(w.held)
	d.compact.overlap = nil
	d.compact.overlapDisabled = true
}

// Optional compression state never turns an otherwise admitted writer into a
// memory-budget failure. The owner first commits outstanding work, then retires
// its owned scratch and retries the original admission once.
func (b *Builder) reserveCompactMemory(ctx context.Context, n uint64) error {
	err := b.d.storage.reserveMemory(ctx, n)
	if err == nil || b.d.compact == nil || b.d.compact.overlap == nil {
		return err
	}
	if drainErr := b.finishCompactCompression(); drainErr != nil {
		return drainErr
	}
	b.d.stopCompactCompression()
	return b.d.storage.reserveMemory(ctx, n)
}
