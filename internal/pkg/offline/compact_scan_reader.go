package offline

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"unsafe"
)

const compactDetailsHeaderCacheSlots = 8

type compactScanHeader struct {
	off, size uint64
	data      [compactBlockHeaderBytes]byte
	valid     bool
}

// compactScanReader owns one scan's scratch, avoiding repeated block/cache copies
// and inflater allocations. Returned blocks are borrowed until the next Read.
// The third record allowance admits decoded row strings while both buffers live.
type compactScanReader struct {
	dataset       *diskDataset
	input, output []byte
	source        bytes.Reader
	inflater      io.ReadCloser
	held          uint64
	inflaterHeld  bool
	extra         [1]byte
	headers       [2]compactScanHeader
	detailHeaders *[compactDetailsHeaderCacheSlots]compactScanHeader
	nextDetail    uint8
}

func newCompactScanReader(ctx context.Context, d *diskDataset) (*compactScanReader, error) {
	// The fixed, scan-local cache is allocated only after its full storage
	// admission. Builder checksum readers keep their existing single header.
	held := d.storage.limits.MaxRecordBytes*3 + compactBlockHeaderBytes*4 + 1024 + uint64(unsafe.Sizeof([compactDetailsHeaderCacheSlots]compactScanHeader{}))
	inflaterHeld := d.storage.limits.CacheBytes >= 16<<20
	if inflaterHeld {
		held += compactInflaterMemory
	}
	if err := d.storage.reserveMemory(ctx, held); err != nil {
		return nil, err
	}
	return &compactScanReader{dataset: d, held: held, inflaterHeld: inflaterHeld, detailHeaders: new([compactDetailsHeaderCacheSlots]compactScanHeader)}, nil
}
func (r *compactScanReader) Close() error {
	var err error
	if r.inflater != nil {
		err = r.inflater.Close()
		r.inflater = nil
	}
	r.input, r.output = nil, nil
	r.detailHeaders = nil
	r.source.Reset(nil)
	if r.held != 0 {
		r.dataset.storage.releaseMemory(r.held)
		r.held = 0
	}
	return err
}
func (r *compactScanReader) Read(ctx context.Context, f *os.File, off, size uint64, kind uint16, id PacketID) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.held == 0 {
		return nil, errors.New("compact scan reader closed")
	}
	max := r.dataset.storage.limits.MaxRecordBytes
	if size < 72 || size-72 > max || off < 32 || size > math.MaxInt64 || off > math.MaxInt64-size {
		return nil, errors.New("compact invalid block reference")
	}
	// ReadAt provides the short-read check without a per-block stat syscall.
	if r.input == nil {
		r.input = make([]byte, int(max)+compactBlockHeaderBytes)
	}
	p := r.input[:int(size)]
	if _, err := f.ReadAt(p, int64(off)); err != nil {
		return nil, err
	}
	h := p[:compactBlockHeaderBytes]
	first := binary.LittleEndian.Uint64(h[8:])
	count := uint64(binary.LittleEndian.Uint32(h[16:]))
	columns := int(binary.LittleEndian.Uint16(h[20:]))
	n := binary.LittleEndian.Uint64(h[24:])
	wires, widths, err := compactColumnTypes(kind)
	if err != nil {
		return nil, err
	}
	if string(h[:4]) != "LCB2" || binary.LittleEndian.Uint16(h[4:]) != kind || binary.LittleEndian.Uint16(h[6:]) != 72 || binary.LittleEndian.Uint16(h[22:]) > 1 || binary.LittleEndian.Uint64(h[32:]) != 1 || count == 0 || count > 4096 || first > math.MaxUint64-count || uint64(id) < first || uint64(id)-first >= count || n > max || (binary.LittleEndian.Uint16(h[22:]) == 0 && n != size-72) || columns != len(wires) || uint64(columns)*24 > n {
		return nil, errors.New("compact invalid block header")
	}
	if binary.LittleEndian.Uint16(h[22:]) == 1 {
		if r.output == nil {
			r.output = make([]byte, int(max)+compactBlockHeaderBytes)
		}
		result := r.output[:compactBlockHeaderBytes+int(n)]
		copy(result, h)
		r.source.Reset(p[compactBlockHeaderBytes:])
		if r.inflater == nil {
			if !r.inflaterHeld {
				if err = r.dataset.storage.reserveMemory(ctx, compactInflaterMemory); err != nil {
					return nil, err
				}
				r.held += compactInflaterMemory
				r.inflaterHeld = true
			}
			r.inflater = flate.NewReader(&r.source)
		} else if err = r.inflater.(flate.Resetter).Reset(&r.source, nil); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(r.inflater, result[compactBlockHeaderBytes:]); err != nil {
			return nil, err
		}
		count, tailErr := r.inflater.Read(r.extra[:])
		if count != 0 || tailErr != io.EOF || r.source.Len() != 0 {
			return nil, errors.New("compact invalid compressed payload length")
		}
		p = result
	}
	if err = validateCompactBlockPayload(p, wires, widths); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// IndexChecksum authenticates every row against its original block headers.
// Summary headers use the last-reference cache; scan readers retain a bounded
// set of details headers so amended rows can revisit earlier blocks cheaply.
func (r *compactScanReader) IndexChecksum(refs []byte, id PacketID) ([32]byte, error) {
	if r.held == 0 {
		return [32]byte{}, errors.New("compact scan reader closed")
	}
	if len(refs) != 32 {
		return [32]byte{}, errors.New("compact invalid directory references")
	}
	var input [8 + 32 + 72*2]byte
	binary.LittleEndian.PutUint64(input[:8], uint64(id))
	copy(input[8:40], refs)
	for i, f := range [...]*os.File{r.dataset.summaries, r.dataset.details} {
		off := binary.LittleEndian.Uint64(refs[i*16:])
		size := binary.LittleEndian.Uint64(refs[i*16+8:])
		if i == 1 && off == 0 && size == 0 {
			continue
		}
		if off < compactHeaderBytes || off > math.MaxInt64-72 || size < 72 || size-72 > r.dataset.storage.limits.MaxRecordBytes {
			return [32]byte{}, errors.New("compact invalid directory block reference")
		}
		h := &r.headers[i]
		if i == 1 && r.detailHeaders != nil {
			var hit bool
			for j := range r.detailHeaders {
				candidate := &r.detailHeaders[j]
				if candidate.valid && candidate.off == off && candidate.size == size {
					h, hit = candidate, true
					break
				}
			}
			if !hit {
				h = &r.detailHeaders[r.nextDetail]
				r.nextDetail = (r.nextDetail + 1) % compactDetailsHeaderCacheSlots
			}
		}
		if !h.valid || h.off != off || h.size != size {
			h.valid = false
			if _, err := f.ReadAt(h.data[:], int64(off)); err != nil {
				return [32]byte{}, err
			}
			h.off, h.size, h.valid = off, size, true
		}
		copy(input[40+i*72:40+(i+1)*72], h.data[:])
	}
	return sha256.Sum256(input[:]), nil
}
