package offline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
)

// Column blocks use fixed-width descriptors followed by disjoint typed columns
// and a bounded block-local arena. Compound values and exact text use references;
// the reference's block word is zero because arenas never escape their block.
// This keeps random row lookup independent of a dataset-sized arena index.
func buildCompactColumnTypes(kind uint16) ([]byte, []int, error) {
	var sample any
	if kind == 1 {
		sample = compactRow{}
	} else if kind == 4 {
		sample = compactOverrides{}
	} else {
		return nil, nil, errors.New("unknown compact block kind")
	}
	t := reflect.TypeOf(sample)
	names := compactFieldNames[t]
	types := make([]byte, 0, len(names)+2)
	widths := make([]int, 0, len(names)+2)
	if kind == 1 {
		types = append(types, 4, 4)
		widths = append(widths, 8, 8)
	}
	for _, name := range names {
		f, ok := t.FieldByName(name)
		if !ok {
			return nil, nil, fmt.Errorf("unknown compact field %s", name)
		}
		wire, width := byte(7), 16
		switch f.Type.Kind() {
		case reflect.Bool, reflect.Uint8:
			wire, width = 1, 1
		case reflect.Uint16:
			wire, width = 2, 2
		case reflect.Uint32:
			wire, width = 3, 4
		case reflect.Uint, reflect.Uint64:
			wire, width = 4, 8
		case reflect.Int, reflect.Int64:
			wire, width = 5, 8
		case reflect.Float64:
			wire, width = 6, 8
		case reflect.Array:
			if f.Type.Len() == 32 && f.Type.Elem().Kind() == reflect.Uint8 {
				wire, width = 8, 32
			}
		}
		types = append(types, wire)
		widths = append(widths, width)
	}
	return types, widths, nil
}

func mustCompactColumnTypes(kind uint16) ([]byte, []int) {
	wires, widths, err := buildCompactColumnTypes(kind)
	if err != nil {
		panic(err)
	}
	return wires, widths
}

var compactRowWires, compactRowWidths = mustCompactColumnTypes(1)
var compactMetadataWires, compactMetadataWidths = mustCompactColumnTypes(4)

func compactColumnTypes(kind uint16) ([]byte, []int, error) {
	if kind == 1 {
		return compactRowWires, compactRowWidths, nil
	}
	if kind == 4 {
		return compactMetadataWires, compactMetadataWidths, nil
	}
	return nil, nil, errors.New("unknown compact block kind")
}

func (b *Builder) writeCompactBlock(f *os.File, kind uint16, first PacketID, rows [][]byte) (uint64, uint64, error) {
	return b.writeCompactBlockWithEnds(f, kind, first, rows, nil)
}

// recorded contains column boundaries from trusted internal typed encoders.
// All other callers retain the complete parsing and validation path.
func (b *Builder) writeCompactBlockWithEnds(f *os.File, kind uint16, first PacketID, rows [][]byte, recorded []uint32) (uint64, uint64, error) {
	max := b.d.storage.limits.MaxRecordBytes
	if len(rows) == 0 || len(rows) > 4096 {
		return 0, 0, errors.New("compact invalid block row count")
	}
	wires, widths, err := compactColumnTypes(kind)
	if err != nil {
		return 0, 0, err
	}
	// Account the transposition arrays and copied field buffers before allocation.
	var encodedBytes uint64
	for _, row := range rows {
		if uint64(len(row)) > max-encodedBytes {
			return 0, 0, errors.New("compact input rows exceed block budget")
		}
		encodedBytes += uint64(len(row))
	}
	count := len(rows) * len(wires)
	scratch := max + encodedBytes*3 + uint64(count)*32
	var ends = recorded
	if recorded != nil {
		if (kind != 1 && kind != 4) || len(recorded) != count {
			return 0, 0, errors.New("invalid recorded compact columns")
		}
		scratch -= uint64(count) * 4
	} else if b.d.storage.limits.CacheBytes >= 16<<20 {
		// Retained transposition offsets replace the same allowance in this
		// block's transient reservation. Small budgets keep the old lifetime.
		ends, err = b.compactColumnEnds(count)
		if err != nil {
			return 0, 0, err
		}
		scratch -= uint64(count) * 4
	}
	if err = b.reserveCompactMemory(context.Background(), scratch); err != nil {
		return 0, 0, err
	}
	defer b.d.storage.releaseMemory(scratch)
	if ends == nil {
		ends = make([]uint32, count)
	}
	var fields [64][]byte
	n := uint64(len(wires)) * 24
	for _, width := range widths {
		n += uint64(width * len(rows))
	}
	for i, row := range rows {
		if recorded != nil {
			var start uint32
			for col, end := range ends[i*len(wires) : (i+1)*len(wires)] {
				if end < start || uint64(end) > uint64(len(row)) {
					return 0, 0, errors.New("invalid recorded compact column boundary")
				}
				length := int(end - start)
				if wires[col] == 7 {
					n += uint64(length)
				} else if length != widths[col] {
					return 0, 0, errors.New("compact fixed column width mismatch")
				}
				start = end
			}
			if uint64(start) != uint64(len(row)) {
				return 0, 0, errors.New("invalid recorded compact trailing bytes")
			}
			continue
		}
		parts, splitErr := compactSplitRowInto(kind, row, max, fields[:0])
		err = splitErr
		if err != nil {
			return 0, 0, err
		}
		if len(parts) != len(wires) {
			return 0, 0, errors.New("compact column count mismatch")
		}
		var end uint64
		for col, p := range parts {
			end += uint64(len(p))
			if end > math.MaxUint32 {
				return 0, 0, errors.New("compact field offset overflow")
			}
			ends[i*len(wires)+col] = uint32(end)
			if wires[col] == 7 {
				n += uint64(len(p))
			} else if len(p) != widths[col] {
				return 0, 0, errors.New("compact fixed column width mismatch")
			}
		}
	}
	if n > max || n > math.MaxUint32 {
		return 0, 0, errors.New("compact block exceeds allocation limit")
	}
	payload, err := b.compactBuffer(&b.d.compact.blockBuffer, int(n))
	if err != nil {
		return 0, 0, err
	}
	clear(payload) // Reserved descriptor/reference words must stay zero on reuse.
	columnStart := len(wires) * 24
	arena := columnStart
	for _, width := range widths {
		arena += width * len(rows)
	}
	for col, wire := range wires {
		desc := payload[col*24 : (col+1)*24]
		binary.LittleEndian.PutUint16(desc, uint16(col+1))
		desc[2] = wire
		binary.LittleEndian.PutUint32(desc[4:], uint32(len(rows)))
		binary.LittleEndian.PutUint64(desc[8:], uint64(columnStart))
		binary.LittleEndian.PutUint64(desc[16:], uint64(widths[col]*len(rows)))
		for row := range rows {
			target := payload[columnStart+row*widths[col] : columnStart+(row+1)*widths[col]]
			start := uint32(0)
			if col > 0 {
				start = ends[row*len(wires)+col-1]
			}
			p := rows[row][start:ends[row*len(wires)+col]]
			if wire == 7 {
				binary.LittleEndian.PutUint32(target[4:], uint32(arena))
				binary.LittleEndian.PutUint32(target[8:], uint32(len(p)))
				binary.LittleEndian.PutUint32(target[12:], 1)
				copy(payload[arena:], p)
				arena += len(p)
			} else {
				copy(target, p)
			}
		}
		columnStart += widths[col] * len(rows)
	}
	if kind == 1 && b.d.compact.queueCompression && b.startCompactCompression(payload, first, len(rows), len(wires)) {
		return 0, 0, nil
	}
	stored, flags, err := b.compressCompact(payload)
	if err != nil {
		return 0, 0, err
	}
	var h [72]byte
	copy(h[:], "LCB2")
	binary.LittleEndian.PutUint16(h[4:], kind)
	binary.LittleEndian.PutUint16(h[6:], 72)
	binary.LittleEndian.PutUint64(h[8:], uint64(first))
	binary.LittleEndian.PutUint32(h[16:], uint32(len(rows)))
	binary.LittleEndian.PutUint16(h[20:], uint16(len(wires)))
	binary.LittleEndian.PutUint16(h[22:], flags)
	binary.LittleEndian.PutUint64(h[24:], n)
	binary.LittleEndian.PutUint64(h[32:], 1)
	digest := sha256.Sum256(payload)
	copy(h[40:], digest[:])
	off, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, 0, err
	}
	if kind == 1 {
		b.d.storage.releaseDisk(b.d.compact.transferDisk)
		b.d.compact.transferDisk = 0
	}
	if err = b.write(f, h[:]); err == nil {
		err = b.write(f, stored)
	}
	return uint64(off), uint64(len(stored)) + 72, err
}

func (d *diskDataset) compactWholeBlock(ctx context.Context, f *os.File, off, size uint64, kind uint16, id PacketID) ([]byte, uint64, error) {
	max := d.storage.limits.MaxRecordBytes
	if size < 72 || size-72 > max || off < 32 || size > math.MaxInt64 || off > math.MaxInt64-size {
		return nil, 0, errors.New("compact invalid block reference")
	}
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	if off+size > uint64(st.Size()) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	held := size + max*3
	inflaterHeld := d.storage.limits.CacheBytes >= 16<<20
	if inflaterHeld {
		held += compactInflaterMemory
	}
	if err = d.storage.reserveMemory(ctx, held); err != nil {
		return nil, 0, err
	}
	fail := func(e error) ([]byte, uint64, error) { d.storage.releaseMemory(held); return nil, 0, e }
	key := cacheKey{dataset: d, id: PacketID(off), kind: kind + 16}
	p := d.storage.cached(key)
	cacheHit := p != nil
	if p == nil {
		p = make([]byte, size)
		if _, err = f.ReadAt(p, int64(off)); err != nil {
			return fail(err)
		}
	} else {
		if len(p) < 80 || binary.LittleEndian.Uint64(p[:8]) != size {
			return fail(errors.New("compact cached block reference mismatch"))
		}
		p = p[8:]
	}
	h := p[:72]
	first := binary.LittleEndian.Uint64(h[8:])
	count := uint64(binary.LittleEndian.Uint32(h[16:]))
	columns := int(binary.LittleEndian.Uint16(h[20:]))
	n := binary.LittleEndian.Uint64(h[24:])
	wires, widths, err := compactColumnTypes(kind)
	if err != nil {
		return fail(err)
	}
	if string(h[:4]) != "LCB2" || binary.LittleEndian.Uint16(h[4:]) != kind || binary.LittleEndian.Uint16(h[6:]) != 72 || binary.LittleEndian.Uint16(h[22:]) > 1 || binary.LittleEndian.Uint64(h[32:]) != 1 || count == 0 || count > 4096 || first > math.MaxUint64-count || uint64(id) < first || uint64(id)-first >= count || n > max || (binary.LittleEndian.Uint16(h[22:]) == 0 && n != size-72) || columns != len(wires) || uint64(columns)*24 > n {
		return fail(errors.New("compact invalid block header"))
	}
	if !cacheHit && binary.LittleEndian.Uint16(h[22:]) == 1 {
		if !inflaterHeld {
			if err = d.storage.reserveMemory(ctx, compactInflaterMemory); err != nil {
				return fail(err)
			}
			held += compactInflaterMemory
		}
		p, err = inflateCompact(p, n)
		if err != nil {
			return fail(err)
		}
	}
	if uint64(len(p)) != n+72 {
		return fail(errors.New("compact cached block reference mismatch"))
	}
	if cacheHit {
		if err = ctx.Err(); err != nil {
			return fail(err)
		}
		return p, held, nil
	}
	if err = validateCompactBlockPayload(p, wires, widths); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	// The cached payload is expanded, but references still carry physical sizes.
	// Bind both so a cache hit cannot accept a malformed compressed reference.
	cached := make([]byte, len(p)+8)
	binary.LittleEndian.PutUint64(cached, size)
	copy(cached[8:], p)
	d.storage.cacheFrame(key, cached)
	return p, held, nil
}

// compactBlock materializes a single row from an authenticated block. Sequential
// queries retain the whole block instead, amortizing validation and decompression.
func (d *diskDataset) compactBlock(ctx context.Context, f *os.File, off, size uint64, kind uint16, id PacketID) ([]byte, uint64, error) {
	p, held, err := d.compactWholeBlock(ctx, f, off, size, kind, id)
	if err != nil {
		return nil, 0, err
	}
	wires, widths, err := compactColumnTypes(kind)
	if err != nil {
		d.storage.releaseMemory(held)
		return nil, 0, err
	}
	row := uint64(id) - binary.LittleEndian.Uint64(p[8:])
	var fields [64][]byte
	var length uint64
	for col := range wires {
		fields[col] = compactBlockField(p, row, col, wires[col], widths[col])
		length += uint64(len(fields[col]))
		if length > d.storage.limits.MaxRecordBytes {
			d.storage.releaseMemory(held)
			return nil, 0, errors.New("compact selected row exceeds allocation limit")
		}
	}
	result := make([]byte, 0, length)
	for _, field := range fields[:len(wires)] {
		result = append(result, field...)
	}
	return result, held, nil
}

// compactBlockField borrows a field from an already authenticated block.
func compactBlockField(block []byte, row uint64, col int, wire byte, width int) []byte {
	payload := block[compactBlockHeaderBytes:]
	desc := payload[col*24 : (col+1)*24]
	start := binary.LittleEndian.Uint64(desc[8:]) + row*uint64(width)
	field := payload[start : start+uint64(width)]
	if wire == 7 {
		offset := uint64(binary.LittleEndian.Uint32(field[4:]))
		length := uint64(binary.LittleEndian.Uint32(field[8:]))
		field = payload[offset : offset+length]
	}
	return field
}

// validateCompactBlockPayload checks all columns and arena references even when
// the caller will decode only a subset. Header bounds have already been checked.
func validateCompactBlockPayload(p []byte, wires []byte, widths []int) error {
	h := p[:compactBlockHeaderBytes]
	payload := p[compactBlockHeaderBytes:]
	count := uint64(binary.LittleEndian.Uint32(h[16:]))
	columns := len(wires)
	n := uint64(len(payload))
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], h[40:]) {
		return errors.New("compact block checksum mismatch")
	}
	cursor := uint64(columns) * 24
	for col, wire := range wires {
		desc := payload[col*24 : (col+1)*24]
		length := count * uint64(widths[col])
		if binary.LittleEndian.Uint16(desc) != uint16(col+1) || desc[2] != wire || desc[3] != 0 || uint64(binary.LittleEndian.Uint32(desc[4:])) != count || binary.LittleEndian.Uint64(desc[8:]) != cursor || binary.LittleEndian.Uint64(desc[16:]) != length || cursor > n || length > n-cursor {
			return errors.New("compact invalid column descriptor")
		}
		cursor += length
	}
	arena := cursor
	for col, wire := range wires {
		desc := payload[col*24 : (col+1)*24]
		start := binary.LittleEndian.Uint64(desc[8:])
		if wire != 7 {
			continue
		}
		for i := uint64(0); i < count; i++ {
			ref := payload[start+i*16 : start+(i+1)*16]
			offset := uint64(binary.LittleEndian.Uint32(ref[4:]))
			length := uint64(binary.LittleEndian.Uint32(ref[8:]))
			if binary.LittleEndian.Uint32(ref) != 0 || binary.LittleEndian.Uint32(ref[12:]) != 1 || offset != arena || offset > n || length > n-offset {
				return errors.New("compact invalid arena reference")
			}
			arena += length
		}
	}
	if arena != n {
		return errors.New("compact trailing arena bytes")
	}
	return nil
}

// compactColumnEnds reuses one block's offset table. Admit new capacity before
// allocation, retain its charge between blocks, and release it at builder EOF.
func (b *Builder) compactColumnEnds(n int) ([]uint32, error) {
	c := b.d.compact
	if cap(c.columnEnds) < n {
		if err := b.reserveCompactMemory(context.Background(), uint64(n)*4); err != nil {
			return nil, err
		}
		ends := make([]uint32, n)
		b.d.storage.releaseMemory(uint64(cap(c.columnEnds)) * 4)
		c.columnEnds = ends
	}
	return c.columnEnds[:n], nil
}
