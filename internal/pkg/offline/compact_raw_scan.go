package offline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
)

// iterateCompactRaw retains one authenticated column block and batches bounded
// source reads. Its callback borrows owned backing-lease bytes, avoiding both
// presentation decoding and an unnecessary second copy of every packet.
func (q *diskQuery) iterateCompactRaw(ctx context.Context, visit func(RawRecord) error) (resultErr error) {
	d := q.dataset
	if err := d.validateCompactStreams(); err != nil {
		return err
	}
	bufferBytes := min(uint64(32<<10), d.storage.limits.MaxRecordBytes)
	const batchCount = 64
	scratch := 2*bufferBytes + uint64(batchCount)*(uint64(reflect.TypeOf(RawRecord{}).Size())+uint64(reflect.TypeOf(Locator{}).Size()))
	if err := d.storage.reserveMemory(ctx, scratch); err != nil {
		return err
	}
	defer d.storage.releaseMemory(scratch)
	directory := bufio.NewReaderSize(io.NewSectionReader(d.offsets, compactHeaderBytes, int64(d.count)*compactIndexBytes), int(bufferBytes))
	var ids *bufio.Reader
	if !q.identity {
		ids = bufio.NewReaderSize(io.NewSectionReader(q.file, queryHeaderBytes, int64(q.count)*queryEntryBytes), int(bufferBytes))
	}
	blockReader, err := newCompactScanReader(ctx, d)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, blockReader.Close()) }()
	var block []byte
	var offset, size uint64
	var records [batchCount]RawRecord
	var locators [batchCount]Locator
	pending := 0
	var pendingBytes uint64
	batchBytes := min(uint64(256<<10), d.storage.limits.MaxRecordBytes)
	flush := func() error {
		if pending == 0 {
			return nil
		}
		lease, packets, err := d.compact.registry.ReadBatch(ctx, locators[:pending], batchBytes)
		if err != nil {
			return err
		}
		for i := 0; i < pending; i++ {
			if err = ctx.Err(); err != nil {
				break
			}
			records[i].RawData = packets[i]
			if err = visit(records[i]); err != nil {
				break
			}
		}
		clear(records[:pending]) // Do not retain lease bytes after releasing their charge.
		pending = 0
		pendingBytes = 0
		return errors.Join(err, lease.Close())
	}
	var next, previous PacketID
	var row compactRow
	target := reflect.ValueOf(&row).Elem()
	names := compactFieldNames[target.Type()]
	indexes := compactFieldIndexes[target.Type()]
	var selected [64]bool
	for col, name := range names {
		switch name {
		case "Argument", "Locator", "Context", "OriginalLink", "Captured", "Original", "Timestamp", "LinkType", "ContextRef", "Length":
			selected[col] = true
		}
	}
	for resultRow := uint64(0); resultRow < q.count; resultRow++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := PacketID(resultRow)
		if ids != nil {
			var entry [queryEntryBytes]byte
			if _, err := io.ReadFull(ids, entry[:]); err != nil {
				return err
			}
			id = PacketID(binary.LittleEndian.Uint64(entry[:]))
			if uint64(id) >= d.count || (resultRow > 0 && id <= previous) {
				return errors.New("corrupt unordered query IDs")
			}
		}
		previous = id
		if id != next {
			gap := uint64(id-next) * compactIndexBytes
			if gap <= bufferBytes {
				if _, err := directory.Discard(int(gap)); err != nil {
					return err
				}
			} else {
				directory.Reset(io.NewSectionReader(d.offsets, compactHeaderBytes+int64(id)*compactIndexBytes, int64(d.count-uint64(id))*compactIndexBytes))
			}
		}
		next = id + 1
		var entry [compactIndexBytes]byte
		if _, err := io.ReadFull(directory, entry[:]); err != nil {
			return err
		}
		checksum, err := blockReader.IndexChecksum(entry[:32], id)
		if err != nil {
			return err
		}
		if !bytes.Equal(checksum[:], entry[32:]) {
			return errors.New("compact row directory checksum mismatch")
		}
		off, n := binary.LittleEndian.Uint64(entry[:8]), binary.LittleEndian.Uint64(entry[8:16])
		if block == nil || offset != off || size != n {
			block, err = blockReader.Read(ctx, d.summaries, off, n, 1, id)
			if err != nil {
				return err
			}
			offset, size = off, n
		}
		first, count := binary.LittleEndian.Uint64(block[8:]), uint64(binary.LittleEndian.Uint32(block[16:]))
		if uint64(id) < first || uint64(id)-first >= count {
			return errors.New("compact directory row outside block")
		}
		rowIndex := uint64(id) - first
		for col := 0; col < 2; col++ {
			field := compactBlockField(block, rowIndex, col, compactRowWires[col], compactRowWidths[col])
			if binary.LittleEndian.Uint64(field) != binary.LittleEndian.Uint64(entry[16+col*8:]) {
				return errors.New("compact inconsistent metadata directory reference")
			}
		}
		row = compactRow{}
		memory := compactRowMemory
		for col, index := range indexes {
			if !selected[col] {
				continue
			}
			field := compactBlockField(block, rowIndex, col+2, compactRowWires[col+2], compactRowWidths[col+2])
			decoder := compactDecoder{decoder: decoder{data: field, max: d.storage.limits.MaxRecordBytes, memory: memory}}
			if err := decoder.value(target.Field(index)); err != nil {
				return err
			}
			if decoder.pos != len(field) {
				return errors.New("compact trailing raw field bytes")
			}
			memory = decoder.memory
		}
		if err := d.compact.resolveCompactRow(&row); err != nil {
			return err
		}
		if _, err := row.source(d.compact); err != nil {
			return err
		}
		if err := validateCompactContext(row.Context, row.OriginalLink); err != nil {
			return err
		}
		descriptor, err := d.compact.registry.Describe(row.Locator.BackingID)
		if err != nil {
			return err
		}
		if row.Length < 0 || row.Locator.Offset < 0 || row.Captured != row.Locator.Length || descriptor.Source.SourceIndex != int(row.Argument) {
			return ErrInvalidLocator
		}
		if uint64(row.Locator.Length) > d.storage.limits.MaxRecordBytes {
			return ErrInvalidLocator
		}
		if pending == batchCount || uint64(row.Locator.Length) > batchBytes-pendingBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		// An individually large admitted packet gets a singleton batch; ordinary
		// batches remain at 256 KiB even when the record budget is much larger.
		if uint64(row.Locator.Length) > batchBytes {
			lease, err := d.compact.registry.Read(ctx, row.Locator)
			if err != nil {
				return err
			}
			record := RawRecord{ID: id, Timestamp: row.Timestamp, CapturedLength: row.Captured, OriginalLength: row.Original, LinkType: row.LinkType, RawData: lease.Bytes}
			err = visit(record)
			if err = errors.Join(err, lease.Close()); err != nil {
				return err
			}
			continue
		}
		records[pending] = RawRecord{ID: id, Timestamp: row.Timestamp, CapturedLength: row.Captured, OriginalLength: row.Original, LinkType: row.LinkType}
		locators[pending] = row.Locator
		pending++
		pendingBytes += uint64(row.Locator.Length)
	}
	if err := flush(); err != nil {
		return err
	}
	return ctx.Err()
}
