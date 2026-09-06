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

// scanCompactSummaries reads the authenticated row directory sequentially and
// retains one expanded block. Amendments may point to replacement blocks; the
// directory remains authoritative, including when returning to an earlier block.
func (d *diskDataset) scanCompactSummaries(ctx context.Context, expression *Expression, related bool, visit func(Summary) error) (err error) {
	bufferBytes := min(uint64(32<<10), d.storage.limits.MaxRecordBytes)
	if err := d.storage.reserveMemory(ctx, bufferBytes); err != nil {
		return err
	}
	defer d.storage.releaseMemory(bufferBytes)
	reader := bufio.NewReaderSize(io.NewSectionReader(d.offsets, compactHeaderBytes, int64(d.count)*compactIndexBytes), int(bufferBytes))
	blocks, err := newCompactScanReader(ctx, d)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, blocks.Close()) }()
	var block []byte
	var offset, size uint64
	selected := compactQueryColumns(expression, related)
	// Reflection needs an addressable row. Reuse its scratch object rather than
	// allocating one for every packet; decoded strings and summaries are owned.
	var row compactRow
	target := reflect.ValueOf(&row).Elem()
	indexes := compactFieldIndexes[target.Type()]
	for id := PacketID(0); uint64(id) < d.count; id++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var entry [compactIndexBytes]byte
		if _, err := io.ReadFull(reader, entry[:]); err != nil {
			return err
		}
		checksum, err := blocks.IndexChecksum(entry[:32], id)
		if err != nil {
			return err
		}
		if !bytes.Equal(checksum[:], entry[32:]) {
			return errors.New("compact row directory checksum mismatch")
		}
		off, n := binary.LittleEndian.Uint64(entry[:8]), binary.LittleEndian.Uint64(entry[8:16])
		if block == nil || off != offset || n != size {
			block, err = blocks.Read(ctx, d.summaries, off, n, 1, id)
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
		// compactWholeBlock retains size + 3*MaxRecordBytes + inflater memory.
		// That admission covers both the expanded block and this row's decoder
		// scratch (bounded cumulatively by MaxRecordBytes) before allocation.
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
				return errors.New("compact trailing query field bytes")
			}
			memory = decoder.memory
		}
		if err := d.compact.resolveCompactRow(&row); err != nil {
			return err
		}
		if row.Length < 0 {
			return errors.New("compact negative query packet length")
		}
		summary, summaryHeld, err := d.materializeCompactSummary(ctx, row, id)
		row = compactRow{}
		if err != nil {
			return err
		}
		err = visit(summary)
		d.storage.releaseMemory(summaryHeld)
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

// The v2 compression unit is a complete block, so integrity verification still
// reads its complete bytes. Only selected columns and referenced arena values
// are decoded/allocated; raw locators and detail sidecars are never materialized.
func compactQueryColumns(expression *Expression, related bool) []bool {
	names := compactFieldNames[reflect.TypeOf(compactRow{})]
	selected := make([]bool, len(names))
	required := map[string]bool{"Timestamp": true, "SrcIP": true, "DstIP": true, "Protocol": true, "Length": true}
	if related {
		for _, name := range []string{"SrcPort", "DstPort", "Node", "NodeRef", "Transport"} {
			required[name] = true
		}
	} else if expression == nil {
		for _, name := range []string{"SrcPort", "DstPort", "Info", "Node", "NodeRef", "Device", "DeviceRef", "Transport", "LinkType", "Projection"} {
			required[name] = true
		}
	} else {
		for _, field := range expression.RequiredFields() {
			switch field {
			case "src", "srcip", "dst", "dstip", "protocol", "length", "len":
			case "srcport":
				required["SrcPort"] = true
			case "dstport":
				required["DstPort"] = true
			case "info":
				required["Info"] = true
			case "node", "nodeid":
				required["Node"] = true
				required["NodeRef"] = true
			case "interface":
				required["Device"] = true
				required["DeviceRef"] = true
			case "transport":
				required["Transport"] = true
			default:
				required["Projection"] = true
			}
		}
	}
	for col, name := range names {
		selected[col] = required[name]
	}
	return selected
}
