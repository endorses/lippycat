package offline

import (
	"errors"
	"reflect"
)

var errCompactProjectionPresence = errors.New("invalid compact projection presence")

// compactRowEncoder writes the hot completed-row path in schema-v2 order. The
// generic codec remains the compatibility oracle and handles sparse metadata.
// Both passes use the same budget checks as the generic encoder.
type compactRowEncoder struct {
	compactEncoder
	err    error
	ends   []uint32
	column int
}

func (e *compactRowEncoder) uint(n uint64, width int) {
	if e.err == nil {
		e.err = e.integer(n, width)
	}
}
func (e *compactRowEncoder) boolean(b bool) {
	var n uint64
	if b {
		n = 1
	}
	e.uint(n, 1)
}
func (e *compactRowEncoder) text(s string) {
	if e.err != nil {
		return
	}
	if e.err = e.length(len(s)); e.err != nil {
		return
	}
	if e.err = addBudget(&e.size, uint64(len(s)), e.max); e.err != nil {
		return
	}
	if e.data != nil {
		e.data = append(e.data, s...)
	}
}
func (e *compactRowEncoder) endColumn() {
	if e.ends != nil && e.err == nil {
		e.ends[e.column] = uint32(len(e.data))
		e.column++
	}
}
func (e *compactRowEncoder) row(r *compactRow) {
	e.uint(uint64(r.Argument), 4)
	e.endColumn()
	e.uint(uint64(r.Interface), 4)
	e.endColumn()
	e.uint(r.Sequence, 8)
	e.endColumn()
	e.uint(uint64(r.Locator.BackingID), 4)
	e.uint(uint64(r.Locator.Offset), 8)
	e.uint(uint64(r.Locator.Length), 4)
	if e.err == nil {
		e.err = e.put(r.Locator.Digest[:])
	}
	e.endColumn()
	c := &r.Context
	e.uint(uint64(c.Format), 1)
	e.uint(uint64(c.ByteOrder), 1)
	e.uint(uint64(c.SectionID), 4)
	e.uint(uint64(c.InterfaceID), 4)
	e.uint(uint64(c.LinkType), 4)
	e.uint(uint64(c.Snaplen), 4)
	e.uint(uint64(c.TimestampResolutionBase), 1)
	e.uint(uint64(c.TimestampResolutionExponent), 1)
	e.uint(uint64(c.TimestampOffset), 8)
	e.boolean(c.TimestampMissing)
	e.endColumn()
	e.uint(r.PhysicalOrdinal, 8)
	e.endColumn()
	e.uint(uint64(r.OriginalCaptured), 4)
	e.endColumn()
	e.uint(uint64(r.OriginalWire), 4)
	e.endColumn()
	e.uint(uint64(r.OriginalLink), 4)
	e.endColumn()
	e.boolean(r.Derived)
	e.endColumn()
	e.uint(uint64(r.Captured), 4)
	e.endColumn()
	e.uint(uint64(r.Original), 4)
	e.endColumn()
	e.uint(uint64(r.Timestamp.Unix()), 8)
	e.uint(uint64(r.Timestamp.Nanosecond()), 4)
	e.endColumn()
	for _, s := range [...]string{r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Protocol, r.Info, r.Node, r.Device} {
		e.text(s)
		e.endColumn()
	}
	e.uint(uint64(r.Transport), 1)
	e.endColumn()
	e.uint(uint64(r.Length), 8)
	e.endColumn()
	e.uint(uint64(r.LinkType), 1)
	e.endColumn()
	e.projection(&r.Projection)
	e.endColumn()
	e.uint(uint64(r.NodeRef), 4)
	e.endColumn()
	e.uint(uint64(r.DeviceRef), 4)
	e.endColumn()
	e.uint(uint64(r.ContextRef), 4)
	e.endColumn()
}
func (e *compactRowEncoder) projection(p *compactProjection) {
	if p.Presence & ^uint8(31) != 0 {
		if e.err == nil {
			e.err = errCompactProjectionPresence
		}
		return
	}
	e.uint(uint64(p.Presence), 1)
	if p.Presence&1 != 0 {
		for _, s := range [...]string{p.User, p.From, p.To, p.CallID, p.Method, p.Codec, p.FromTag, p.ToTag, p.IMSI, p.IMEI} {
			e.text(s)
		}
		e.uint(uint64(p.Status), 8)
		e.boolean(p.IsRTP)
		e.uint(uint64(p.SequenceNum), 2)
		e.uint(uint64(p.SSRC), 4)
	}
	if p.Presence&2 != 0 {
		e.text(p.QueryName)
		e.text(p.QueryType)
		e.uint(uint64(p.QueryResponseTimeMs), 8)
		e.boolean(p.AnswerPresent)
		e.uint(uint64(p.TTL), 4)
	}
	if p.Presence&8 != 0 {
		e.text(p.SNI)
		e.text(p.JA3)
	}
	if p.Presence&16 != 0 {
		e.text(p.Host)
		e.text(p.Path)
		e.text(p.HTTPMethod)
		e.uint(uint64(p.StatusCode), 8)
		e.uint(uint64(p.ContentLength), 8)
	}
}

var compactRowMemory = uint64(reflect.TypeOf(compactRow{}).Size())

func encodeCompactRow(r *compactRow, max uint64, prefix int) ([]byte, error) {
	return encodeCompactRowInto(r, max, prefix, nil)
}

// encodeCompactRowInto reuses caller-admitted storage when the complete encoded
// row fits. Oversized rows retain the exact-size allocation and budget checks.
func encodeCompactRowInto(r *compactRow, max uint64, prefix int, buffer []byte) ([]byte, error) {
	return encodeCompactRowWithEnds(r, max, prefix, buffer, nil)
}

func encodeCompactRowWithEnds(r *compactRow, max uint64, prefix int, buffer []byte, ends []uint32) ([]byte, error) {
	if ends != nil && (prefix != 16 || len(ends) != len(compactRowWires)) {
		return nil, errors.New("invalid compact column ends buffer")
	}

	if r == nil || prefix < 0 || max > uint64(int(^uint(0)>>1)-prefix) || compactRowMemory > max {
		return nil, errors.New("invalid compact row or memory budget")
	}
	memory := compactRowMemory
	p := &r.Projection
	// Memory admission includes every owned string even when presence suppresses
	// its wire representation, matching measureMemory's complete owned graph.
	for _, s := range [...]string{r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Protocol, r.Info, r.Node, r.Device, p.User, p.From, p.To, p.CallID, p.Method, p.Codec, p.FromTag, p.ToTag, p.IMSI, p.IMEI, p.QueryName, p.QueryType, p.SNI, p.JA3, p.Host, p.Path, p.HTTPMethod} {
		if err := addBudget(&memory, uint64(len(s)), max); err != nil {
			return nil, err
		}
	}

	// A conservative wire bound includes all projection groups, even absent ones.
	// Every string length was already counted by the owned-graph check above.
	wireBound := memory - compactRowMemory + compactRowMaxFixedBytes
	if uint64(cap(buffer)) >= uint64(prefix)+wireBound {
		buffer = buffer[:prefix]
		clear(buffer)
		e := compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max, data: buffer}}, ends: ends, column: 2}
		if ends != nil {
			ends[0], ends[1] = 8, 16
		}
		e.row(r)
		if e.err != nil {
			return nil, e.err
		}
		return e.data, nil
	}

	e := compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max}}}
	e.row(r)
	if e.err != nil {
		return nil, e.err
	}
	if cap(buffer) < prefix+int(e.size) {
		buffer = make([]byte, prefix, prefix+int(e.size))
	} else {
		buffer = buffer[:prefix]
		clear(buffer)
	}
	e = compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max, data: buffer}}, ends: ends, column: 2}
	if ends != nil {
		ends[0], ends[1] = 8, 16
	}
	e.row(r)
	return e.data, e.err
}

// Maximum fixed encoding overhead is derived from the same frozen writer.
var compactRowMaxFixedBytes = func() uint64 {
	r := compactRow{Projection: compactProjection{Presence: 31}}
	e := compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: ^uint64(0)}}}
	e.row(&r)
	if e.err != nil {
		panic(e.err)
	}
	return e.size
}()
