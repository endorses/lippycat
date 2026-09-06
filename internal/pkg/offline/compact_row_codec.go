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
	err error
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
func (e *compactRowEncoder) row(r *compactRow) {
	e.uint(uint64(r.Argument), 4)
	e.uint(uint64(r.Interface), 4)
	e.uint(r.Sequence, 8)
	e.uint(uint64(r.Locator.BackingID), 4)
	e.uint(uint64(r.Locator.Offset), 8)
	e.uint(uint64(r.Locator.Length), 4)
	if e.err == nil {
		e.err = e.put(r.Locator.Digest[:])
	}
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
	e.uint(r.PhysicalOrdinal, 8)
	e.uint(uint64(r.OriginalCaptured), 4)
	e.uint(uint64(r.OriginalWire), 4)
	e.uint(uint64(r.OriginalLink), 4)
	e.boolean(r.Derived)
	e.uint(uint64(r.Captured), 4)
	e.uint(uint64(r.Original), 4)
	e.uint(uint64(r.Timestamp.Unix()), 8)
	e.uint(uint64(r.Timestamp.Nanosecond()), 4)
	for _, s := range [...]string{r.SrcIP, r.DstIP, r.SrcPort, r.DstPort, r.Protocol, r.Info, r.Node, r.Device} {
		e.text(s)
	}
	e.uint(uint64(r.Transport), 1)
	e.uint(uint64(r.Length), 8)
	e.uint(uint64(r.LinkType), 1)
	e.projection(&r.Projection)
	e.uint(uint64(r.NodeRef), 4)
	e.uint(uint64(r.DeviceRef), 4)
	e.uint(uint64(r.ContextRef), 4)
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

	e := compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max}}}
	e.row(r)
	if e.err != nil {
		return nil, e.err
	}
	e = compactRowEncoder{compactEncoder: compactEncoder{encoder: encoder{max: max, data: make([]byte, prefix, prefix+int(e.size))}}}
	e.row(r)
	return e.data, e.err
}
