package offline

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sync"
)

// Compile the row's wire shape once. Splitting encoded rows then retains slices
// of the admitted input instead of allocating decoded strings and reencoding
// every column. Metadata blocks retain the general codec path.
type compactWireSpan struct {
	kind      reflect.Kind
	width     int
	fields    []compactWireSpan
	groups    [][]compactWireSpan
	timestamp bool
}

var compactRowSpans = sync.OnceValues(func() ([]compactWireSpan, error) {
	span, err := compileCompactWireSpan(reflect.TypeOf(compactRow{}))
	return span.fields, err
})

func compileCompactWireSpan(t reflect.Type) (compactWireSpan, error) {
	s := compactWireSpan{kind: t.Kind()}
	if t == timestampType {
		s.timestamp = true
		return s, nil
	}
	if t == reflect.TypeOf(compactProjection{}) {
		s.groups = make([][]compactWireSpan, len(compactProjectionGroups))
		for i, names := range compactProjectionGroups {
			for _, name := range names {
				field, ok := t.FieldByName(name)
				if !ok {
					return s, fmt.Errorf("missing compact projection field %s", name)
				}
				child, err := compileCompactWireSpan(field.Type)
				if err != nil {
					return s, err
				}
				s.groups[i] = append(s.groups[i], child)
			}
		}
		return s, nil
	}
	switch t.Kind() {
	case reflect.Struct:
		names, ok := compactFieldNames[t]
		if !ok {
			return s, fmt.Errorf("unsupported compact span struct %s", t)
		}
		for _, name := range names {
			field, ok := t.FieldByName(name)
			if !ok {
				return s, fmt.Errorf("missing compact span field %s", name)
			}
			child, err := compileCompactWireSpan(field.Type)
			if err != nil {
				return s, err
			}
			s.fields = append(s.fields, child)
		}
	case reflect.String, reflect.Bool:
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		s.width = compactIntegerBytes(t.Kind())
	case reflect.Float64:
		s.width = 8
	case reflect.Array:
		if t.Elem().Kind() != reflect.Uint8 {
			return s, fmt.Errorf("unsupported compact span array %s", t)
		}
		s.width = t.Len()
	default:
		return s, fmt.Errorf("unsupported compact span type %s", t)
	}
	return s, nil
}

func (s *compactWireSpan) skip(d *compactDecoder) error {
	if s.timestamp {
		p, err := d.take(12)
		if err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(p[8:]) >= 1e9 {
			return fmt.Errorf("invalid offline timestamp nanoseconds")
		}
		return nil
	}
	if s.groups != nil {
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] & ^byte(31) != 0 {
			return fmt.Errorf("invalid compact projection presence")
		}
		for i, fields := range s.groups {
			if p[0]&(1<<i) != 0 {
				for j := range fields {
					if err := fields[j].skip(d); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	switch s.kind {
	case reflect.Struct:
		for i := range s.fields {
			if err := s.fields[i].skip(d); err != nil {
				return err
			}
		}
	case reflect.String:
		p, err := d.take(4)
		if err != nil {
			return err
		}
		n := uint64(binary.LittleEndian.Uint32(p))
		if err := addBudget(&d.memory, n, d.max); err != nil {
			return err
		}
		if n > uint64(len(d.data)-d.pos) {
			return io.ErrUnexpectedEOF
		}
		d.pos += int(n)
	case reflect.Bool:
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] > 1 {
			return fmt.Errorf("invalid offline boolean")
		}
	default:
		_, err := d.take(uint64(s.width))
		return err
	}
	return nil
}

func compactSplitRow(kind uint16, data []byte, max uint64) ([][]byte, error) {
	return compactSplitRowInto(kind, data, max, nil)
}

func compactSplitRowInto(kind uint16, data []byte, max uint64, parts [][]byte) ([][]byte, error) {
	if kind != 1 {
		var overrides compactOverrides
		if err := decodeCompactValue(data, &overrides, max); err != nil {
			return nil, err
		}
		return encodeCompactFields(overrides, max)
	}
	if len(data) < 16 {
		return nil, io.ErrUnexpectedEOF
	}
	memory := uint64(reflect.TypeOf(compactRow{}).Size())
	if max > uint64(int(^uint(0)>>1)) || uint64(len(data)-16) > max || memory > max {
		return nil, fmt.Errorf("compact row exceeds memory budget")
	}
	spans, err := compactRowSpans()
	if err != nil {
		return nil, err
	}
	if cap(parts) < len(spans)+2 {
		parts = make([][]byte, len(spans)+2)
	} else {
		parts = parts[:len(spans)+2]
	}
	parts[0], parts[1] = data[:8], data[8:16]
	d := compactDecoder{decoder: decoder{data: data[16:], max: max, memory: memory}}
	for i := range spans {
		start := d.pos
		if err := spans[i].skip(&d); err != nil {
			return nil, err
		}
		parts[i+2] = d.data[start:d.pos]
	}
	if d.pos != len(d.data) {
		return nil, fmt.Errorf("compact trailing value bytes")
	}
	return parts, nil
}
