package offline

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"reflect"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// Schema v1 is little endian. The 32-byte frame has magic, version, kind,
// payload length, packet ID, CRC32 and four reserved zero bytes. Payload structs
// follow declaration order; changing their field layout requires a version bump.
const frameHeaderBytes = 32
const (
	recordKindSummary uint16 = 1
	recordKindDetail  uint16 = 2
)

type summaryWire struct{ Packet types.PacketDisplay }
type detailWire struct {
	Source                         SourcePosition
	CapturedLength, OriginalLength uint32
	Packet                         types.PacketDisplay
}

var timestampType = reflect.TypeOf(time.Time{})

func wireValue(value any) (any, error) {
	switch v := value.(type) {
	case Summary:
		return summaryWire{v.packet}, nil
	case Detail:
		return detailWire{v.Source, v.CapturedLength, v.OriginalLength, v.Packet}, nil
	default:
		return nil, fmt.Errorf("unsupported offline record %T", value)
	}
}

// recordMemory conservatively counts the retained Go object, backing arrays,
// strings and map buckets. It does not allocate copies of user-supplied data.
func recordMemory(value any, max uint64) (uint64, error) {
	var v reflect.Value
	switch p := value.(type) {
	case Summary:
		v = reflect.ValueOf(p)
	case Detail:
		v = reflect.ValueOf(p)
	default:
		return 0, fmt.Errorf("unsupported offline record %T", value)
	}
	n := uint64(v.Type().Size())
	err := measureMemory(v, &n, max)
	return n, err
}
func addBudget(n *uint64, amount, max uint64) error {
	if *n > max || amount > max-*n {
		return fmt.Errorf("offline record exceeds allocation limit %d", max)
	}
	*n += amount
	return nil
}
func measureMemory(v reflect.Value, n *uint64, max uint64) error {
	if v.Type() == timestampType {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		return addBudget(n, uint64(v.Len()), max)
	case reflect.Pointer:
		if !v.IsNil() {
			if err := addBudget(n, uint64(v.Type().Elem().Size()), max); err != nil {
				return err
			}
			return measureMemory(v.Elem(), n, max)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := measureMemory(v.Field(i), n, max); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if err := addProduct(n, uint64(v.Len()), uint64(v.Type().Elem().Size()), max); err != nil {
			return err
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := measureMemory(v.Index(i), n, max); err != nil {
				return err
			}
		}
	case reflect.Map:
		if !v.IsNil() {
			if err := addBudget(n, 512, max); err != nil {
				return err
			}
		}
		if err := addProduct(n, uint64(v.Len()), 128, max); err != nil {
			return err
		}
		it := v.MapRange()
		for it.Next() {
			if err := measureMemory(it.Key(), n, max); err != nil {
				return err
			}
			if err := measureMemory(it.Value(), n, max); err != nil {
				return err
			}
		}
	}
	return nil
}
func addProduct(n *uint64, count, size, max uint64) error {
	if size != 0 && count > max/size {
		return fmt.Errorf("offline container exceeds allocation limit %d", max)
	}
	return addBudget(n, count*size, max)
}

type encoder struct {
	data      []byte
	size, max uint64
}

func (e *encoder) put(p []byte) error {
	if err := addBudget(&e.size, uint64(len(p)), e.max); err != nil {
		return err
	}
	if e.data != nil {
		e.data = append(e.data, p...)
	}
	return nil
}
func (e *encoder) number(n uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return e.put(b[:])
}
func (e *encoder) value(v reflect.Value) error {
	if v.Type() == timestampType {
		t := v.Interface().(time.Time)
		if err := e.number(uint64(t.Unix())); err != nil {
			return err
		}
		return e.number(uint64(t.Nanosecond()))
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := e.value(v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Pointer:
		if v.IsNil() {
			return e.put([]byte{0})
		}
		if err := e.put([]byte{1}); err != nil {
			return err
		}
		return e.value(v.Elem())
	case reflect.Bool:
		if v.Bool() {
			return e.put([]byte{1})
		}
		return e.put([]byte{0})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.number(uint64(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.number(v.Uint())
	case reflect.Float64:
		return e.number(math.Float64bits(v.Float()))
	case reflect.String:
		if err := e.number(uint64(v.Len())); err != nil {
			return err
		}
		if err := addBudget(&e.size, uint64(v.Len()), e.max); err != nil {
			return err
		}
		if e.data != nil {
			e.data = append(e.data, v.String()...)
		}
	case reflect.Slice, reflect.Map:
		if v.IsNil() {
			return e.number(math.MaxUint64)
		}
		if err := e.number(uint64(v.Len())); err != nil {
			return err
		}
		if v.Kind() == reflect.Map {
			it := v.MapRange()
			for it.Next() {
				if err := e.value(it.Key()); err != nil {
					return err
				}
				if err := e.value(it.Value()); err != nil {
					return err
				}
			}
			return nil
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if err := addBudget(&e.size, uint64(v.Len()), e.max); err != nil {
				return err
			}
			if e.data != nil {
				e.data = append(e.data, v.Bytes()...)
			}
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported offline schema type %s", v.Type())
	}
	return nil
}

func writeRecord(w io.Writer, kind uint16, id PacketID, value any, max uint64) (uint64, error) {
	if (kind != recordKindSummary && kind != recordKindDetail) || max > uint64(int(^uint(0)>>1)) {
		return 0, fmt.Errorf("invalid offline record kind or budget")
	}
	wire, err := wireValue(value)
	if err != nil {
		return 0, err
	}
	if (kind == recordKindSummary) != (reflect.TypeOf(wire) == reflect.TypeOf(summaryWire{})) {
		return 0, fmt.Errorf("offline record kind mismatch")
	}
	if _, err = recordMemory(value, max); err != nil {
		return 0, err
	}
	e := encoder{max: max}
	if err = e.value(reflect.ValueOf(wire)); err != nil {
		return 0, err
	}
	size := e.size
	e = encoder{max: max, data: make([]byte, 0, int(size))}
	if err = e.value(reflect.ValueOf(wire)); err != nil {
		return 0, err
	}
	var h [frameHeaderBytes]byte
	copy(h[:4], "LCOF")
	binary.LittleEndian.PutUint16(h[4:6], RecordSchemaVersion)
	binary.LittleEndian.PutUint16(h[6:8], kind)
	binary.LittleEndian.PutUint64(h[8:16], size)
	binary.LittleEndian.PutUint64(h[16:24], uint64(id))
	binary.LittleEndian.PutUint32(h[24:28], crc32.ChecksumIEEE(e.data))
	n, err := w.Write(h[:])
	if err == nil && n != len(h) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return uint64(n), fmt.Errorf("write offline frame: %w", err)
	}
	m, err := w.Write(e.data)
	if err == nil && m != len(e.data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return uint64(n + m), fmt.Errorf("write offline payload: %w", err)
	}
	return uint64(n + m), nil
}

type decoder struct {
	data        []byte
	pos         int
	memory, max uint64
}

func (d *decoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.data)-d.pos) {
		return nil, io.ErrUnexpectedEOF
	}
	p := d.data[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return p, nil
}
func (d *decoder) number() (uint64, error) {
	p, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(p), nil
}
func (d *decoder) value(v reflect.Value) error {
	if v.Type() == timestampType {
		s, err := d.number()
		if err != nil {
			return err
		}
		ns, err := d.number()
		if err != nil {
			return err
		}
		if ns >= 1e9 {
			return fmt.Errorf("invalid offline timestamp nanoseconds")
		}
		v.Set(reflect.ValueOf(time.Unix(int64(s), int64(ns)).UTC()))
		return nil
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := d.value(v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Pointer:
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] == 0 {
			return nil
		}
		if p[0] != 1 {
			return fmt.Errorf("invalid offline pointer marker")
		}
		if err = addBudget(&d.memory, uint64(v.Type().Elem().Size()), d.max); err != nil {
			return err
		}
		v.Set(reflect.New(v.Type().Elem()))
		return d.value(v.Elem())
	case reflect.Bool:
		p, err := d.take(1)
		if err != nil {
			return err
		}
		if p[0] > 1 {
			return fmt.Errorf("invalid offline boolean")
		}
		v.SetBool(p[0] == 1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := d.number()
		if err != nil {
			return err
		}
		if v.OverflowInt(int64(n)) {
			return fmt.Errorf("offline integer overflow")
		}
		v.SetInt(int64(n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := d.number()
		if err != nil {
			return err
		}
		if v.OverflowUint(n) {
			return fmt.Errorf("offline integer overflow")
		}
		v.SetUint(n)
	case reflect.Float64:
		n, err := d.number()
		if err != nil {
			return err
		}
		v.SetFloat(math.Float64frombits(n))
	case reflect.String:
		n, err := d.number()
		if err != nil {
			return err
		}
		if err = addBudget(&d.memory, n, d.max); err != nil {
			return err
		}
		p, err := d.take(n)
		if err != nil {
			return err
		}
		v.SetString(string(p))
	case reflect.Slice, reflect.Map:
		n, err := d.number()
		if err != nil {
			return err
		}
		if n == math.MaxUint64 {
			return nil
		}
		// Every non-byte element occupies at least one payload byte. Check this
		// independently of the memory cap before allocating a backing array/map.
		if n > uint64(len(d.data)-d.pos) {
			return io.ErrUnexpectedEOF
		}
		size := uint64(128)
		if v.Kind() == reflect.Slice {
			size = uint64(v.Type().Elem().Size())
		}
		if err = addProduct(&d.memory, n, size, d.max); err != nil {
			return err
		}
		if v.Kind() == reflect.Map {
			if err = addBudget(&d.memory, 512, d.max); err != nil {
				return err
			}
			v.Set(reflect.MakeMapWithSize(v.Type(), int(n)))
			for i := uint64(0); i < n; i++ {
				k := reflect.New(v.Type().Key()).Elem()
				val := reflect.New(v.Type().Elem()).Elem()
				if err = d.value(k); err != nil {
					return err
				}
				if err = d.value(val); err != nil {
					return err
				}
				if v.MapIndex(k).IsValid() {
					return fmt.Errorf("duplicate offline map key")
				}
				v.SetMapIndex(k, val)
			}
			return nil
		}
		v.Set(reflect.MakeSlice(v.Type(), int(n), int(n)))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			p, err := d.take(n)
			if err != nil {
				return err
			}
			reflect.Copy(v, reflect.ValueOf(p))
			return nil
		}
		for i := 0; i < int(n); i++ {
			if err = d.value(v.Index(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported offline schema type %s", v.Type())
	}
	return nil
}

func readRecordAt(r io.ReaderAt, offset int64, kind uint16, id PacketID, max uint64, value any) (uint64, error) {
	var h [frameHeaderBytes]byte
	if offset < 0 || offset > math.MaxInt64-frameHeaderBytes {
		return 0, fmt.Errorf("invalid offline offset")
	}
	if _, err := r.ReadAt(h[:], offset); err != nil {
		return 0, fmt.Errorf("read offline frame: %w", err)
	}
	if string(h[:4]) != "LCOF" || binary.LittleEndian.Uint16(h[4:6]) != RecordSchemaVersion || binary.LittleEndian.Uint16(h[6:8]) != kind || binary.LittleEndian.Uint64(h[16:24]) != uint64(id) || !bytes.Equal(h[28:], []byte{0, 0, 0, 0}) {
		return 0, fmt.Errorf("invalid offline record frame/version/kind/id")
	}
	n := binary.LittleEndian.Uint64(h[8:16])
	if n > max || n > uint64(int(^uint(0)>>1)) || n > uint64(math.MaxInt64-offset-frameHeaderBytes) {
		return 0, fmt.Errorf("offline payload exceeds limit or offset range")
	}
	var target any
	switch value.(type) {
	case *Summary:
		if kind != recordKindSummary {
			return 0, fmt.Errorf("offline summary kind mismatch")
		}
		target = &summaryWire{}
	case *Detail:
		if kind != recordKindDetail {
			return 0, fmt.Errorf("offline detail kind mismatch")
		}
		target = &detailWire{}
	default:
		return 0, fmt.Errorf("unsupported offline destination %T", value)
	}
	// Check the actual backing stream size before payload allocation. All
	// production readers expose Stat or Size; a generic ReaderAt is bounded with
	// a one-byte probe at the declared end before any payload-sized allocation.
	end := offset + frameHeaderBytes + int64(n)
	switch sized := r.(type) {
	case interface{ Stat() (os.FileInfo, error) }:
		st, err := sized.Stat()
		if err != nil {
			return 0, fmt.Errorf("stat offline payload: %w", err)
		}
		if end > st.Size() {
			return 0, io.ErrUnexpectedEOF
		}
	case interface{ Size() int64 }:
		if end > sized.Size() {
			return 0, io.ErrUnexpectedEOF
		}
	default:
		if n > 0 {
			var last [1]byte
			if _, err := r.ReadAt(last[:], end-1); err != nil {
				return 0, fmt.Errorf("offline truncated payload: %w", err)
			}
		}
	}
	p := make([]byte, int(n))
	if _, err := r.ReadAt(p, offset+frameHeaderBytes); err != nil {
		return 0, fmt.Errorf("read offline payload: %w", err)
	}
	if crc32.ChecksumIEEE(p) != binary.LittleEndian.Uint32(h[24:28]) {
		return 0, fmt.Errorf("offline payload checksum mismatch")
	}
	v := reflect.ValueOf(target).Elem()
	d := decoder{data: p, max: max, memory: uint64(reflect.TypeOf(value).Elem().Size())}
	if d.memory > max {
		return 0, fmt.Errorf("offline record exceeds allocation limit")
	}
	if err := d.value(v); err != nil {
		return 0, fmt.Errorf("decode offline record: %w", err)
	}
	if d.pos != len(p) {
		return 0, fmt.Errorf("trailing offline payload data")
	}
	switch dest := value.(type) {
	case *Summary:
		w := target.(*summaryWire)
		*dest = Summary{ID: id, packet: w.Packet}
	case *Detail:
		w := target.(*detailWire)
		*dest = Detail{ID: id, Source: w.Source, CapturedLength: w.CapturedLength, OriginalLength: w.OriginalLength, Packet: w.Packet}
	}
	return n + frameHeaderBytes, nil
}

const streamHeaderBytes = 16

func writeStreamHeader(w io.Writer, kind uint16) (uint64, error) {
	var h [streamHeaderBytes]byte
	copy(h[:8], "LCODATA\x00")
	binary.LittleEndian.PutUint16(h[8:10], RecordSchemaVersion)
	binary.LittleEndian.PutUint16(h[10:12], kind)
	n, err := w.Write(h[:])
	if err == nil && n != len(h) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return uint64(n), fmt.Errorf("write offline stream header: %w", err)
	}
	return uint64(n), nil
}
func readStreamHeader(r io.ReaderAt, kind uint16) error {
	var h [streamHeaderBytes]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return fmt.Errorf("read offline stream header: %w", err)
	}
	if string(h[:8]) != "LCODATA\x00" || binary.LittleEndian.Uint16(h[8:10]) != RecordSchemaVersion || binary.LittleEndian.Uint16(h[10:12]) != kind || binary.LittleEndian.Uint32(h[12:]) != 0 {
		return fmt.Errorf("invalid offline stream header/version/kind")
	}
	return nil
}
