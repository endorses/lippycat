package offline

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func filledValue(v reflect.Value) {
	if v.Type() == timestampType {
		v.Set(reflect.ValueOf(time.Date(2400, 2, 29, 3, 4, 5, 123456789, time.UTC)))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			filledValue(v.Field(i))
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		filledValue(v.Elem())
	case reflect.String:
		v.SetString("héllo\x00" + v.Type().String())
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(27)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(42)
	case reflect.Float64:
		v.SetFloat(0.125)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		for i := 0; i < v.Len(); i++ {
			filledValue(v.Index(i))
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		k := reflect.New(v.Type().Key()).Elem()
		val := reflect.New(v.Type().Elem()).Elem()
		filledValue(k)
		filledValue(val)
		v.SetMapIndex(k, val)
	default:
		panic(v.Type().String())
	}
}
func TestCodecAllMetadataRoundTrip(t *testing.T) {
	var original Detail
	filledValue(reflect.ValueOf(&original).Elem())
	original.Token = Token{}
	original.ID = 123
	original.Source.Path = "/exact/input/a.pcapng"
	original.Packet.LinkType = layers.LinkTypeRaw
	// Raw bytes represent effective reassembled/decapsulated bytes, independent
	// of source framing and of the original wire length.
	original.Packet.RawData = []byte{0x45, 0, 0, 20}
	original.CapturedLength = 4
	original.OriginalLength = 200
	var b bytes.Buffer
	n, err := writeRecord(&b, recordKindDetail, original.ID, original, 1<<20)
	require.NoError(t, err)
	require.Equal(t, uint64(b.Len()), n)
	var actual Detail
	_, err = readRecordAt(bytes.NewReader(b.Bytes()), 0, recordKindDetail, original.ID, 1<<20, &actual)
	require.NoError(t, err)
	require.Equal(t, original, actual)
	s := NewSummary(original.ID, original.Packet)
	b.Reset()
	_, err = writeRecord(&b, recordKindSummary, s.ID, s, 1<<20)
	require.NoError(t, err)
	var decoded Summary
	_, err = readRecordAt(bytes.NewReader(b.Bytes()), 0, recordKindSummary, s.ID, 1<<20, &decoded)
	require.NoError(t, err)
	require.Equal(t, s, decoded)
	original.Packet.RawData[0] = 0
	original.Packet.VoIPData.Headers["changed"] = "yes"
	require.Equal(t, byte(0x45), actual.Packet.RawData[0])
	require.NotContains(t, actual.Packet.VoIPData.Headers, "changed")
}
func TestCodecNilEmptyAndTimestampRange(t *testing.T) {
	for _, stamp := range []time.Time{{}, time.Unix(-2, 123).UTC(), time.Date(12000, 1, 1, 0, 0, 0, 999999999, time.UTC)} {
		for _, empty := range []bool{false, true} {
			p := types.PacketDisplay{Timestamp: stamp, EmailData: &types.EmailMetadata{Timestamp: stamp}, TLSData: &types.TLSMetadata{}, HTTPData: &types.HTTPMetadata{}}
			if empty {
				p.RawData = []byte{}
				p.TLSData.CipherSuites = []uint16{}
				p.HTTPData.Headers = map[string]string{}
			}
			want := Detail{Packet: p}
			var b bytes.Buffer
			_, err := writeRecord(&b, recordKindDetail, 0, want, 1<<20)
			require.NoError(t, err)
			var got Detail
			_, err = readRecordAt(bytes.NewReader(b.Bytes()), 0, recordKindDetail, 0, 1<<20, &got)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	}
}
func TestCodecCorruption(t *testing.T) {
	var b bytes.Buffer
	_, err := writeRecord(&b, recordKindDetail, 7, Detail{}, 1<<20)
	require.NoError(t, err)
	valid := b.Bytes()
	for _, at := range []int{0, 4, 6, 8, 16, 24, 28, 32, len(valid) - 1} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			p := bytes.Clone(valid)
			p[at] ^= 0xff
			var d Detail
			_, err := readRecordAt(bytes.NewReader(p), 0, recordKindDetail, 7, 1<<20, &d)
			require.Error(t, err)
		})
	}
	for i := 0; i < len(valid); i++ {
		var d Detail
		_, err := readRecordAt(bytes.NewReader(valid[:i]), 0, recordKindDetail, 7, 1<<20, &d)
		require.Error(t, err, "truncation %d", i)
	}
	var d Detail
	_, err = readRecordAt(bytes.NewReader(valid), math.MaxInt64-1, recordKindDetail, 7, 1<<20, &d)
	require.Error(t, err)
	// A syntactically framed record with a malicious string length must fail
	// before allocating it, even if its checksum is correct.
	p := bytes.Clone(valid)
	binary.LittleEndian.PutUint64(p[40:48], math.MaxUint64)
	binary.LittleEndian.PutUint32(p[24:28], crc32.ChecksumIEEE(p[32:]))
	_, err = readRecordAt(bytes.NewReader(p), 0, recordKindDetail, 7, 1<<20, &d)
	require.Error(t, err)
	p = append(bytes.Clone(valid), 0)
	binary.LittleEndian.PutUint64(p[8:16], uint64(len(p)-32))
	binary.LittleEndian.PutUint32(p[24:28], crc32.ChecksumIEEE(p[32:]))
	_, err = readRecordAt(bytes.NewReader(p), 0, recordKindDetail, 7, 1<<20, &d)
	require.ErrorContains(t, err, "trailing")
}
func TestCodecAllocationLimits(t *testing.T) {
	var b bytes.Buffer
	huge := Detail{Packet: types.PacketDisplay{RawData: make([]byte, 1<<20)}}
	_, err := writeRecord(&b, recordKindDetail, 0, huge, 1024)
	require.Error(t, err)
	require.Zero(t, b.Len())
	allocs := testing.AllocsPerRun(5, func() { _, _ = writeRecord(io.Discard, recordKindDetail, 0, huge, 1024) })
	require.Less(t, allocs, float64(40))
	for _, p := range [][]byte{{2}, {1}, {255}} {
		d := decoder{data: p, max: 1024}
		var v bool
		err = d.value(reflect.ValueOf(&v).Elem())
		if p[0] > 1 {
			require.Error(t, err)
		}
	}
	var hugeLength [8]byte
	binary.LittleEndian.PutUint64(hugeLength[:], 1<<40)
	d := decoder{data: hugeLength[:], max: 1024}
	var strings []string
	require.Error(t, d.value(reflect.ValueOf(&strings).Elem()))
	require.Nil(t, strings)
}

type shortCodecWriter struct{}

func (shortCodecWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestCodecStreamHeadersAndShortWrites(t *testing.T) {
	var b bytes.Buffer
	n, err := writeStreamHeader(&b, recordKindDetail)
	require.NoError(t, err)
	require.Equal(t, uint64(16), n)
	require.NoError(t, readStreamHeader(bytes.NewReader(b.Bytes()), recordKindDetail))
	require.Error(t, readStreamHeader(bytes.NewReader(b.Bytes()), recordKindSummary))
	for i := 0; i < 16; i++ {
		p := bytes.Clone(b.Bytes())
		p[i] ^= 255
		require.Error(t, readStreamHeader(bytes.NewReader(p), recordKindDetail))
	}
	_, err = writeStreamHeader(shortCodecWriter{}, recordKindDetail)
	require.ErrorIs(t, err, io.ErrShortWrite)
	_, err = writeRecord(shortCodecWriter{}, recordKindDetail, 0, Detail{}, 1<<20)
	require.ErrorIs(t, err, io.ErrShortWrite)
}
func schemaShape(t reflect.Type, b *strings.Builder) {
	b.WriteString(t.String())
	b.WriteByte('[')
	if t != timestampType {
		switch t.Kind() {
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				b.WriteString(t.Field(i).Name)
				b.WriteByte(':')
				schemaShape(t.Field(i).Type, b)
			}
		case reflect.Slice, reflect.Pointer:
			schemaShape(t.Elem(), b)
		case reflect.Map:
			schemaShape(t.Key(), b)
			schemaShape(t.Elem(), b)
		}
	}
	b.WriteByte(']')
}
func TestCodecSchemaV1Shape(t *testing.T) {
	var b strings.Builder
	schemaShape(reflect.TypeOf(summaryWire{}), &b)
	schemaShape(reflect.TypeOf(detailWire{}), &b)
	require.Equal(t, "9c090c8f9071bed585cf8e10b39f1d9bbdfb7d65f8b4a0b768baa088732c9105", fmt.Sprintf("%x", sha256.Sum256([]byte(b.String()))), "Persisted field layout changed: explicitly version the schema before accepting the new shape")
}

func TestCodecTruncatedPayloadCheckedBeforeAllocation(t *testing.T) {
	var b bytes.Buffer
	_, err := writeRecord(&b, recordKindDetail, 0, Detail{}, 1<<20)
	require.NoError(t, err)
	h := bytes.Clone(b.Bytes()[:frameHeaderBytes])
	binary.LittleEndian.PutUint64(h[8:16], 1<<40)
	var d Detail
	_, err = readRecordAt(bytes.NewReader(h), 0, recordKindDetail, 0, 1<<40, &d)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestCodecDecodedAmplificationCheckedBeforeAllocation(t *testing.T) {
	// The encoded slice count fits the payload, but the backing string headers
	// do not fit the decoded budget. The destination must remain nil.
	p := make([]byte, 8+128)
	binary.LittleEndian.PutUint64(p[:8], 128)
	d := decoder{data: p, max: 256}
	var result []string
	require.ErrorContains(t, d.value(reflect.ValueOf(&result).Elem()), "allocation limit")
	require.Nil(t, result)
	// Non-nil maps also charge a base bucket/header allowance when empty.
	d = decoder{data: make([]byte, 8), max: 128}
	var m map[string]string
	require.ErrorContains(t, d.value(reflect.ValueOf(&m).Elem()), "allocation limit")
	require.Nil(t, m)
}

func TestBorrowedFrameValidationAndOwnership(t *testing.T) {
	const budget = 16 << 10
	var encoded bytes.Buffer
	_, err := writeRecord(&encoded, recordKindDetail, 7, Detail{Packet: types.PacketDisplay{RawData: []byte("original"), Info: "metadata"}}, budget)
	require.NoError(t, err)
	good := encoded.Bytes()
	var decoded Detail
	_, err = readRecordAt(frameReader{Reader: bytes.NewReader(good), data: good}, 0, recordKindDetail, 7, budget, &decoded)
	require.NoError(t, err)
	decoded.Packet.RawData[0] = 'X'
	_, err = readRecordAt(frameReader{Reader: bytes.NewReader(good), data: good}, 0, recordKindDetail, 7, budget, &decoded)
	require.NoError(t, err)
	require.Equal(t, "original", string(decoded.Packet.RawData))
	for _, damage := range []string{"header", "truncated", "declared length", "checksum"} {
		t.Run(damage, func(t *testing.T) {
			data := append([]byte(nil), good...)
			switch damage {
			case "header":
				data[0] = 0
			case "truncated":
				data = data[:len(data)-1]
			case "declared length":
				binary.LittleEndian.PutUint64(data[8:16], uint64(len(data)))
			case "checksum":
				data[len(data)-1] ^= 0xff
			}
			_, err := readRecordAt(frameReader{Reader: bytes.NewReader(data), data: data}, 0, recordKindDetail, 7, budget, &Detail{})
			require.Error(t, err)
		})
	}
}

func TestBorrowedRecordFieldsPreserveSchemaAndBudgets(t *testing.T) {
	var detail Detail
	filledValue(reflect.ValueOf(&detail).Elem())
	summary := NewSummary(detail.ID, detail.Packet)
	for _, tc := range []struct {
		name                  string
		value, borrowed, wire any
		kind                  uint16
	}{
		{"detail", detail, &detail, detailWire{detail.Source, detail.CapturedLength, detail.OriginalLength, detail.Packet}, recordKindDetail},
		{"summary", summary, &summary, summaryWire{summary.packet}, recordKindSummary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const max = 1 << 20
			measured, err := recordMemory(tc.value, max)
			require.NoError(t, err)
			borrowedMemory, err := recordMemory(tc.borrowed, max)
			require.NoError(t, err)
			require.Equal(t, measured, borrowedMemory)
			_, err = recordMemory(tc.borrowed, measured-1)
			require.Error(t, err)
			_, err = recordMemory(tc.borrowed, measured)
			require.NoError(t, err)

			// Compare the payload against the original declaration-order wire schema.
			legacy := encoder{max: max, data: make([]byte, 0)}
			require.NoError(t, legacy.value(reflect.ValueOf(tc.wire)))
			var frame bytes.Buffer
			_, err = writeValidatedRecord(&frame, tc.kind, 7, tc.borrowed, max)
			require.NoError(t, err)
			require.Equal(t, legacy.data, frame.Bytes()[frameHeaderBytes:])
			var checked bytes.Buffer
			_, err = writeRecord(&checked, tc.kind, 7, tc.borrowed, max)
			require.NoError(t, err)
			require.Equal(t, frame.Bytes(), checked.Bytes())
			_, err = writeRecord(io.Discard, tc.kind, 7, tc.borrowed, measured-1)
			require.Error(t, err)
		})
	}
}
