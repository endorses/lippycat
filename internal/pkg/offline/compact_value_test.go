package offline

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactValueSchemaNamesCoverFields(t *testing.T) {
	for typ, names := range compactFieldNames {
		require.Len(t, names, typ.NumField(), "schema update required for %s", typ)
		seen := map[string]bool{}
		for _, name := range names {
			_, ok := typ.FieldByName(name)
			require.True(t, ok, "schema field %s.%s", typ, name)
			require.False(t, seen[name])
			seen[name] = true
		}
	}
}
func TestCompactValueRoundTripAndColumns(t *testing.T) {
	values := []any{
		compactRow{Argument: 3, Sequence: 1 << 40, Locator: Locator{BackingID: 2, Offset: 1 << 35, Length: 7, Digest: [32]byte{1, 2, 3}}, Timestamp: time.Unix(-123, 456).UTC(), SrcIP: "::ffff:192.0.2.1", SrcPort: "", DstPort: "0", Info: "unique arbitrary text", Projection: compactProjection{Presence: 31, User: "alice", QueryName: "example", AnswerPresent: true, SNI: "server", ContentLength: -1}},
		compactOverrides{Mask: 31, Metadata: compactMetadata{VoIP: &types.VoIPMetadata{CSeqNumber: 42, ViaBranch: "z9hG4bK-test", Headers: map[string]string{"b": "2", "a": "1"}, RawSIP: []byte{}, AccessNetworkInfo: &types.AccessNetworkInfo{Parameters: map[string]string{}}}, DNS: &types.DNSMetadata{Answers: []types.DNSAnswer{{TTL: 45, Data: "192.0.2.1"}}}, TLS: &types.TLSMetadata{CipherSuites: []uint16{1, 65535}, Extensions: []uint16{}, ALPNProtocols: []string{"h2"}}, Email: &types.EmailMetadata{Timestamp: time.Time{}, RcptTo: []string{}}, HTTP: &types.HTTPMetadata{Headers: map[string]string{}, ContentLength: -1}}},
	}
	for _, value := range values {
		wire, err := encodeCompactValue(value, 1<<20)
		require.NoError(t, err)
		target := reflect.New(reflect.TypeOf(value))
		require.NoError(t, decodeCompactValue(wire, target.Interface(), 1<<20))
		require.Equal(t, value, target.Elem().Interface())
		cols, err := encodeCompactFields(value, 1<<20)
		require.NoError(t, err)
		require.Equal(t, wire, bytes.Join(cols, nil))
		require.NoError(t, decodeCompactFields(cols, target.Interface(), 1<<20))
		require.Equal(t, value, target.Elem().Interface())
		for i := 0; i < len(wire); i++ {
			require.Error(t, decodeCompactValue(wire[:i], target.Interface(), 1<<20))
		}
		require.Error(t, decodeCompactValue(append(wire, 0), target.Interface(), 1<<20))
	}
}
func TestCompactValueRejectsMalformedAndBudget(t *testing.T) {
	var text string
	wire := []byte{255, 255, 255, 255}
	require.Error(t, decodeCompactValue(wire, &text, 128))
	var ptr *types.HTTPMetadata
	require.Error(t, decodeCompactValue([]byte{2}, &ptr, 1<<20))
	var array []string
	require.Error(t, decodeCompactValue([]byte{2}, &array, 1<<20))
	var flag bool
	require.Error(t, decodeCompactValue([]byte{2}, &flag, 1<<20))
	var stamp time.Time
	timestamp := make([]byte, 12)
	binary.LittleEndian.PutUint32(timestamp[8:], 1e9)
	require.Error(t, decodeCompactValue(timestamp, &stamp, 1<<20))
	require.Error(t, decodeCompactValue([]byte{32}, &compactProjection{}, 1<<20))
	_, err := encodeCompactValue(string(make([]byte, 1024)), 512)
	require.Error(t, err)
	// No metadata presence occupies a single byte, with no empty protocol records.
	wire, err = encodeCompactValue(compactProjection{}, 1024)
	require.NoError(t, err)
	require.Equal(t, []byte{0}, wire)
}

func TestCompactValueFixedWidthsAndCanonicalMaps(t *testing.T) {
	for _, tc := range []struct {
		value any
		wire  []byte
	}{
		{uint8(255), []byte{255}},
		{int16(-2), []byte{254, 255}},
		{uint32(0x04030201), []byte{1, 2, 3, 4}},
		{int(-1), []byte{255, 255, 255, 255, 255, 255, 255, 255}},
		{"abc", []byte{3, 0, 0, 0, 'a', 'b', 'c'}},
		{[]byte(nil), []byte{0}},
		{[]byte{}, []byte{1, 0, 0, 0, 0}},
	} {
		wire, err := encodeCompactValue(tc.value, 1024)
		require.NoError(t, err)
		require.Equal(t, tc.wire, wire)
		target := reflect.New(reflect.TypeOf(tc.value))
		require.NoError(t, decodeCompactValue(wire, target.Interface(), 1024))
		require.Equal(t, tc.value, target.Elem().Interface())
	}
	m := map[string]string{"z": "last", "a": "first"}
	first, err := encodeCompactValue(m, 4096)
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		wire, err := encodeCompactValue(m, 4096)
		require.NoError(t, err)
		require.Equal(t, first, wire)
	}
}

// Pin schema-v2.3 field order, field types, integer widths and sparse projection
// groups. A declaration edit must never silently reinterpret completed blocks.
func TestCompactValueSchemaFingerprint(t *testing.T) {
	require.Equal(t, 3, compactSchemaMinor)
	var schema bytes.Buffer
	schema.WriteString("schema-v2.3; little-endian; int=8; timestamp=seconds8+nanos4; string=length4+bytes; container=presence1+length4; pointer=presence1; bool=1; float64=8; array=fixed-elements\n")
	var structs []reflect.Type
	for typ := range compactFieldNames {
		structs = append(structs, typ)
	}
	sort.Slice(structs, func(i, j int) bool { return structs[i].String() < structs[j].String() })
	for _, typ := range structs {
		for id, name := range compactFieldNames[typ] {
			field, ok := typ.FieldByName(name)
			require.True(t, ok)
			_, err := fmt.Fprintf(&schema, "%s.%s:%d:%s:%s", typ.PkgPath(), typ.Name(), id+1, name, field.Type)
			require.NoError(t, err)
			switch field.Type.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				_, err = fmt.Fprintf(&schema, ":width%d", compactIntegerBytes(field.Type.Kind()))
				require.NoError(t, err)
			}
			schema.WriteByte('\n')
		}
	}
	for i, fields := range compactProjectionGroups {
		_, err := fmt.Fprintf(&schema, "projection-bit%d:%q\n", i, fields)
		require.NoError(t, err)
	}
	digest := sha256.Sum256(schema.Bytes())
	require.Equal(t, "a0457446d3761fa99d61da39e52ec76266249b0bca7863f9c84faec5a34ec7c4", hex.EncodeToString(digest[:]), "schema-v2.3 changed: review compatibility and explicitly version the format")
}

func TestCompactValueRejectsDuplicateMapKeys(t *testing.T) {
	wire := []byte{1, 2, 0, 0, 0, 1, 0, 0, 0, 'a', 1, 0, 0, 0, 'x', 1, 0, 0, 0, 'a', 1, 0, 0, 0, 'y'}
	target := map[string]string{"existing": "unchanged"}
	require.ErrorContains(t, decodeCompactValue(wire, &target, 4096), "duplicate")
	require.Equal(t, map[string]string{"existing": "unchanged"}, target)
}
