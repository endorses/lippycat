package offline

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompactRowEncoderMatchesSchema(t *testing.T) {
	var row compactRow
	fieldID := 0
	var fill func(reflect.Value)
	fill = func(v reflect.Value) {
		fieldID++
		if v.Type() == timestampType {
			v.Set(reflect.ValueOf(time.Unix(-123456, 987654321).UTC()))
			return
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				fill(v.Field(i))
			}
		case reflect.Array:
			for i := 0; i < v.Len(); i++ {
				v.Index(i).SetUint(uint64(i + 1))
			}
		case reflect.String:
			v.SetString(fmt.Sprintf("field-%d", fieldID))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v.SetInt(-int64(fieldID))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v.SetUint(uint64(fieldID))
		case reflect.Bool:
			v.SetBool(true)
		default:
			t.Fatalf("unhandled fixture type %v", v.Type())
		}
	}
	fill(reflect.ValueOf(&row).Elem())
	for mask := 0; mask < 32; mask++ {
		row.Projection.Presence = uint8(mask)
		fields, err := encodeCompactFields(row, 1<<20)
		require.NoError(t, err)
		want := bytes.Join(fields, nil)
		got, err := encodeCompactRow(&row, 1<<20, 0)
		require.NoError(t, err)
		require.Equal(t, want, got, "presence=%d", mask)
		got, err = encodeCompactRow(&row, 1<<20, 16)
		require.NoError(t, err)
		require.Equal(t, make([]byte, 16), got[:16])
		require.Equal(t, want, got[16:])
	}
	// Presence does not remove owned string memory from admission.
	row.Projection.Presence = 0
	for budget := uint64(0); budget < 4096; budget += 17 {
		_, referenceErr := encodeCompactFields(row, budget)
		_, err := encodeCompactRow(&row, budget, 16)
		require.Equal(t, referenceErr == nil, err == nil, "budget=%d", budget)
	}
	row.Projection.Presence = 32
	_, err := encodeCompactRow(&row, 1<<20, 0)
	require.ErrorContains(t, err, "presence")
}
