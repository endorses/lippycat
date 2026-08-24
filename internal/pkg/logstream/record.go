// Package logstream writes normalized protocol events to rotating structured logs.
package logstream

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/logschema"
)

// Unset marks a field whose value is unavailable. TSV renders it as "-" and
// JSON renders it as null. Empty strings remain distinct and render as Zeek's
// empty-field marker in TSV.
type unsetValue struct{}

var Unset = unsetValue{}

// Record is a row in a registered log schema. Values follow schema field order.
type Record struct {
	Stream string
	Values []any
}

func NewRecord(stream string, values ...any) (Record, error) {
	schema, ok := logschema.ByName(stream)
	if !ok {
		return Record{}, fmt.Errorf("unknown log stream %q", stream)
	}
	if len(values) != len(schema.Fields) {
		return Record{}, fmt.Errorf("log stream %q: got %d values, want %d", stream, len(values), len(schema.Fields))
	}
	return Record{Stream: stream, Values: values}, nil
}
