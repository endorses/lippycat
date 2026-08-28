package logstream

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logschema"
)

type encoder interface {
	Open(time.Time) error
	Encode(Record) error
	Close(time.Time) error
	Flush() error
}

type tsvEncoder struct {
	w      *bufio.Writer
	schema logschema.Stream
}

func newTSVEncoder(w io.Writer, schema logschema.Stream) encoder {
	return &tsvEncoder{bufio.NewWriter(w), schema}
}

func (e *tsvEncoder) Open(now time.Time) error {
	_, err := fmt.Fprintf(e.w, "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\t%s\n#open\t%s\n#fields", e.schema.Name, zeekClock(now))
	if err != nil {
		return err
	}
	for _, f := range e.schema.Fields {
		if _, err = fmt.Fprintf(e.w, "\t%s", f.Name); err != nil {
			return err
		}
	}
	if _, err = io.WriteString(e.w, "\n#types"); err != nil {
		return err
	}
	for _, f := range e.schema.Fields {
		if _, err = fmt.Fprintf(e.w, "\t%s", f.Type); err != nil {
			return err
		}
	}
	_, err = io.WriteString(e.w, "\n")
	return err
}

func (e *tsvEncoder) Encode(r Record) error {
	for i, value := range r.Values {
		if i > 0 {
			if err := e.w.WriteByte('\t'); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(e.w, formatTSV(value)); err != nil {
			return err
		}
	}
	return e.w.WriteByte('\n')
}
func (e *tsvEncoder) Close(now time.Time) error {
	_, err := fmt.Fprintf(e.w, "#close\t%s\n", zeekClock(now))
	return err
}
func (e *tsvEncoder) Flush() error { return e.w.Flush() }

type jsonEncoder struct {
	w      *bufio.Writer
	schema logschema.Stream
}

func newJSONEncoder(w io.Writer, schema logschema.Stream) encoder {
	return &jsonEncoder{bufio.NewWriter(w), schema}
}
func (e *jsonEncoder) Open(time.Time) error  { return nil }
func (e *jsonEncoder) Close(time.Time) error { return nil }
func (e *jsonEncoder) Flush() error          { return e.w.Flush() }
func (e *jsonEncoder) Encode(r Record) error {
	row := make(map[string]any, len(e.schema.Fields))
	for i, field := range e.schema.Fields {
		value := r.Values[i]
		if _, ok := value.(unsetValue); ok {
			value = nil
		}
		row[field.Name] = jsonValue(value)
	}
	b, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode JSON record: %w", err)
	}
	if _, err = e.w.Write(b); err != nil {
		return err
	}
	return e.w.WriteByte('\n')
}

func zeekClock(t time.Time) string { return t.UTC().Format("2006-01-02-15-04-05") }
func formatTSV(v any) string {
	if _, ok := v.(unsetValue); ok || v == nil {
		return "-"
	}
	switch value := v.(type) {
	case string:
		if value == "" {
			return "(empty)"
		}
		return escapeZeek(value)
	case time.Time:
		return strconv.FormatFloat(float64(value.UnixNano())/1e9, 'f', 6, 64)
	case time.Duration:
		return strconv.FormatFloat(value.Seconds(), 'f', 6, 64)
	case bool:
		if value {
			return "T"
		}
		return "F"
	case netip.Addr:
		if !value.IsValid() {
			return "-"
		}
		return value.String()
	}
	rv := reflect.ValueOf(v)
	if rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
		if rv.Len() == 0 {
			return "(empty)"
		}
		parts := make([]string, rv.Len())
		for i := range parts {
			parts[i] = strings.ReplaceAll(formatTSV(rv.Index(i).Interface()), ",", "\\x2c")
		}
		return strings.Join(parts, ",")
	}
	return escapeZeek(fmt.Sprint(v))
}
func escapeZeek(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c == '\\' || c == '\t' || c == '\n' || c == '\r' || c < 0x20 || c >= 0x7f {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
func jsonValue(v any) any {
	switch value := v.(type) {
	case time.Time:
		return float64(value.UnixNano()) / 1e9
	case time.Duration:
		return value.Seconds()
	case netip.Addr:
		if !value.IsValid() {
			return nil
		}
		return value.String()
	}

	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Interface, reflect.Pointer:
		if rv.IsNil() {
			return nil
		}
		return jsonValue(rv.Elem().Interface())
	case reflect.Slice:
		if rv.IsNil() {
			return nil
		}
		// Preserve encoding/json's base64 representation for byte slices.
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		fallthrough
	case reflect.Array:
		values := make([]any, rv.Len())
		for i := range values {
			values[i] = jsonValue(rv.Index(i).Interface())
		}
		return values
	case reflect.Map:
		if rv.IsNil() || rv.Type().Key().Kind() != reflect.String {
			return v
		}
		values := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			values[iter.Key().String()] = jsonValue(iter.Value().Interface())
		}
		return values
	default:
		return v
	}
}
