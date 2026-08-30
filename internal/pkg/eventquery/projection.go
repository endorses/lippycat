// Package eventquery projects normalized events onto the canonical log schema
// and compiles user-facing predicates over those projections.
package eventquery

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
	"github.com/endorses/lippycat/internal/pkg/logstream"
	"github.com/endorses/lippycat/internal/pkg/logstream/records"
)

// Value is one canonical field value. Lists retain their members so queries
// match any member rather than a renderer-specific joined representation.
type Value struct {
	Type   string
	Values []any
}

// Projection is the shared, presentation-neutral view of an event.
type Projection struct {
	Event   events.Event
	Kind    events.Kind
	Summary string
	Fields  map[string]Value
}

// Project maps event to canonical logschema fields plus envelope/provenance
// fields. Unsupported content events still expose their envelope.
func Project(event events.Event) Projection {
	p := Projection{Event: event, Fields: make(map[string]Value)}
	if event == nil {
		return p
	}
	p.Kind, p.Summary = event.Kind(), Summary(event)
	env := event.Envelope()
	add := func(name, typ string, values ...any) { p.Fields[name] = Value{Type: typ, Values: values} }
	add("ts", "time", env.Timestamp)
	add("uid", "string", env.UID)
	add("id.orig_h", "addr", env.Flow.SourceAddress)
	add("id.orig_p", "port", uint64(env.Flow.SourcePort))
	add("id.resp_h", "addr", env.Flow.DestinationAddress)
	add("id.resp_p", "port", uint64(env.Flow.DestinationPort))
	add("proto", "enum", uint64(env.Flow.Protocol))
	add("community_id", "string", env.CommunityID)
	add("node_id", "string", env.NodeID)
	add("capture_scope", "enum", string(env.CaptureScope))
	add("partial", "bool", env.Partial)
	add("event_id", "string", env.EventID)
	add("producer_session_id", "string", env.ProducerSessionID)
	add("event_sequence", "count", env.EventSequence)
	add("capture_source", "string", env.Provenance.CaptureSource)
	add("interface_name", "string", env.Provenance.InterfaceName)
	add("interface_index", "count", uint64(env.Provenance.InterfaceIndex))
	add("input_file", "string", env.Provenance.InputFile)
	add("processor_node_ids", "vector[string]", stringsToAny(env.Provenance.ProcessorNodeIDs)...)
	if record, ok := canonicalRecord(event); ok {
		schema, _ := logschema.ByName(record.Stream)
		for i, field := range schema.Fields {
			if record.Values[i] == logstream.Unset {
				continue
			}
			p.Fields[field.Name] = Value{Type: field.Type, Values: anyValues(record.Values[i])}
		}
	}
	return p
}

func canonicalRecord(event events.Event) (logstream.Record, bool) {
	var build logstream.Builder
	switch event.Kind() {
	case events.KindConn:
		build = records.Conn
	case events.KindDNS:
		build = records.DNS
	case events.KindTLS:
		build = records.SSL
	case events.KindHTTP:
		build = records.HTTP
	case events.KindSMTP:
		build = records.SMTP
	case events.KindFileMetadata:
		build = records.Files
	default:
		return logstream.Record{}, false
	}
	record, ok, err := build(event)
	return record, ok && err == nil
}

func anyValues(v any) []any {
	switch x := v.(type) {
	case []string:
		return stringsToAny(x)
	case []time.Duration:
		r := make([]any, len(x))
		for i := range x {
			r[i] = x[i]
		}
		return r
	default:
		return []any{v}
	}
}
func stringsToAny(v []string) []any {
	r := make([]any, len(v))
	for i := range v {
		r[i] = v[i]
	}
	return r
}

// Summary returns the same compact summary used by event timelines.
func Summary(event events.Event) string {
	switch e := event.(type) {
	case events.DNSEvent:
		return strings.TrimSpace(fmt.Sprintf("%s qtype=%d rcode=%d", e.Query, e.QType, e.RCode))
	case events.HTTPEvent:
		return strings.TrimSpace(fmt.Sprintf("%s %s%s status=%d", e.Method, e.Host, e.URI, e.StatusCode))
	case events.TLSEvent:
		return strings.TrimSpace(fmt.Sprintf("%s %s %s", e.ServerName, e.Version, e.ValidationStatus))
	case events.SMTPEvent:
		return strings.TrimSpace(fmt.Sprintf("%s -> %s %s", e.MailFrom, strings.Join(e.Recipients, ","), e.Subject))
	case events.ConnEvent:
		return strings.TrimSpace(fmt.Sprintf("%s %s %s", e.Service, e.State, e.Duration))
	case events.FileMetadataEvent:
		return strings.TrimSpace(fmt.Sprintf("%s %s %dB", e.Filename, e.MIMEType, e.SeenBytes))
	default:
		return ""
	}
}
