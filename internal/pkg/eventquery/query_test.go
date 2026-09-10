package eventquery

import (
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func envelope() events.Envelope {
	return events.Envelope{Timestamp: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC), EventID: "event-1", UID: "C123", NodeID: "node-1", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), SourcePort: 1234, DestinationAddress: netip.MustParseAddr("198.51.100.2"), DestinationPort: 443}, Provenance: events.SourceProvenance{CaptureSource: "remote-west", InterfaceName: "eth0", ProcessorNodeIDs: []string{"processor-a", "processor-b"}}}
}

func httpEvent() events.Event {
	e := events.NewHTTPEvent(envelope())
	e.Method = "GET"
	e.Host = "Example Org"
	e.URI = "/download"
	e.UserAgent = "Firefox Hidden Agent"
	e.StatusCode = 404
	e.ResponseFilenames = []string{"report.pdf", "payload.bin"}
	return e
}

func smtpEvent() events.Event {
	e := events.NewSMTPEvent(envelope())
	e.Recipients = []string{"first@example.test", "Second@Example.test"}
	e.Subject = "Quarterly report"
	return e
}

func TestProjectionUsesCanonicalRecordAndEnvelope(t *testing.T) {
	p := Project(httpEvent())
	assert.Equal(t, events.KindHTTP, p.Kind)
	assert.Equal(t, "count", p.Fields["status_code"].Type)
	assert.Equal(t, []any{uint16(404)}, p.Fields["status_code"].Values)
	assert.Equal(t, []any{"Firefox Hidden Agent"}, p.Fields["user_agent"].Values)
	assert.Equal(t, []any{"processor-a", "processor-b"}, p.Fields["processor_node_ids"].Values)
}

func TestBareTextSearchesKindSummaryCanonicalAndProvenance(t *testing.T) {
	for _, q := range []string{"http", "download", "firefox hidden", "payload.bin", "REMOTE-WEST", "processor-b"} {
		pred, err := Compile(q)
		require.NoError(t, err, q)
		assert.True(t, pred(httpEvent()), q)
	}
	pred, err := Compile("missing")
	require.NoError(t, err)
	assert.False(t, pred(httpEvent()))
}

func TestKindsAliasesFieldsAndTypedComparisons(t *testing.T) {
	for _, q := range []string{"kind:http", "event:http", "node:node-1", "src:192.0.2.1", "dport:443", "status_code:>=400", "status_code:<500", "ts:>=2026-08-30T00:00:00Z"} {
		pred, err := Compile(q)
		require.NoError(t, err, q)
		assert.True(t, pred(httpEvent()), q)
	}
	conn := events.NewConnEvent(envelope())
	pred, err := Compile("conn")
	require.NoError(t, err)
	assert.True(t, pred(conn))
	for _, q := range []string{"kind:dns", "status_code:<400", "src:203.0.113.1"} {
		pred, err := Compile(q)
		require.NoError(t, err, q)
		assert.False(t, pred(httpEvent()), q)
	}
}

func TestBooleanCompositionQuotingListsAndEmptyValues(t *testing.T) {
	for _, q := range []string{`host:"Example Org" AND (status_code:404 OR status_code:500)`, `NOT kind:dns AND user_agent:firefox`, `rcptto:second@example.test`, `host:""`} {
		pred, err := Compile(q)
		require.NoError(t, err, q)
		event := httpEvent()
		if q == "rcptto:second@example.test" {
			event = smtpEvent()
		}
		assert.True(t, pred(event), q)
	}
	pred, err := Compile("kind:dns OR kind:smtp AND subject:missing")
	require.NoError(t, err)
	assert.False(t, pred(httpEvent()))
}

func TestDurationBooleanAndInvalidQueries(t *testing.T) {
	e := events.NewConnEvent(envelope())
	e.Duration = 1500 * time.Millisecond
	e.LocalOrigin = true
	for _, q := range []string{"duration:>1s", "duration:<=2s", "local_orig:true"} {
		pred, err := Compile(q)
		require.NoError(t, err)
		assert.True(t, pred(e), q)
	}
	for _, q := range []string{"", "unknown:value", "status_code:wat", "duration:later", "local_orig:perhaps", "(kind:http", "kind:"} {
		_, err := Compile(q)
		assert.Error(t, err, q)
	}
}

func TestRADIUSProjectionUsesObservationSchema(t *testing.T) {
	event := events.NewRADIUSEvent(envelope())
	event.Code, event.Identifier = 2, 42
	event.ObservationID, event.Association = "observation", "unique"
	event.Attributes = []string{"1:hex:616c696365"}
	projection := Project(event)
	require.Equal(t, events.KindRADIUS, projection.Kind)
	require.Contains(t, projection.Summary, "code=2 id=42")
	require.Equal(t, []any{"observation"}, projection.Fields["observation_id"].Values)
	pred, err := Compile("616c696365")
	require.NoError(t, err)
	require.True(t, pred(event))
}
