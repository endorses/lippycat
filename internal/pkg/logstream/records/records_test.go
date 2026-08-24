package records

import (
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

func TestDNSRecord(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", CommunityID: "1:test", NodeID: "hunter-a", Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53}}
	ev := events.NewDNSEvent(env)
	ev.TransactionID, ev.Query, ev.QClass, ev.QType = 42, "example.test", 1, 1
	record, emit, err := DNS(ev)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, record.Values, 26)
	require.Equal(t, "example.test", record.Values[9])
	require.Equal(t, "hunter-a", record.Values[25])
}

func TestSMTPRecord(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", CommunityID: "1:test", NodeID: "tap-a", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.25"), SourcePort: 40000, DestinationPort: 25}}
	ev := events.NewSMTPEvent(env)
	ev.MailFrom = "sender@example.test"
	ev.Recipients = []string{"receiver@example.test"}
	ev.Subject = "hello"
	record, emit, err := SMTP(ev)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, record.Values, 29)
	require.Equal(t, "sender@example.test", record.Values[8])
	require.Equal(t, "tap-a", record.Values[28])
}

func TestSSLAndHTTPRecords(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", CommunityID: "1:test", NodeID: "node-a", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 50000, DestinationPort: 443}}
	tlsEvent := events.NewTLSEvent(env)
	tlsEvent.ServerName = "example.test"
	sslRecord, emit, err := SSL(tlsEvent)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, sslRecord.Values, 26)
	require.Equal(t, "example.test", sslRecord.Values[9])

	httpEvent := events.NewHTTPEvent(env)
	httpEvent.Method, httpEvent.URI = "GET", "/"
	httpRecord, emit, err := HTTP(httpEvent)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, httpRecord.Values, 32)
	require.Equal(t, "GET", httpRecord.Values[7])
}

func TestConnRecord(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", CommunityID: "1:test", NodeID: "hunter-a", CaptureScope: events.CaptureScopeFiltered, Partial: true, Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 50000, DestinationPort: 443}}
	ev := events.NewConnEvent(env)
	ev.Service, ev.State, ev.Duration = "ssl", "S1", time.Second
	ev.OriginPackets, ev.OriginIPBytes = 2, 100
	record, emit, err := Conn(ev)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, record.Values, 24)
	require.Equal(t, "tcp", record.Values[6])
	require.Equal(t, "1:test", record.Values[20])
	require.Equal(t, true, record.Values[23])
}

func TestFilesRecordRejectsContent(t *testing.T) {
	env := events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", CommunityID: "1:test", NodeID: "hunter-a"}
	ev := events.NewFileMetadataEvent(env)
	ev.FileID, ev.Source, ev.MIMEType, ev.SHA256 = "FTEST", "HTTP", "text/plain", "abc"
	record, emit, err := Files(ev)
	require.NoError(t, err)
	require.True(t, emit)
	require.Len(t, record.Values, 23)
	require.Equal(t, "FTEST", record.Values[1])
	require.Equal(t, "hunter-a", record.Values[22])
	_, emit, err = Files(events.NewFileContentEvent(env))
	require.Error(t, err)
	require.False(t, emit)
}
