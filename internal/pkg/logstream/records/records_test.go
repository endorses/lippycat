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
