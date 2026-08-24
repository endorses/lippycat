package conntrack

import (
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
	"net/netip"
	"testing"
	"time"
)

func testEnv(ts time.Time, reverse bool) events.Envelope {
	f := events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("198.51.100.2"), SourcePort: 40000, DestinationPort: 443}
	if reverse {
		f.SourceAddress, f.DestinationAddress = f.DestinationAddress, f.SourceAddress
		f.SourcePort, f.DestinationPort = f.DestinationPort, f.SourcePort
	}
	return events.Envelope{Timestamp: ts, UID: "Ctest", CommunityID: "1:test", NodeID: "hunter", Flow: f, CaptureScope: events.CaptureScopeFull}
}
func TestTCPStatesAndAccounting(t *testing.T) {
	now := time.Now()
	tr, err := New(Config{MaxFlows: 10, IdleTimeout: time.Minute, HalfOpenTimeout: time.Second})
	require.NoError(t, err)
	_, err = tr.Observe(Observation{Envelope: testEnv(now, false), IPBytes: 40, TCP: &TCPFlags{SYN: true}})
	require.NoError(t, err)
	_, _ = tr.Observe(Observation{Envelope: testEnv(now.Add(time.Millisecond), true), IPBytes: 40, TCP: &TCPFlags{SYN: true, ACK: true}})
	_, _ = tr.Observe(Observation{Envelope: testEnv(now.Add(2*time.Millisecond), false), IPBytes: 50, PayloadBytes: 10, TCP: &TCPFlags{ACK: true, FIN: true}})
	_, _ = tr.Observe(Observation{Envelope: testEnv(now.Add(3*time.Millisecond), true), IPBytes: 40, TCP: &TCPFlags{ACK: true, FIN: true}})
	got := tr.Close()
	require.Len(t, got, 1)
	require.Equal(t, "SF", got[0].State)
	require.Equal(t, uint64(2), got[0].OriginPackets)
	require.Equal(t, uint64(10), got[0].OriginBytes)
	require.False(t, got[0].Envelope().Partial)
	require.NotEmpty(t, got[0].History)
}
func TestPartialAndExpiry(t *testing.T) {
	now := time.Now()
	tr, _ := New(Config{MaxFlows: 10, IdleTimeout: time.Minute, HalfOpenTimeout: time.Second})
	_, _ = tr.Observe(Observation{Envelope: testEnv(now, false), IPBytes: 50, PayloadBytes: 10, TCP: &TCPFlags{ACK: true}})
	got := tr.Expire(now.Add(2 * time.Second))
	require.Len(t, got, 1)
	require.Equal(t, "OTH", got[0].State)
	require.True(t, got[0].Envelope().Partial)
	require.Empty(t, got[0].History)
}
func TestHardCapEvicts(t *testing.T) {
	tr, _ := New(Config{MaxFlows: 1, IdleTimeout: time.Minute, HalfOpenTimeout: time.Second})
	now := time.Now()
	_, _ = tr.Observe(Observation{Envelope: testEnv(now, false), TCP: &TCPFlags{SYN: true}})
	e := testEnv(now.Add(time.Second), false)
	e.Flow.SourcePort++
	got, _ := tr.Observe(Observation{Envelope: e, TCP: &TCPFlags{SYN: true}})
	require.Len(t, got, 1)
	require.Equal(t, 1, tr.Stats().Depth)
	require.Equal(t, uint64(1), tr.Stats().Evictions)
}

func BenchmarkTracker100kFlows(b *testing.B) {
	tr, _ := New(Config{MaxFlows: 100000, IdleTimeout: 5 * time.Minute, HalfOpenTimeout: 30 * time.Second})
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := testEnv(now, false)
		e.Flow.SourcePort = uint16(i % 65535)
		e.Flow.SourceAddress = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		_, _ = tr.Observe(Observation{Envelope: e, IPBytes: 60, TCP: &TCPFlags{SYN: true}})
	}
}
