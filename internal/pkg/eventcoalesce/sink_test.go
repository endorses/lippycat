package eventcoalesce

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/stretchr/testify/require"
)

type collectingSink struct {
	mu     sync.Mutex
	events []events.Event
}

func (s *collectingSink) HandleEvent(_ context.Context, ev events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}
func (*collectingSink) Flush(context.Context) error { return nil }
func (*collectingSink) Close(context.Context) error { return nil }
func (s *collectingSink) snapshot() []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.Event(nil), s.events...)
}

func envelope() events.Envelope {
	return events.Envelope{Timestamp: time.Unix(1, 0), UID: "Ctest", Flow: events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 50000, DestinationPort: 443}}
}

func TestHTTPPairEmitsSingleCombinedTransaction(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
	req := events.NewHTTPEvent(envelope())
	req.TransactionDepth, req.Method, req.URI, req.RequestBodyLength = 1, "POST", "/items", 12
	resp := events.NewHTTPEvent(envelope())
	resp.StatusCode, resp.StatusMessage, resp.ResponseBodyLength = 201, "Created", 34
	require.NoError(t, sink.HandleEvent(context.Background(), req))
	require.Empty(t, next.snapshot())
	require.NoError(t, sink.HandleEvent(context.Background(), resp))
	got := next.snapshot()
	require.Len(t, got, 1)
	http := got[0].(events.HTTPEvent)
	require.Equal(t, "POST", http.Method)
	require.Equal(t, "/items", http.URI)
	require.Equal(t, uint16(201), http.StatusCode)
	require.Equal(t, uint64(34), http.ResponseBodyLength)
}

func TestHTTPInformationalResponseWaitsForFinalResponse(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
	req := events.NewHTTPEvent(envelope())
	req.TransactionDepth, req.Method, req.URI = 1, "POST", "/upload"
	info := events.NewHTTPEvent(envelope())
	info.StatusCode, info.StatusMessage = 100, "Continue"
	final := events.NewHTTPEvent(envelope())
	final.StatusCode, final.StatusMessage = 201, "Created"

	require.NoError(t, sink.HandleEvent(context.Background(), req))
	require.NoError(t, sink.HandleEvent(context.Background(), info))
	require.Empty(t, next.snapshot())
	require.NoError(t, sink.HandleEvent(context.Background(), final))
	got := next.snapshot()
	require.Len(t, got, 1)
	http := got[0].(events.HTTPEvent)
	require.Equal(t, uint16(100), http.InformationalCode)
	require.Equal(t, "Continue", http.InformationalMessage)
	require.Equal(t, uint16(201), http.StatusCode)
}

func TestTLSPairEmitsSingleCombinedHandshake(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
	client := events.NewTLSEvent(envelope())
	client.ServerName, client.JA3 = "example.test", "client"
	server := events.NewTLSEvent(envelope())
	server.Version, server.Cipher, server.JA3S, server.Established = "TLS 1.3", "0x1301", "server", true
	require.NoError(t, sink.HandleEvent(context.Background(), client))
	require.NoError(t, sink.HandleEvent(context.Background(), server))
	got := next.snapshot()
	require.Len(t, got, 1)
	tls := got[0].(events.TLSEvent)
	require.Equal(t, "example.test", tls.ServerName)
	require.Equal(t, "client", tls.JA3)
	require.Equal(t, "server", tls.JA3S)
	require.Equal(t, "0x1301", tls.Cipher)
}

func TestDNSPairEmitsSingleCombinedTransaction(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })

	query := events.NewDNSEvent(envelope())
	query.TransactionID, query.Query, query.QClass, query.QType = 42, "example.test", 1, 1
	query.RecursionDesired = true
	responseEnv := envelope()
	responseEnv.Timestamp = responseEnv.Timestamp.Add(25 * time.Millisecond)
	response := events.NewDNSEvent(responseEnv)
	response.IsResponse, response.TransactionID = true, 42
	response.Authoritative, response.RecursionAvailable = true, true
	response.Answers = []string{"192.0.2.10"}
	response.TTLs = []time.Duration{time.Minute}

	require.NoError(t, sink.HandleEvent(context.Background(), query))
	require.Empty(t, next.snapshot())
	require.NoError(t, sink.HandleEvent(context.Background(), response))
	got := next.snapshot()
	require.Len(t, got, 1)
	dns := got[0].(events.DNSEvent)
	require.Equal(t, "example.test", dns.Query)
	require.Equal(t, uint16(1), dns.QType)
	require.True(t, dns.RecursionDesired)
	require.True(t, dns.Authoritative)
	require.True(t, dns.RecursionAvailable)
	require.Equal(t, []string{"192.0.2.10"}, dns.Answers)
	require.Equal(t, []time.Duration{time.Minute}, dns.TTLs)
	require.Equal(t, 25*time.Millisecond, dns.RTT)
}

func TestDNSCorrelationSeparatesTransportAndQueuesReusedIDs(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })

	udp := events.NewDNSEvent(envelope())
	udp.TransactionID, udp.Query = 7, "first.test"
	tcpEnv := envelope()
	tcpEnv.Flow.Protocol = 17
	tcp := events.NewDNSEvent(tcpEnv)
	tcp.TransactionID, tcp.Query = 7, "other-transport.test"
	second := events.NewDNSEvent(envelope())
	second.TransactionID, second.Query = 7, "second.test"
	response := events.NewDNSEvent(envelope())
	response.IsResponse, response.TransactionID = true, 7

	require.NoError(t, sink.HandleEvent(context.Background(), udp))
	require.NoError(t, sink.HandleEvent(context.Background(), tcp))
	require.NoError(t, sink.HandleEvent(context.Background(), second))
	require.NoError(t, sink.HandleEvent(context.Background(), response))
	require.Equal(t, "first.test", next.snapshot()[0].(events.DNSEvent).Query)
	require.NoError(t, sink.HandleEvent(context.Background(), response))
	require.Equal(t, "second.test", next.snapshot()[1].(events.DNSEvent).Query)
	require.NoError(t, sink.Flush(context.Background()))
	require.Equal(t, "other-transport.test", next.snapshot()[2].(events.DNSEvent).Query)
}

func TestUnmatchedDNSResponsePassesThrough(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close(context.Background())) })
	response := events.NewDNSEvent(envelope())
	response.IsResponse, response.TransactionID = true, 99
	require.NoError(t, sink.HandleEvent(context.Background(), response))
	require.Len(t, next.snapshot(), 1)
}

func TestDNSPendingIsBoundedAndExpiresAsPartial(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: 20 * time.Millisecond, MaxPending: 1})
	require.NoError(t, err)
	first := events.NewDNSEvent(envelope())
	first.TransactionID, first.Query = 1, "evicted.test"
	second := events.NewDNSEvent(envelope())
	second.TransactionID, second.Query = 2, "expired.test"
	require.NoError(t, sink.HandleEvent(context.Background(), first))
	require.NoError(t, sink.HandleEvent(context.Background(), second))
	require.Equal(t, "evicted.test", next.snapshot()[0].(events.DNSEvent).Query)
	require.Eventually(t, func() bool { return len(next.snapshot()) == 2 }, time.Second, 5*time.Millisecond)
	require.Equal(t, "expired.test", next.snapshot()[1].(events.DNSEvent).Query)
	require.NoError(t, sink.Close(context.Background()))
}

func TestEmptyTLSAfterCombinedHandshakeIsSuppressed(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: 10 * time.Millisecond, MaxPending: 10})
	require.NoError(t, err)
	client := events.NewTLSEvent(envelope())
	client.ServerName, client.JA3 = "example.test", "client"
	server := events.NewTLSEvent(envelope())
	server.Version, server.Cipher, server.JA3S, server.Established = "TLS 1.3", "0x1301", "server", true

	require.NoError(t, sink.HandleEvent(context.Background(), client))
	require.NoError(t, sink.HandleEvent(context.Background(), server))
	// A protobuf TLSMetadata{} maps to this zero-value protocol event. It must
	// not become a second row when the coalescer expires or flushes.
	require.NoError(t, sink.HandleEvent(context.Background(), events.NewTLSEvent(envelope())))
	time.Sleep(25 * time.Millisecond)
	require.NoError(t, sink.Flush(context.Background()))
	require.Len(t, next.snapshot(), 1)
	require.NoError(t, sink.Close(context.Background()))
}

func TestIncompleteMeaningfulTLSIsEmitted(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Hour, MaxPending: 10})
	require.NoError(t, err)
	partial := events.NewTLSEvent(envelope())
	partial.Version = "TLS 1.2"

	require.NoError(t, sink.HandleEvent(context.Background(), partial))
	require.Empty(t, next.snapshot())
	require.NoError(t, sink.Flush(context.Background()))
	got := next.snapshot()
	require.Len(t, got, 1)
	require.Equal(t, "TLS 1.2", got[0].(events.TLSEvent).Version)
	require.NoError(t, sink.Close(context.Background()))
}

func TestExpiredIncompleteEventIsEmitted(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: 10 * time.Millisecond, MaxPending: 10})
	require.NoError(t, err)
	request := events.NewHTTPEvent(envelope())
	request.Method = "GET"
	require.NoError(t, sink.HandleEvent(context.Background(), request))
	require.Eventually(t, func() bool { return len(next.snapshot()) == 1 }, time.Second, 5*time.Millisecond)
	require.NoError(t, sink.Close(context.Background()))
}

func TestFlushEmitsPendingAndPassesOtherEvents(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Second, MaxPending: 10})
	require.NoError(t, err)
	smtp := events.NewSMTPEvent(envelope())
	require.NoError(t, sink.HandleEvent(context.Background(), smtp))
	request := events.NewHTTPEvent(envelope())
	request.Method = "GET"
	require.NoError(t, sink.HandleEvent(context.Background(), request))
	require.Len(t, next.snapshot(), 1)
	require.NoError(t, sink.Flush(context.Background()))
	require.Len(t, next.snapshot(), 2)
	require.NoError(t, sink.Close(context.Background()))
}

func TestCloseEmitsPending(t *testing.T) {
	next := &collectingSink{}
	sink, err := New(next, Config{Timeout: time.Hour, MaxPending: 10})
	require.NoError(t, err)
	request := events.NewHTTPEvent(envelope())
	request.Method = "GET"
	require.NoError(t, sink.HandleEvent(context.Background(), request))
	require.NoError(t, sink.Close(context.Background()))
	require.Len(t, next.snapshot(), 1)
}
