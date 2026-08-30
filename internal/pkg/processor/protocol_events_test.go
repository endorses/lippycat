//go:build processor || tap || all

package processor

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
)

type collectingSink struct {
	mu     sync.Mutex
	events []events.Event
}

func TestProtocolMetadataWritesStructuredLogs(t *testing.T) {
	dir := t.TempDir()
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16, LogConfig: &StructuredLogConfig{Enabled: true, Directory: dir, Format: "json", Streams: []string{"dns", "ssl", "http", "smtp"}, QueueSize: 16, EmitStage: "all"}})
	require.NoError(t, err)
	require.NoError(t, p.logSink.Start(context.Background()))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{
		{TimestampNs: time.Unix(10, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Dns: &data.DNSMetadata{TransactionId: 7, QueryName: "example.test", QueryType: "A", QueryClass: "IN"}}},
		{TimestampNs: time.Unix(11, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.25", SrcPort: 40000, DstPort: 25, Transport: "tcp", Email: &data.EmailMetadata{MailFrom: "sender@example.test", RcptTo: []string{"receiver@example.test"}, Subject: "hello"}}},
		{TimestampNs: time.Unix(12, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.20", SrcPort: 51000, DstPort: 443, Transport: "tcp", Tls: &data.TLSMetadata{Version: "TLS 1.3", Sni: "tls.example.test", Ja3: "ja3"}}},
		{TimestampNs: time.Unix(13, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.20", DstIp: "192.0.2.10", SrcPort: 80, DstPort: 52000, Transport: "tcp", Http: &data.HTTPMetadata{Type: "response", IsServer: true, Version: "HTTP/1.1", StatusCode: 200, StatusReason: "OK"}}},
	})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	for name, expected := range map[string]string{"dns.log": "example.test", "smtp.log": "sender@example.test"} {
		contents, readErr := os.ReadFile(dir + "/" + name)
		require.NoError(t, readErr)
		require.True(t, strings.Contains(string(contents), expected), string(contents))
		require.Contains(t, string(contents), "hunter-a")
	}
	for name, expected := range map[string]string{"ssl.log": "tls.example.test", "http.log": "HTTP/1.1"} {
		contents, readErr := os.ReadFile(dir + "/" + name)
		require.NoError(t, readErr)
		require.Contains(t, string(contents), expected)
	}
}

func (s *collectingSink) HandleEvent(_ context.Context, event events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (*collectingSink) Flush(context.Context) error { return nil }
func (*collectingSink) Close(context.Context) error { return nil }

func TestEmitDNSAndSMTPEvents(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindDNS, events.KindSMTP))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{{TimestampNs: time.Unix(10, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Dns: &data.DNSMetadata{TransactionId: 7, QueryName: "example.test", QueryType: "A", QueryClass: "IN"}, Email: &data.EmailMetadata{MailFrom: "sender@example.test", RcptTo: []string{"receiver@example.test"}, Subject: "hello"}}}})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 2)
	for _, event := range sink.events {
		require.Equal(t, "hunter-a", event.Envelope().NodeID)
		require.Equal(t, []string{"processor-test"}, event.Envelope().Provenance.ProcessorNodeIDs)
		require.NotEmpty(t, event.Envelope().UID)
		require.NotEmpty(t, event.Envelope().CommunityID)
	}
}

func TestEventBroadcasterReceivesNormalizedEventsWithStructuredLogsDisabled(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	require.Nil(t, p.logSink)

	subscription, err := p.eventBroadcaster.Subscribe(broadcast.Options{
		QueueSize:        1,
		Kinds:            []events.Kind{events.KindDNS},
		ProcessorNodeIDs: []string{"processor-test"},
	})
	require.NoError(t, err)
	defer subscription.Close()
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{{
		TimestampNs: time.Unix(10, 0).UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp",
			Dns: &data.DNSMetadata{TransactionId: 7, QueryName: "example.test", QueryType: "A", QueryClass: "IN"},
		},
	}})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))

	select {
	case event := <-subscription.Events():
		require.Equal(t, events.KindDNS, event.Kind())
		require.Equal(t, "hunter-a", event.Envelope().NodeID)
		require.Equal(t, []string{"processor-test"}, event.Envelope().Provenance.ProcessorNodeIDs)
	default:
		t.Fatal("event broadcaster did not receive normalized DNS event")
	}
}

func TestFileMetadataGenerationDoesNotRequireStructuredLogs(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	require.Nil(t, p.logSink)
	require.NotNil(t, p.eventRuntime)

	subscription, err := p.eventBroadcaster.Subscribe(broadcast.Options{QueueSize: 2, Kinds: []events.Kind{events.KindHTTP, events.KindFileMetadata}})
	require.NoError(t, err)
	defer subscription.Close()
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{{
		TimestampNs: time.Unix(10, 0).UnixNano(),
		Metadata: &data.PacketMetadata{
			SrcIp: "192.0.2.20", DstIp: "192.0.2.10", SrcPort: 80, DstPort: 52000, Transport: "tcp",
			Http: &data.HTTPMetadata{Type: "response", IsServer: true, StatusCode: 200, ContentType: "text/plain", BodyPreview: []byte("payload"), BodySize: 7},
		},
	}})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))

	kinds := map[events.Kind]bool{}
	for event := range subscription.Events() {
		kinds[event.Kind()] = true
	}
	require.True(t, kinds[events.KindHTTP])
	require.True(t, kinds[events.KindFileMetadata])
}

func TestTapLocalEventsUseEffectiveTapID(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "tap-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindDNS, events.KindConn))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	packet := &data.CapturedPacket{
		TimestampNs: time.Unix(10, 0).UnixNano(),
		LinkType:    1,
		Metadata: &data.PacketMetadata{
			SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Protocol: "DNS",
			Dns: &data.DNSMetadata{QueryName: "example.test", QueryType: "A", QueryClass: "IN"},
		},
	}
	p.emitProtocolEvents("tap-test-local", []*data.CapturedPacket{packet})
	p.eventRuntime.EOF()
	require.NoError(t, p.eventDispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 2)
	for _, event := range sink.events {
		envelope := event.Envelope()
		require.Equal(t, "tap-test", envelope.NodeID)
		require.Equal(t, "tap-test-local", envelope.Provenance.CaptureSource)
		require.Equal(t, []string{"tap-test"}, envelope.Provenance.ProcessorNodeIDs)
		require.NotEmpty(t, envelope.ProducerSessionID)
		require.Equal(t, sink.events[0].Envelope().ProducerSessionID, envelope.ProducerSessionID)
	}
}

func TestConnectionAndProtocolEventsShareFlowIdentity(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindDNS, events.KindConn))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	packet := &data.CapturedPacket{TimestampNs: time.Unix(10, 0).UnixNano(), LinkType: 1, Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Protocol: "DNS", Dns: &data.DNSMetadata{QueryName: "example.test", QueryType: "A", QueryClass: "IN"}}}
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{packet})
	p.eventRuntime.EOF()
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 2)
	require.Equal(t, sink.events[0].Envelope().UID, sink.events[1].Envelope().UID)
	require.Equal(t, sink.events[0].Envelope().CommunityID, sink.events[1].Envelope().CommunityID)
}

func TestEmitTLSAndHTTPEventsNormalizesResponseDirection(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindTLS, events.KindHTTP))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("tap-local", []*data.CapturedPacket{
		{TimestampNs: time.Unix(12, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 50000, DstPort: 443, Transport: "tcp", Tls: &data.TLSMetadata{Version: "TLS 1.3", Sni: "example.test"}}},
		{TimestampNs: time.Unix(13, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.2", DstIp: "192.0.2.1", SrcPort: 80, DstPort: 50001, Transport: "tcp", Http: &data.HTTPMetadata{Type: "response", IsServer: true, StatusCode: 204}}},
	})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 2)
	require.Equal(t, "example.test", sink.events[0].(events.TLSEvent).ServerName)
	httpEvent := sink.events[1].(events.HTTPEvent)
	require.Equal(t, uint64(1), httpEvent.TransactionDepth)
	require.Equal(t, uint16(204), httpEvent.StatusCode)
	require.Equal(t, uint16(50001), httpEvent.Envelope().Flow.SourcePort)
}

func TestProtocolEventsPropagateFilteredCaptureProvenance(t *testing.T) {
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink, events.KindDNS, events.KindTLS, events.KindHTTP, events.KindSMTP))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{{TimestampNs: time.Unix(10, 0).UnixNano(), MatchedFilterIds: []string{"filter-a"}, Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.20", SrcPort: 50000, DstPort: 443, Transport: "tcp", Dns: &data.DNSMetadata{}, Tls: &data.TLSMetadata{}, Http: &data.HTTPMetadata{}, Email: &data.EmailMetadata{}}}})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.events, 4)
	for _, event := range sink.events {
		require.Equal(t, events.CaptureScopeFiltered, event.Envelope().CaptureScope)
		require.True(t, event.Envelope().Partial)
	}
}

func TestProcessorAndTapSharedFixtureProduceEquivalentHTTPEvents(t *testing.T) {
	fixture, err := eventfixture.Captured()
	require.NoError(t, err)
	run := func(t *testing.T, processorID, sourceID string) events.HTTPEvent {
		t.Helper()
		p, err := New(Config{ListenAddr: ":0", ProcessorID: processorID, EventQueueSize: 32})
		require.NoError(t, err)
		sink := &collectingSink{}
		require.NoError(t, p.RegisterEventSink(sink, events.KindHTTP))
		require.NoError(t, p.eventDispatcher.Start(context.Background()))
		p.emitProtocolEvents(sourceID, fixture)
		p.eventRuntime.EOF()
		require.NoError(t, p.eventDispatcher.Close(context.Background()))
		sink.mu.Lock()
		defer sink.mu.Unlock()
		require.Len(t, sink.events, 1)
		return sink.events[0].(events.HTTPEvent)
	}
	processorEvent := run(t, "processor-test", "hunter-a")
	tapEvent := run(t, "tap-test", "tap-test-local")
	for _, event := range []events.HTTPEvent{processorEvent, tapEvent} {
		require.Equal(t, "GET", event.Method)
		require.Equal(t, "/phase4", event.URI)
		require.Equal(t, "parity.example.test", event.Host)
		require.True(t, eventfixture.BaseTime.Add(2*time.Second).Equal(event.Envelope().Timestamp))
	}
	require.Equal(t, "hunter-a", processorEvent.Envelope().NodeID)
	require.Equal(t, "tap-test", tapEvent.Envelope().NodeID)
	require.Equal(t, "tap-test-local", tapEvent.Envelope().Provenance.CaptureSource)
}
