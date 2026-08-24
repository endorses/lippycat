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
	"github.com/stretchr/testify/require"
)

type collectingSink struct {
	mu     sync.Mutex
	events []events.Event
}

func TestProtocolMetadataWritesStructuredLogs(t *testing.T) {
	dir := t.TempDir()
	p, err := New(Config{ListenAddr: ":0", ProcessorID: "processor-test", EventQueueSize: 16, LogConfig: &StructuredLogConfig{Enabled: true, Directory: dir, Format: "json", Streams: []string{"dns", "smtp"}, QueueSize: 16, EmitStage: "all"}})
	require.NoError(t, err)
	require.NoError(t, p.logSink.Start(context.Background()))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	p.emitProtocolEvents("hunter-a", []*data.CapturedPacket{
		{TimestampNs: time.Unix(10, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Dns: &data.DNSMetadata{TransactionId: 7, QueryName: "example.test", QueryType: "A", QueryClass: "IN"}}},
		{TimestampNs: time.Unix(11, 0).UnixNano(), Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.25", SrcPort: 40000, DstPort: 25, Transport: "tcp", Email: &data.EmailMetadata{MailFrom: "sender@example.test", RcptTo: []string{"receiver@example.test"}, Subject: "hello"}}},
	})
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	for name, expected := range map[string]string{"dns.log": "example.test", "smtp.log": "sender@example.test"} {
		contents, readErr := os.ReadFile(dir + "/" + name)
		require.NoError(t, readErr)
		require.True(t, strings.Contains(string(contents), expected), string(contents))
		require.Contains(t, string(contents), "hunter-a")
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
		require.NotEmpty(t, event.Envelope().UID)
		require.NotEmpty(t, event.Envelope().CommunityID)
	}
}
