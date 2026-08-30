package eventanalysis

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type memorySink struct {
	mu     sync.Mutex
	events []events.Event
}

func TestNewPreservesExplicitTimeoutsWhenCapacitiesDefault(t *testing.T) {
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 1, SinkQueueSize: 1})
	require.NoError(t, err)
	runtime, err := New(Config{
		Dispatcher: dispatcher,
		Flow:       flowid.Config{IdleTimeout: 11 * time.Second},
		Connections: conntrack.Config{
			IdleTimeout: 13 * time.Second, HalfOpenTimeout: 17 * time.Second,
		},
	})
	require.NoError(t, err)
	require.Equal(t, 100000, runtime.cfg.Flow.MaxEntries)
	require.Equal(t, 11*time.Second, runtime.cfg.Flow.IdleTimeout)
	require.Equal(t, 100000, runtime.cfg.Connections.MaxFlows)
	require.Equal(t, 13*time.Second, runtime.cfg.Connections.IdleTimeout)
	require.Equal(t, 17*time.Second, runtime.cfg.Connections.HalfOpenTimeout)
}

func (s *memorySink) HandleEvent(_ context.Context, e events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}
func (*memorySink) Flush(context.Context) error { return nil }
func (*memorySink) Close(context.Context) error { return nil }

func testRuntime(t *testing.T, queue int) (*Runtime, *events.Dispatcher, *memorySink) {
	t.Helper()
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: queue, SinkQueueSize: queue, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, d.Register(sink))
	r, err := New(Config{Dispatcher: d})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	return r, d, sink
}
func packet(ts time.Time) *data.CapturedPacket {
	return &data.CapturedPacket{TimestampNs: ts.UnixNano(), LinkType: 1, Metadata: &data.PacketMetadata{SrcIp: "192.0.2.1", DstIp: "192.0.2.53", SrcPort: 40000, DstPort: 53, Transport: "udp", Protocol: "DNS", Dns: &data.DNSMetadata{QueryName: "example.test", QueryType: "A", QueryClass: "IN"}}}
}

func TestRuntimeEOFEmitsPartialConnectionAndPreservesIdentity(t *testing.T) {
	r, d, s := testRuntime(t, 16)
	source := Source{NodeID: "node", CaptureSource: "pcap", InputFile: "fixture.pcap"}
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{packet(time.Unix(10, 0))}))
	r.EOF()
	require.NoError(t, d.Close(context.Background()))
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Len(t, s.events, 2)
	require.Equal(t, events.KindDNS, s.events[0].Kind())
	require.Equal(t, events.KindConn, s.events[1].Kind())
	require.Equal(t, s.events[0].Envelope().UID, s.events[1].Envelope().UID)
	require.Equal(t, "fixture.pcap", s.events[0].Envelope().Provenance.InputFile)
}

func TestRuntimeLiveExpiryClosesQuietConnection(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 16, SinkQueueSize: 16, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, dispatcher.Register(sink))
	runtime, err := New(Config{
		Dispatcher: dispatcher,
		Connections: conntrack.Config{
			MaxFlows:        16,
			IdleTimeout:     20 * time.Millisecond,
			HalfOpenTimeout: 20 * time.Millisecond,
		},
		ExpiryInterval: 5 * time.Millisecond,
		LiveExpiry:     true,
	})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, runtime.ObserveCaptured(Source{NodeID: "node", CaptureSource: "live"}, []*data.CapturedPacket{packet(time.Now())}))

	require.Eventually(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		for _, event := range sink.events {
			if event.Kind() == events.KindConn {
				return true
			}
		}
		return false
	}, time.Second, 5*time.Millisecond)

	runtime.Close()
	require.NoError(t, dispatcher.Close(context.Background()))
}

func TestObserveCapturedPreservesPacketInterfaceProvenance(t *testing.T) {
	r, d, sink := testRuntime(t, 16)
	p := packet(time.Unix(10, 0))
	p.InterfaceName = "eth7"
	p.InterfaceIndex = 7
	require.NoError(t, r.ObserveCaptured(Source{NodeID: "node", CaptureSource: "hunter-a"}, []*data.CapturedPacket{p}))
	r.EOF()
	require.NoError(t, d.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.NotEmpty(t, sink.events)
	provenance := sink.events[0].Envelope().Provenance
	require.Equal(t, "eth7", provenance.InterfaceName)
	require.Equal(t, uint32(7), provenance.InterfaceIndex)
}

func TestRuntimeResetFlushesOldFlowAndAcceptsNewInput(t *testing.T) {
	r, d, s := testRuntime(t, 16)
	source := Source{NodeID: "node", CaptureSource: "live"}
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{packet(time.Unix(10, 0))}))
	require.NoError(t, r.Reset())
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{packet(time.Unix(20, 0))}))
	r.Close()
	r.Close()
	require.Error(t, r.ObserveCaptured(source, []*data.CapturedPacket{packet(time.Unix(30, 0))}))
	require.NoError(t, d.Close(context.Background()))
	s.mu.Lock()
	defer s.mu.Unlock()
	var conns int
	for _, e := range s.events {
		if e.Kind() == events.KindConn {
			conns++
		}
	}
	require.Equal(t, 2, conns)
}

func TestRuntimeExpireUsesCaptureClockAndMidFlowIsPartial(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 16, SinkQueueSize: 16, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, d.Register(sink))
	r, err := New(Config{Dispatcher: d, Connections: conntrack.Config{MaxFlows: 10, IdleTimeout: time.Second, HalfOpenTimeout: time.Second}})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	p := packet(time.Unix(10, 0))
	p.Metadata.Transport, p.Metadata.SrcPort, p.Metadata.DstPort = "tcp", 40000, 443
	require.NoError(t, r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{p}))
	r.Expire(time.Unix(12, 0))
	require.NoError(t, d.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	found := false
	for _, event := range sink.events {
		if event.Kind() == events.KindConn {
			found = true
			require.True(t, event.Envelope().Partial)
		}
	}
	require.True(t, found)
}

func TestRuntimeReportsDispatcherPressureWithoutBlocking(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 1, SinkQueueSize: 1, Producer: producer})
	require.NoError(t, err)
	r, err := New(Config{Dispatcher: d})
	require.NoError(t, err)
	source := Source{NodeID: "node"}
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{packet(time.Unix(10, 0))}))
	stats := r.Stats()
	require.Positive(t, stats.Dropped)
	require.Equal(t, stats.Emitted, stats.Dropped)
}

func TestObservePacketUsesNowForMissingCaptureTimestamp(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 16, SinkQueueSize: 16, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, d.Register(sink))
	now := time.Unix(123, 456)
	r, err := New(Config{Dispatcher: d, Now: func() time.Time { return now }})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))

	pkt := gopacket.NewPacket(udpPacket(t, 40000, 53), layers.LayerTypeEthernet, gopacket.Default)
	require.True(t, pkt.Metadata().Timestamp.IsZero())
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet}))
	r.EOF()
	require.NoError(t, d.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.NotEmpty(t, sink.events)
	require.Equal(t, now, sink.events[0].Envelope().Timestamp)
}

func TestObserveCapturedExpiresAfterWholeOutOfOrderBatch(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 32, SinkQueueSize: 32, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, d.Register(sink))
	r, err := New(Config{Dispatcher: d, Connections: conntrack.Config{MaxFlows: 100, IdleTimeout: time.Second, HalfOpenTimeout: time.Second}})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	source := Source{NodeID: "node"}
	original := packet(time.Unix(0, 1))
	original.Metadata.Dns = nil
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{original}))

	trigger := packet(time.Unix(100, 0))
	trigger.Metadata.Dns = nil
	trigger.Metadata.SrcPort = 41000
	continuation := packet(time.Unix(1, 0))
	continuation.Metadata.Dns = nil
	require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{trigger, continuation}))
	r.EOF()
	require.NoError(t, d.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	originalConnections := 0
	for _, event := range sink.events {
		if event.Kind() == events.KindConn && event.Envelope().Flow.SourcePort == 40000 {
			originalConnections++
		}
	}
	require.Equal(t, 1, originalConnections)
}

func TestObserveCapturedReportsInvalidPacketsAndContinues(t *testing.T) {
	r, d, sink := testRuntime(t, 16)
	err := r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{nil, packet(time.Unix(10, 0))})
	require.ErrorContains(t, err, "1 of 2 invalid")
	r.EOF()
	require.NoError(t, d.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.NotEmpty(t, sink.events)
	require.Equal(t, uint64(1), r.Stats().Invalid)
}

func TestSMTPAdapterUsesSharedEmailParser(t *testing.T) {
	r, d, _ := testRuntime(t, 16)
	metadata := r.smtpToProto([]byte("MAIL FROM:<alice@example.test> SIZE=123\r\nRCPT TO:<bob@example.test>\r\nSubject: shared parser\r\nMessage-ID: <message-1@example.test>\r\n"))
	require.NotNil(t, metadata)
	require.Equal(t, "alice@example.test", metadata.MailFrom)
	require.Equal(t, []string{"bob@example.test"}, metadata.RcptTo)
	require.Equal(t, "shared parser", metadata.Subject)
	require.Equal(t, "message-1@example.test", metadata.MessageId)
	r.Close()
	require.NoError(t, d.Close(context.Background()))
}

func TestLosslessEOFDrainsMoreConnectionsThanDispatcherQueue(t *testing.T) {
	producer, err := events.NewOfflineProducer("node", events.OfflineSession{InputIdentity: "fixture", AnalysisProfile: "test"})
	require.NoError(t, err)
	d, err := events.NewDispatcher(events.Config{QueueSize: 1, SinkQueueSize: 1, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, d.Register(sink))
	r, err := New(Config{Dispatcher: d, LosslessDelivery: true})
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))

	for i := 0; i < 20; i++ {
		p := packet(time.Unix(int64(i+1), 0))
		p.Metadata.Dns = nil
		p.Metadata.SrcPort = uint32(40000 + i)
		require.NoError(t, r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{p}))
	}
	r.EOF()
	require.NoError(t, d.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	connEvents := 0
	for _, event := range sink.events {
		if event.Kind() == events.KindConn {
			connEvents++
		}
	}
	require.Equal(t, 20, connEvents)
	require.Zero(t, r.Stats().Dropped)
}

func udpPacket(t *testing.T, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 53)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: layers.UDPPort(destinationPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("payload"))))
	return buffer.Bytes()
}

func tcpPacket(t *testing.T, sourcePort, destinationPort uint16, seq uint32, syn bool, payload []byte, ts time.Time) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sourcePort), DstPort: layers.TCPPort(destinationPort), Seq: seq, SYN: syn, ACK: !syn, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
	pkt := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = ts
	return capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet, Interface: "fixture"}
}

func TestRuntimeReassemblesSegmentedApplicationProtocols(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		payload  []byte
		split    int
		kind     events.Kind
		validate func(t *testing.T, event events.Event)
	}{
		{name: "http", port: 80, payload: []byte("GET /split HTTP/1.1\r\nHost: example.test\r\n\r\n"), split: 29, kind: events.KindHTTP, validate: func(t *testing.T, event events.Event) {
			httpEvent := event.(events.HTTPEvent)
			require.Equal(t, "GET", httpEvent.Method)
			require.Equal(t, "example.test", httpEvent.Host)
		}},
		{name: "smtp", port: 25, payload: []byte("MAIL FROM:<alice@example.test>\r\n"), split: 7, kind: events.KindSMTP, validate: func(t *testing.T, event events.Event) {
			require.Equal(t, "alice@example.test", event.(events.SMTPEvent).MailFrom)
		}},
		{name: "tls", port: 443, payload: testClientHello(), split: 3, kind: events.KindTLS, validate: func(t *testing.T, event events.Event) {
			require.Equal(t, "TLS 1.2", event.(events.TLSEvent).Version)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, dispatcher, sink := testRuntime(t, 32)
			base := time.Unix(100, 0)
			require.NoError(t, r.ObservePacket(Source{NodeID: "node", CaptureSource: "fixture"}, tcpPacket(t, 40000, tc.port, 1000, true, nil, base)))
			require.NoError(t, r.ObservePacket(Source{NodeID: "node", CaptureSource: "fixture"}, tcpPacket(t, 40000, tc.port, 1001, false, tc.payload[:tc.split], base.Add(time.Second))))
			require.NoError(t, dispatcher.Flush(context.Background()))
			sink.mu.Lock()
			for _, event := range sink.events {
				require.NotEqual(t, tc.kind, event.Kind(), "incomplete segment emitted an application event")
			}
			sink.mu.Unlock()
			completion := base.Add(2 * time.Second)
			require.NoError(t, r.ObservePacket(Source{NodeID: "node", CaptureSource: "fixture"}, tcpPacket(t, 40000, tc.port, 1001+uint32(tc.split), false, tc.payload[tc.split:], completion)))
			r.EOF()
			require.NoError(t, dispatcher.Close(context.Background()))
			sink.mu.Lock()
			defer sink.mu.Unlock()
			var matched []events.Event
			for _, event := range sink.events {
				if event.Kind() == tc.kind {
					matched = append(matched, event)
				}
			}
			require.Len(t, matched, 1)
			require.Equal(t, completion, matched[0].Envelope().Timestamp)
			require.False(t, matched[0].Envelope().Partial)
			tc.validate(t, matched[0])
		})
	}
}

func TestRuntimeReassemblesTLSHandshakeAcrossRecords(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 32)
	base := time.Unix(125, 0)
	record := testClientHello()
	handshake := record[5:]
	split := 20
	first := []byte{22, 3, 1}
	first = binary.BigEndian.AppendUint16(first, uint16(split))
	first = append(first, handshake[:split]...)
	second := []byte{22, 3, 1}
	second = binary.BigEndian.AppendUint16(second, uint16(len(handshake)-split))
	second = append(second, handshake[split:]...)

	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 40000, 443, 1000, true, nil, base)))
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 40000, 443, 1001, false, first, base.Add(time.Second))))
	require.NoError(t, dispatcher.Flush(context.Background()))
	sink.mu.Lock()
	for _, event := range sink.events {
		require.NotEqual(t, events.KindTLS, event.Kind(), "incomplete TLS handshake emitted")
	}
	sink.mu.Unlock()

	completion := base.Add(2 * time.Second)
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 40000, 443, 1001+uint32(len(first)), false, second, completion)))
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var matched []events.TLSEvent
	for _, event := range sink.events {
		if event.Kind() == events.KindTLS {
			matched = append(matched, event.(events.TLSEvent))
		}
	}
	require.Len(t, matched, 1)
	require.Equal(t, "TLS 1.2", matched[0].Version)
	require.Equal(t, completion, matched[0].Envelope().Timestamp)
}

func TestObserveCapturedReassemblesPacketLocalMetadataOnNonstandardPort(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 32)
	base := time.Unix(150, 0)
	payload := []byte("GET /transported HTTP/1.1\r\nHost: example.test\r\n\r\n")
	split := 31
	infos := []capture.PacketInfo{
		tcpPacket(t, 40000, 18080, 1000, true, nil, base),
		tcpPacket(t, 40000, 18080, 1001, false, payload[:split], base.Add(time.Second)),
		tcpPacket(t, 40000, 18080, 1001+uint32(split), false, payload[split:], base.Add(2*time.Second)),
	}
	for index, info := range infos {
		metadata := protocolmeta.Enrich(info.Packet, nil, false)
		if index == 1 {
			require.NotNil(t, metadata.Http, "fixture must exercise premature packet-local metadata")
		}
		require.NoError(t, r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{{
			Data: info.Packet.Data(), TimestampNs: info.Packet.Metadata().Timestamp.UnixNano(),
			LinkType: uint32(info.LinkType), Metadata: metadata,
		}}))
		if index == 1 {
			require.NoError(t, dispatcher.Flush(context.Background()))
			sink.mu.Lock()
			for _, event := range sink.events {
				require.NotEqual(t, events.KindHTTP, event.Kind(), "incomplete transported metadata emitted")
			}
			sink.mu.Unlock()
		}
	}
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var matched []events.HTTPEvent
	for _, event := range sink.events {
		if event.Kind() == events.KindHTTP {
			matched = append(matched, event.(events.HTTPEvent))
		}
	}
	require.Len(t, matched, 1)
	require.Equal(t, "/transported", matched[0].URI)
	require.Equal(t, base.Add(2*time.Second), matched[0].Envelope().Timestamp)
}

func TestReassembledFilteredCapturePreservesScopeAndPartialState(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 32)
	fixture, err := eventfixture.Captured()
	require.NoError(t, err)
	for _, packet := range fixture {
		packet.MatchedFilterIds = []string{"filter-a"}
	}
	require.NoError(t, r.ObserveCaptured(Source{NodeID: "node", CaptureSource: "hunter-a"}, fixture))
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Kind() == events.KindHTTP {
			require.Equal(t, events.CaptureScopeFiltered, event.Envelope().CaptureScope)
			require.True(t, event.Envelope().Partial)
			return
		}
	}
	t.Fatal("missing reassembled HTTP event")
}

func TestRuntimeReassemblesChunkedHTTPBodyBeforeEmission(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 32)
	base := time.Unix(200, 0)
	payload := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	split := len(payload) - 5
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 80, 40000, 1000, true, nil, base)))
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 80, 40000, 1001, false, payload[:split], base.Add(time.Second))))
	require.NoError(t, dispatcher.Flush(context.Background()))
	sink.mu.Lock()
	for _, event := range sink.events {
		require.NotEqual(t, events.KindHTTP, event.Kind(), "incomplete chunked response emitted")
	}
	sink.mu.Unlock()
	completion := base.Add(2 * time.Second)
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 80, 40000, 1001+uint32(split), false, payload[split:], completion)))
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Kind() == events.KindHTTP {
			httpEvent := event.(events.HTTPEvent)
			require.Equal(t, uint64(11), httpEvent.ResponseBodyLength)
			require.Equal(t, completion, httpEvent.Envelope().Timestamp)
			return
		}
	}
	t.Fatal("missing chunked HTTP event")
}

func TestRuntimeReassemblesSMTPDataForFileAnalysis(t *testing.T) {
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 32, SinkQueueSize: 32, Producer: producer})
	require.NoError(t, err)
	sink := &memorySink{}
	require.NoError(t, dispatcher.Register(sink))
	r, err := New(Config{Dispatcher: dispatcher, IncludeEmailBodyPreview: true})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))

	base := time.Unix(300, 0)
	payload := []byte("DATA\r\nContent-Type: multipart/mixed; boundary=x\r\nSubject: attachment\r\n\r\n--x\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\nhello\r\n--x--\r\n.\r\n")
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 40000, 25, 1000, true, nil, base)))
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, tcpPacket(t, 40000, 25, 1001, false, payload, base.Add(time.Second))))
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Kind() == events.KindFileMetadata {
			fileEvent := event.(events.FileMetadataEvent)
			require.Equal(t, "a.txt", fileEvent.Filename)
			require.Equal(t, "SMTP", fileEvent.Source)
			return
		}
	}
	t.Fatal("missing SMTP attachment metadata event")
}

func TestReassembledMidFlowApplicationEventIsPartial(t *testing.T) {
	r, dispatcher, sink := testRuntime(t, 16)
	info := tcpPacket(t, 40000, 80, 5000, false, []byte("GET /mid HTTP/1.1\r\nHost: partial.test\r\n\r\n"), time.Unix(50, 0))
	require.NoError(t, r.ObservePacket(Source{NodeID: "node"}, info))
	r.EOF()
	require.NoError(t, dispatcher.Close(context.Background()))
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, event := range sink.events {
		if event.Kind() == events.KindHTTP {
			require.True(t, event.Envelope().Partial)
			return
		}
	}
	t.Fatal("missing HTTP event")
}

func testClientHello() []byte {
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0, 0, 0)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 1}
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...)
}
