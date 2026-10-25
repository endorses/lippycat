//go:build processor || tap || all

package processor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// This uses the production edge runtime and durable forwarding sink, the actual
// gRPC event ingress codec/service, and the processor's log/subscriber sinks.
func TestECHEdgeTransportRetryPreservesObservationCounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "ech-processor", EventQueueSize: 32,
		LogConfig: &StructuredLogConfig{Enabled: true, Directory: dir, Format: "json", Streams: []string{"ssl"}, QueueSize: 32, EmitStage: "all"}})
	require.NoError(t, err)
	require.NoError(t, p.logSink.Start(ctx))
	require.NoError(t, p.eventDispatcher.Start(ctx))
	registration, err := p.RegisterHunter(ctx, &management.HunterRegistration{HunterId: "ech-hunter",
		EventForwarding: &management.EventForwardingCapabilities{RequestedMode: management.ForwardingMode_FORWARDING_MODE_EVENTS,
			EventApiMajors: []uint32{1}, EventKinds: protoadapter.SupportedKindIDs(false), SemanticProfileRevision: 1,
			StatefulAnalysisFeatures: []string{"tcp_reassembly", "connection_tracking", "file_metadata"}}})
	require.NoError(t, err)
	require.True(t, registration.Accepted)
	subscription, err := p.eventBroadcaster.Subscribe(broadcast.Options{QueueSize: 16, Kinds: []events.Kind{events.KindTLS}})
	require.NoError(t, err)
	defer subscription.Close()

	producer, err := events.NewLiveProducer("ech-hunter")
	require.NoError(t, err)
	spool, err := eventspool.Open(eventspool.Config{Directory: filepath.Join(dir, "spool")})
	require.NoError(t, err)
	defer func() { require.NoError(t, spool.Close()) }()
	forwarder, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: "ech-hunter", ProducerSessionID: producer.SessionID(), Profile: eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY}, spool)
	require.NoError(t, err)
	forwardingSink, err := eventforwarding.NewSink(forwarder, 1, 1)
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 32, SinkQueueSize: 32, Producer: producer})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Register(forwardingSink))
	require.NoError(t, dispatcher.Start(ctx))
	runtime, err := eventanalysis.New(eventanalysis.Config{Dispatcher: dispatcher, AnalysisEpoch: producer.SessionID()})
	require.NoError(t, err)
	defer runtime.Close()
	for _, packet := range echTransportPackets(t) {
		require.NoError(t, runtime.ObservePacket(eventanalysis.Source{NodeID: "ech-hunter", CaptureSource: "fixture"}, packet))
	}
	runtime.EOF()
	require.NoError(t, dispatcher.Close(ctx))
	require.Equal(t, uint64(2), runtime.Stats().TLSClientHelloCount)
	require.Equal(t, uint64(1), runtime.Stats().TLSECHOfferedCount)

	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	eventsv1.RegisterEventServiceServer(server, p.eventService)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-serverDone) })
	conn, err := grpc.NewClient("passthrough:///ech", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.DialContext(ctx) }))
	require.NoError(t, err)
	defer func() { require.NoError(t, conn.Close()) }()
	stream, err := eventsv1.NewEventServiceClient(conn).StreamEvents(ctx)
	require.NoError(t, err)
	kinds := protoadapter.SupportedKinds(false)
	require.NoError(t, stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Open{Open: &eventsv1.EventIngressOpen{
		SourceNodeId: "ech-hunter", ProducerSessionId: producer.SessionID(), EventApiMajor: 1,
		SemanticProfileRevision: 1, EventKinds: kinds, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY,
	}}}))
	control, err := stream.Recv()
	require.NoError(t, err)
	require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, control.Kind)
	for _, batch := range spool.Batches() {
		for range 2 { // Replay the same serialized delivery with its original ID.
			require.NoError(t, stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Batch{Batch: batch}}))
			control, err = stream.Recv()
			require.NoError(t, err)
			require.Equal(t, batch.BatchSequence, control.CumulativeAckSequence)
		}
	}
	require.NoError(t, stream.CloseSend())
	require.NoError(t, p.eventDispatcher.Close(ctx))
	require.Zero(t, p.eventAnalysisStats().TLSClientHelloCount, "event-mode reception must not create a second capture authority")
	var count, offered uint64
	for range 2 {
		select {
		case event := <-subscription.Events():
			tls := event.(events.TLSEvent)
			require.Equal(t, "ech-hunter", tls.Envelope().NodeID)
			count += tls.ClientHelloCount
			offered += tls.ECHOfferedCount
		case <-ctx.Done():
			t.Fatal("TLS subscriber did not receive both canonical observations")
		}
	}
	require.Equal(t, uint64(2), count)
	require.Equal(t, uint64(1), offered)
	contents, err := os.ReadFile(filepath.Join(dir, "ssl.log"))
	require.NoError(t, err)
	var logCount, logOffered uint64
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		var record struct {
			ClientHellos uint64 `json:"client_hello_count"`
			ECHOffered   uint64 `json:"ech_offered_count"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		logCount += record.ClientHellos
		logOffered += record.ECHOffered
	}
	require.Equal(t, count, logCount)
	require.Equal(t, offered, logOffered)
}

func echTransportPackets(t *testing.T) []capture.PacketInfo {
	t.Helper()
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	plain := append([]byte{1, 0, 0, byte(len(body))}, body...)
	binary.BigEndian.PutUint16(body[len(body)-2:], 5)
	body = append(body, 0xfe, 0x0d, 0, 1, 0)
	offered := append([]byte{1, 0, 0, byte(len(body))}, body...)
	record := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(plain)+len(offered)))
	record = append(record, plain...)
	record = append(record, offered...)
	var packets []capture.PacketInfo
	for i, payload := range [][]byte{nil, record} {
		eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
		tcp := &layers.TCP{SrcPort: 40000, DstPort: 443, Seq: uint32(1000 + i), SYN: i == 0, ACK: i != 0, Window: 65535}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buffer := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100+int64(i), 0), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
		packets = append(packets, capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "fixture"})
	}
	return packets
}
