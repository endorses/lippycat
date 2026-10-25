//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/conntrack"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const protocolHandoverIdle = 30 * time.Second

type protocolHandoverClock struct{ nanos atomic.Int64 }

func (c *protocolHandoverClock) now() time.Time  { return time.Unix(0, c.nanos.Load()) }
func (c *protocolHandoverClock) set(t time.Time) { c.nanos.Store(t.UnixNano()) }

type protocolHandoverSink struct {
	mu     sync.Mutex
	events []events.HTTPEvent
}

func (s *protocolHandoverSink) HandleEvent(_ context.Context, event events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event.(events.HTTPEvent))
	return nil
}
func (*protocolHandoverSink) Flush(context.Context) error { return nil }
func (*protocolHandoverSink) Close(context.Context) error { return nil }
func (s *protocolHandoverSink) snapshot() []events.HTTPEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.HTTPEvent(nil), s.events...)
}

type protocolHandoverNode struct {
	processor *Processor
	address   string
	outputDir string
	sink      *protocolHandoverSink
	processed <-chan *data.PacketBatch
	seen      *uint64
}

// The socket harness uses production registration, raw/relay ingress and
// upstream senders. The owning hunter's selection is exercised separately in
// hunter/failover_deployment_test.go. An explicit analysis clock and synchronous
// dispatcher barriers avoid sleeping across protocol expiry periods here.
func newProtocolHandoverNode(t *testing.T, pki relayTestPKI, clock *protocolHandoverClock, config Config, outputs bool) protocolHandoverNode {
	t.Helper()
	pair, certificate, key := pki.identity(t, config.ProcessorID)
	config.ListenAddr = "127.0.0.1:0"
	config.TLSEnabled, config.TLSClientAuth = true, true
	config.TLSCAFile, config.TLSCertFile, config.TLSKeyFile = pki.caFile, certificate, key
	config.CallCompletionMonitorConfig = &CallCompletionMonitorConfig{
		GracePeriod: time.Second, CheckInterval: time.Hour, RTPWaitTimeout: time.Minute,
		ClosedCallTTL: 10 * time.Minute, Now: clock.now,
	}
	outputDir := ""
	if outputs {
		outputDir = t.TempDir()
		config.PcapWriterConfig = &PcapWriterConfig{Enabled: true, OutputDir: outputDir, FilePattern: "{callid}.pcap", SyncInterval: time.Hour}
	}
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	p.callAggregator.SetBYETimewait(time.Second)
	sink := &protocolHandoverSink{}
	var processed <-chan *data.PacketBatch
	var seen uint64
	if outputs {
		// Configuring an owned runtime before serving is the same composition
		// boundary used by other packet-source integration tests. No production
		// fault hook or private analysis-state mutation is needed.
		p.eventRuntime, err = eventanalysis.New(eventanalysis.Config{
			Dispatcher: p.eventDispatcher, Now: clock.now,
			Connections: conntrack.Config{IdleTimeout: protocolHandoverIdle},
			LiveExpiry:  false,
		})
		require.NoError(t, err)
		require.NoError(t, p.RegisterEventSink(sink, events.KindHTTP))
		require.NoError(t, p.eventDispatcher.Start(context.Background()))
		processed = p.subscriberManager.Add("protocol-processing-completion")
	}
	address := serveRelayTestProcessor(t, p, pair, pki.pool)
	if config.UpstreamAddr != "" {
		require.NoError(t, p.upstreamManager.Start())
		require.Eventually(t, p.upstreamManager.IsConnected, 5*time.Second, time.Millisecond)
	}
	return protocolHandoverNode{processor: p, address: address, outputDir: outputDir, sink: sink, processed: processed, seen: &seen}
}

type protocolHandoverClient struct {
	stream   data.DataService_StreamPacketsClient
	sourceID string
	sequence uint64
}

func newProtocolHandoverClient(t *testing.T, pki relayTestPKI, address, sourceID string) *protocolHandoverClient {
	t.Helper()
	pair, _, _ := pki.identity(t, sourceID)
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	response, err := management.NewManagementServiceClient(conn).RegisterHunter(ctx, &management.HunterRegistration{
		HunterId: sourceID, Hostname: sourceID, Interfaces: []string{"private-segment"},
	})
	require.NoError(t, err)
	require.True(t, response.Accepted)
	stream, err := data.NewDataServiceClient(conn).StreamPackets(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, stream.CloseSend()) })
	return &protocolHandoverClient{stream: stream, sourceID: sourceID}
}

func (c *protocolHandoverClient) send(t *testing.T, epoch string, packets ...*data.CapturedPacket) {
	t.Helper()
	c.sequence++
	require.NoError(t, c.stream.Send(&data.PacketBatch{
		HunterId: c.sourceID, ProducerSessionId: c.sourceID + "-producer", CaptureEpoch: epoch,
		Sequence: c.sequence, TimestampNs: packets[0].TimestampNs, Packets: packets,
	}))
	ack, err := c.stream.Recv()
	require.NoError(t, err)
	require.Equal(t, c.sequence, ack.AckSequence)
}

func flushProtocolHandover(t *testing.T, node protocolHandoverNode, packets uint64) []events.HTTPEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Subscriber publication follows protocol analysis, aggregation and PCAP
	// writes. The ingress counter alone is incremented before those effects.
	for *node.seen < packets {
		select {
		case batch := <-node.processed:
			*node.seen += uint64(len(batch.Packets))
		case <-ctx.Done():
			t.Fatalf("processed %d of %d expected packets", *node.seen, packets)
		}
	}
	require.Equal(t, packets, *node.seen)
	require.NoError(t, node.processor.eventDispatcher.Flush(ctx))
	return node.sink.snapshot()
}

func protocolHandoverPacket(t *testing.T, at time.Time, transport gopacket.SerializableLayer, payload []byte) *data.CapturedPacket {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(10, 23, 0, 1), DstIP: net.IPv4(10, 23, 0, 2)}
	metadata := &data.PacketMetadata{SrcIp: "10.23.0.1", DstIp: "10.23.0.2"}
	switch layer := transport.(type) {
	case *layers.TCP:
		ip.Protocol = layers.IPProtocolTCP
		require.NoError(t, layer.SetNetworkLayerForChecksum(ip))
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "tcp", uint32(layer.SrcPort), uint32(layer.DstPort)
		metadata.Protocol = "HTTP"
	case *layers.UDP:
		ip.Protocol = layers.IPProtocolUDP
		require.NoError(t, layer.SetNetworkLayerForChecksum(ip))
		metadata.Transport, metadata.SrcPort, metadata.DstPort = "udp", uint32(layer.SrcPort), uint32(layer.DstPort)
	default:
		t.Fatalf("unsupported fixture transport %T", layer)
	}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, transport, gopacket.Payload(payload)))
	return &data.CapturedPacket{
		Data: buffer.Bytes(), TimestampNs: at.UnixNano(), CaptureLength: uint32(len(buffer.Bytes())), OriginalLength: uint32(len(buffer.Bytes())),
		LinkType: uint32(layers.LinkTypeEthernet), InterfaceName: "private-segment", Metadata: metadata,
	}
}

func protocolHandoverTCP(t *testing.T, at time.Time, port uint16, sequence uint32, syn bool, payload string) *data.CapturedPacket {
	t.Helper()
	return protocolHandoverPacket(t, at, &layers.TCP{SrcPort: layers.TCPPort(port), DstPort: 80, Seq: sequence, SYN: syn, ACK: !syn, Window: 65535}, []byte(payload))
}

func TestFailoverTCPContinuityRequiresCommonAnalysisOwner(t *testing.T) {
	for _, common := range []bool{false, true} {
		t.Run(fmt.Sprintf("common_upstream_%t", common), func(t *testing.T) {
			pki := newRelayTestPKI(t)
			clock := &protocolHandoverClock{}
			start := time.Now()
			clock.set(start)
			var first, second, owner protocolHandoverNode
			if common {
				owner = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "central", RelayOrigins: map[string][]string{"relay-a": {"edge-a"}, "relay-b": {"edge-a"}}}, true)
				first = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "relay-a", UpstreamAddr: owner.address}, false)
				second = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "relay-b", UpstreamAddr: owner.address}, false)
			} else {
				first = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "independent-a"}, true)
				second = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "independent-b"}, true)
				owner = second
			}
			before := newProtocolHandoverClient(t, pki, first.address, "edge-a")
			after := newProtocolHandoverClient(t, pki, second.address, "edge-a")
			prefix := "GET /handover HTTP/1.1\r\nHost: "
			suffix := "continuity.example.test\r\n\r\n"
			before.send(t, "same-capture", protocolHandoverTCP(t, start, 41000, 100, true, ""), protocolHandoverTCP(t, start.Add(time.Millisecond), 41000, 101, false, prefix))
			if common {
				require.Empty(t, flushProtocolHandover(t, owner, 2))
			} else {
				require.Empty(t, flushProtocolHandover(t, first, 2))
			}
			after.send(t, "same-capture", protocolHandoverTCP(t, start.Add(2*time.Millisecond), 41000, 101+uint32(len(prefix)), false, suffix))
			if common {
				got := flushProtocolHandover(t, owner, 3)
				require.Len(t, got, 1)
				require.Equal(t, "/handover", got[0].URI)
				require.Equal(t, "continuity.example.test", got[0].Host)
				require.Equal(t, "edge-a", got[0].Envelope().NodeID)
				require.Equal(t, []string{"central"}, got[0].Envelope().Provenance.ProcessorNodeIDs)
			} else {
				require.Empty(t, flushProtocolHandover(t, first, 2))
				require.Empty(t, flushProtocolHandover(t, second, 1), "a new processor cannot inherit the old processor's TCP prefix")
			}
			// A complete message in a new stream proves the replacement's output
			// works even when the old partial stream cannot be reconstructed.
			after.send(t, "same-capture", protocolHandoverTCP(t, start.Add(3*time.Millisecond), 41001, 500, true, "GET /fresh HTTP/1.1\r\nHost: fresh.example.test\r\n\r\n"))
			expectedPackets := uint64(2)
			if common {
				expectedPackets = 4
			}
			got := flushProtocolHandover(t, owner, expectedPackets)
			require.Equal(t, "/fresh", got[len(got)-1].URI)
		})
	}
}

func TestFailoverTCPReplayCannotJoinOtherSourceEpochOrExpiredStream(t *testing.T) {
	pki := newRelayTestPKI(t)
	clock := &protocolHandoverClock{}
	start := time.Now()
	clock.set(start)
	owner := newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "central"}, true)
	a := newProtocolHandoverClient(t, pki, owner.address, "edge-a")
	b := newProtocolHandoverClient(t, pki, owner.address, "edge-b")
	prefix, suffix := "GET /isolated HTTP/1.1\r\nHost: ", "private.example.test\r\n\r\n"
	a.send(t, "capture-one", protocolHandoverTCP(t, start, 41000, 100, true, ""), protocolHandoverTCP(t, start.Add(time.Millisecond), 41000, 101, false, prefix))
	b.send(t, "capture-one", protocolHandoverTCP(t, start.Add(2*time.Millisecond), 41000, 101+uint32(len(prefix)), false, suffix))
	a.send(t, "capture-two", protocolHandoverTCP(t, start.Add(3*time.Millisecond), 41000, 101+uint32(len(prefix)), false, suffix))
	require.Empty(t, flushProtocolHandover(t, owner, 4), "identical private tuples in another source or epoch cannot complete retained bytes")
	a.send(t, "capture-one", protocolHandoverTCP(t, start.Add(4*time.Millisecond), 41000, 101+uint32(len(prefix)), false, suffix))
	got := flushProtocolHandover(t, owner, 5)
	require.Len(t, got, 1)
	require.Equal(t, "/isolated", got[0].URI)

	prefix = "GET /expired HTTP/1.1\r\nHost: "
	a.send(t, "capture-one", protocolHandoverTCP(t, start.Add(time.Second), 41002, 1000, true, ""), protocolHandoverTCP(t, start.Add(time.Second+time.Millisecond), 41002, 1001, false, prefix))
	flushProtocolHandover(t, owner, 7)
	clock.set(start.Add(2 * protocolHandoverIdle))
	owner.processor.eventRuntime.Expire(clock.now())
	// Preserve the historical capture timestamp on replay. It cannot extend
	// the configured idle boundary or recover a prefix already discarded.
	a.send(t, "capture-one", protocolHandoverTCP(t, start.Add(time.Second+2*time.Millisecond), 41002, 1001+uint32(len(prefix)), false, suffix))
	got = flushProtocolHandover(t, owner, 8)
	require.Len(t, got, 1)
	a.send(t, "capture-one", protocolHandoverTCP(t, clock.now(), 41002, 10000, true, "GET /after-expiry HTTP/1.1\r\nHost: new.example.test\r\n\r\n"))
	got = flushProtocolHandover(t, owner, 9)
	require.Len(t, got, 2)
	require.Equal(t, "/after-expiry", got[1].URI)
}

func protocolHandoverSIP(t *testing.T, at time.Time, method string) *data.CapturedPacket {
	t.Helper()
	line, cseqMethod, code := method+" sip:callee@example.test SIP/2.0", method, uint32(0)
	if method == "RESPONSE" {
		line, cseqMethod, code = "SIP/2.0 200 OK", "INVITE", 200
	}
	body := ""
	if method == "INVITE" || method == "RESPONSE" {
		body = "v=0\r\no=caller 1 1 IN IP4 10.23.0.1\r\ns=synthetic\r\nc=IN IP4 10.23.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n"
	}
	payload := fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 10.23.0.1:5060;branch=z9hG4bK-handover\r\nFrom: <sip:caller@example.test>;tag=caller\r\nTo: <sip:callee@example.test>;tag=callee\r\nCall-ID: synthetic-handover\r\nCSeq: 1 %s\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", line, cseqMethod, len(body), body)
	p := protocolHandoverPacket(t, at, &layers.UDP{SrcPort: 5060, DstPort: 5060}, []byte(payload))
	p.Metadata.Protocol = "SIP"
	p.Metadata.Sip = &data.SIPMetadata{CallId: "synthetic-handover", Method: method, ResponseCode: code, CseqMethod: cseqMethod, CseqNumber: 1, ViaBranch: "z9hG4bK-handover", FromUser: "caller", ToUser: "callee", FromUri: "sip:caller@example.test", ToUri: "sip:callee@example.test", FromTag: "caller", ToTag: "callee", MediaPorts: []uint32{40000}}
	return p
}

func protocolHandoverRTP(t *testing.T, at time.Time, sequence uint16) *data.CapturedPacket {
	t.Helper()
	payload := make([]byte, 172)
	payload[0] = 0x80
	binary.BigEndian.PutUint16(payload[2:4], sequence)
	binary.BigEndian.PutUint32(payload[4:8], uint32(sequence)*160)
	binary.BigEndian.PutUint32(payload[8:12], 0x12345678)
	p := protocolHandoverPacket(t, at, &layers.UDP{SrcPort: 40000, DstPort: 40002}, payload)
	p.Metadata.Protocol = "RTP"
	p.Metadata.Sip = &data.SIPMetadata{CallId: "synthetic-handover"}
	p.Metadata.Rtp = &data.RTPMetadata{Ssrc: 0x12345678, Sequence: uint32(sequence), Timestamp: uint32(sequence) * 160}
	return p
}

func protocolHandoverPCAP(t *testing.T, directory, kind string) [][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*_"+kind+".pcap"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	file, err := os.Open(paths[0])
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	var packets [][]byte
	for {
		packet, _, err := reader.ReadPacketData()
		if err == io.EOF {
			return packets
		}
		require.NoError(t, err)
		packets = append(packets, append([]byte(nil), packet...))
	}
}

func TestFailoverSIPRTPContinuityAndFinalizedReplay(t *testing.T) {
	for _, common := range []bool{false, true} {
		t.Run(fmt.Sprintf("common_upstream_%t", common), func(t *testing.T) {
			pki := newRelayTestPKI(t)
			clock := &protocolHandoverClock{}
			start := time.Now()
			clock.set(start)
			var first, second, owner protocolHandoverNode
			if common {
				owner = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "central", RelayOrigins: map[string][]string{"relay-a": {"edge-a"}, "relay-b": {"edge-a"}}}, true)
				first = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "relay-a", UpstreamAddr: owner.address}, false)
				second = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "relay-b", UpstreamAddr: owner.address}, false)
			} else {
				first = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "independent-a"}, true)
				second = newProtocolHandoverNode(t, pki, clock, Config{ProcessorID: "independent-b"}, true)
				owner = second
			}
			before := newProtocolHandoverClient(t, pki, first.address, "edge-a")
			after := newProtocolHandoverClient(t, pki, second.address, "edge-a")
			invite := protocolHandoverSIP(t, start, "INVITE")
			answer := protocolHandoverSIP(t, start.Add(time.Millisecond), "RESPONSE")
			mediaOne := protocolHandoverRTP(t, start.Add(2*time.Millisecond), 1)
			mediaTwo := protocolHandoverRTP(t, start.Add(3*time.Millisecond), 2)
			before.send(t, "same-capture", invite, answer, mediaOne)
			if common {
				flushProtocolHandover(t, owner, 3)
			} else {
				flushProtocolHandover(t, first, 3)
			}
			after.send(t, "same-capture", mediaTwo)
			expectedPackets, expectedMedia := uint64(1), uint64(1)
			if common {
				expectedPackets, expectedMedia = 4, 2
			}
			flushProtocolHandover(t, owner, expectedPackets)
			call, exists := owner.processor.callAggregator.GetCall("synthetic-handover")
			require.True(t, exists)
			require.NotNil(t, call.RTPStats)
			require.EqualValues(t, expectedMedia, call.RTPStats.TotalPackets)
			if common {
				require.Equal(t, "sip:caller@example.test", call.From)
				require.Equal(t, start.UnixNano(), call.StartTime.UnixNano())
			} else {
				require.Empty(t, call.From, "a replacement processor cannot inherit missed SIP setup")
				require.Equal(t, time.Unix(0, mediaTwo.TimestampNs), call.StartTime)
				original, ok := first.processor.callAggregator.GetCall("synthetic-handover")
				require.True(t, ok)
				require.EqualValues(t, 1, original.RTPStats.TotalPackets)
			}
			clock.set(start.Add(time.Second))
			bye := protocolHandoverSIP(t, clock.now(), "BYE")
			after.send(t, "same-capture", bye)
			flushProtocolHandover(t, owner, expectedPackets+1)
			monitor := owner.processor.sessionOutputManager.monitor.(*CallCompletionMonitor)
			clock.set(start.Add(3 * time.Second))
			monitor.checkEndedCalls()
			clock.set(start.Add(5 * time.Second))
			monitor.processPendingClose()
			require.True(t, owner.processor.callLifecycle.IsFinalized("synthetic-handover"))
			finalCall, exists := owner.processor.callAggregator.GetCall("synthetic-handover")
			require.True(t, exists)
			require.Equal(t, voip.CallStateEnded, finalCall.State)
			// A blackout outlasting the configured completion grace does not
			// authorize late media or BYE replay to reopen a completed call.
			clock.set(start.Add(2 * time.Minute))
			after.send(t, "same-capture", mediaTwo, bye)
			flushProtocolHandover(t, owner, expectedPackets+3)
			late, exists := owner.processor.callAggregator.GetCall("synthetic-handover")
			require.True(t, exists)
			require.Equal(t, finalCall.PacketCount, late.PacketCount)
			require.EqualValues(t, expectedMedia, late.RTPStats.TotalPackets)
			require.Equal(t, voip.CallStateEnded, late.State)
			require.NoError(t, owner.processor.sessionOutputManager.Close())
			wantSIP, wantRTP := [][]byte{bye.Data}, [][]byte{mediaTwo.Data}
			if common {
				wantSIP, wantRTP = [][]byte{invite.Data, answer.Data, bye.Data}, [][]byte{mediaOne.Data, mediaTwo.Data}
			} else {
				require.NoError(t, first.processor.sessionOutputManager.Close())
				require.Equal(t, [][]byte{invite.Data, answer.Data}, protocolHandoverPCAP(t, first.outputDir, "sip"))
				require.Equal(t, [][]byte{mediaOne.Data}, protocolHandoverPCAP(t, first.outputDir, "rtp"))
			}
			require.Equal(t, wantSIP, protocolHandoverPCAP(t, owner.outputDir, "sip"))
			require.Equal(t, wantRTP, protocolHandoverPCAP(t, owner.outputDir, "rtp"))
		})
	}
}
