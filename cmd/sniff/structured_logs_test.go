//go:build cli || all

package sniff

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type sniffEventSink struct {
	mu     sync.Mutex
	events []events.Event
}

func (s *sniffEventSink) HandleEvent(_ context.Context, event events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (*sniffEventSink) Flush(context.Context) error { return nil }
func (*sniffEventSink) Close(context.Context) error { return nil }

func TestOfflineStructuredEventProducerIsDeterministic(t *testing.T) {
	firstPath := filepath.Join(t.TempDir(), "first.pcap")
	secondPath := filepath.Join(t.TempDir(), "second.pcap")
	require.NoError(t, os.WriteFile(firstPath, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(secondPath, []byte("second"), 0o600))

	first, err := sniffEventProducer([]string{firstPath, secondPath}, "profile-a")
	require.NoError(t, err)
	replay, err := sniffEventProducer([]string{firstPath, secondPath}, "profile-a")
	require.NoError(t, err)
	reordered, err := sniffEventProducer([]string{secondPath, firstPath}, "profile-a")
	require.NoError(t, err)
	changedProfile, err := sniffEventProducer([]string{firstPath, secondPath}, "profile-b")
	require.NoError(t, err)

	require.Equal(t, first.SessionID(), replay.SessionID())
	require.NotEqual(t, first.SessionID(), reordered.SessionID())
	require.NotEqual(t, first.SessionID(), changedProfile.SessionID())
}

func TestLiveStructuredEventProducerUsesRandomSessions(t *testing.T) {
	first, err := sniffEventProducer(nil, "profile")
	require.NoError(t, err)
	second, err := sniffEventProducer(nil, "profile")
	require.NoError(t, err)
	require.NotEqual(t, first.SessionID(), second.SessionID())
}

func TestStructuredLogFlagsAreInheritedByProtocolCommands(t *testing.T) {
	for _, cmd := range []*cobra.Command{dnsCmd, tlsCmd, httpCmd, emailCmd, voipCmd} {
		require.NotNil(t, cmd.InheritedFlags().Lookup("log-dir"), cmd.Name())
		require.NotNil(t, cmd.InheritedFlags().Lookup("log-streams"), cmd.Name())
	}
}

func TestSniffProducesNormalizedEventsWithoutLogDirectory(t *testing.T) {
	viper.Set("logs.dir", "")
	viper.Set("events.queue_size", 32)
	input := filepath.Join(t.TempDir(), "dns.pcap")
	require.NoError(t, os.WriteFile(input, []byte("identity input"), 0o600))
	sink := &sniffEventSink{}
	session, err := newSniffEventSession("", []string{input}, "test-profile", sink)
	require.NoError(t, err)

	packet := gopacket.NewPacket(dnsPacket(t), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(10, 123)
	session.observe(capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: filepath.Base(input), SourcePath: input})
	session.analysis.EOF()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, session.dispatcher.Close(ctx))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var dnsEvent events.Event
	for _, event := range sink.events {
		if event.Kind() == events.KindDNS {
			dnsEvent = event
			break
		}
	}
	require.NotNil(t, dnsEvent)
	require.Equal(t, "local", dnsEvent.Envelope().NodeID)
	require.Equal(t, input, dnsEvent.Envelope().Provenance.InputFile)
	require.Equal(t, time.Unix(10, 123), dnsEvent.Envelope().Timestamp)
	require.NotEmpty(t, dnsEvent.Envelope().EventID)
}

func TestSniffSharedFixtureProducesReassembledHTTPEvent(t *testing.T) {
	input := filepath.Join(t.TempDir(), "phase4.pcap")
	require.NoError(t, os.WriteFile(input, []byte("phase4 fixture identity"), 0o600))
	sink := &sniffEventSink{}
	session, err := newSniffEventSession("", []string{input}, "phase4-equivalence", sink)
	require.NoError(t, err)
	packets, err := eventfixture.SegmentedHTTP()
	require.NoError(t, err)
	for _, packet := range packets {
		packet.SourcePath = input
		session.observe(packet)
	}
	session.analysis.EOF()
	require.NoError(t, session.dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var httpEvents []events.HTTPEvent
	for _, event := range sink.events {
		if event.Kind() == events.KindHTTP {
			httpEvents = append(httpEvents, event.(events.HTTPEvent))
		}
	}
	require.Len(t, httpEvents, 1)
	require.Equal(t, "GET", httpEvents[0].Method)
	require.Equal(t, "/phase4", httpEvents[0].URI)
	require.Equal(t, "parity.example.test", httpEvents[0].Host)
	require.True(t, eventfixture.BaseTime.Add(2*time.Second).Equal(httpEvents[0].Envelope().Timestamp))
	require.Equal(t, input, httpEvents[0].Envelope().Provenance.InputFile)
}

func TestSniffDistinguishesOfflineInputsWithSameBasename(t *testing.T) {
	viper.Set("logs.dir", "")
	viper.Set("events.queue_size", 32)
	first := filepath.Join(t.TempDir(), "capture.pcap")
	second := filepath.Join(t.TempDir(), "capture.pcap")
	require.NoError(t, os.WriteFile(first, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(second, []byte("second"), 0o600))
	sink := &sniffEventSink{}
	session, err := newSniffEventSession("", []string{first, second}, "test-profile", sink)
	require.NoError(t, err)

	for index, input := range []string{first, second} {
		packet := gopacket.NewPacket(dnsPacket(t), layers.LayerTypeEthernet, gopacket.Default)
		packet.Metadata().Timestamp = time.Unix(int64(10+index), 0)
		session.observe(capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "capture.pcap", SourcePath: input})
	}
	session.analysis.EOF()
	require.NoError(t, session.dispatcher.Close(context.Background()))

	sink.mu.Lock()
	defer sink.mu.Unlock()
	var provenance []string
	for _, event := range sink.events {
		if event.Kind() == events.KindDNS {
			provenance = append(provenance, event.Envelope().Provenance.InputFile)
		}
	}
	require.Equal(t, []string{first, second}, provenance)
}

func TestProtocolSniffPCAPWritesStructuredLogs(t *testing.T) {
	tests := []struct {
		name, stream, needle string
		packet               []byte
		run                  func(string)
	}{
		{"dns", "dns", "example.test", dnsPacket(t), func(path string) { dnsHandler(dnsCmd, []string{path}) }},
		{"tls", "ssl", "example.com", tcpPacket(t, 49152, 443, tlsClientHello()), func(path string) { tlsHandler(tlsCmd, []string{path}) }},
		{"http", "http", "example.test", tcpPacket(t, 49153, 80, []byte("GET /phase6 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: lippycat-test\r\n\r\n")), func(path string) { httpHandler(httpCmd, []string{path}) }},
		{"smtp", "smtp", "alice@example.test", tcpPacket(t, 49154, 25, []byte("MAIL FROM:<alice@example.test>\r\n")), func(path string) { emailHandler(emailCmd, []string{path}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pcapPath := filepath.Join(t.TempDir(), tt.name+".pcap")
			writeTestPCAP(t, pcapPath, tt.packet)
			viper.Set("logs.dir", dir)
			viper.Set("logs.format", "json")
			viper.Set("logs.streams", []string{tt.stream})
			viper.Set("events.queue_size", 32)
			viper.Set("logs.queue_size", 32)
			viper.Set("sniff.quiet", true)
			filter, readFile = "", ""
			tt.run(pcapPath)
			contents, err := os.ReadFile(filepath.Join(dir, tt.stream+".log"))
			require.NoError(t, err)
			require.Contains(t, string(contents), tt.needle)
		})
	}
}

func writeTestPCAP(t *testing.T, path string, packet []byte) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(10, 0), CaptureLength: len(packet), Length: len(packet)}, packet))
	require.NoError(t, f.Close())
}

func dnsPacket(t *testing.T) []byte {
	t.Helper()
	eth, ip := ethernetIPv4(layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	dns := &layers.DNS{ID: 7, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}, QDCount: 1}
	return serializePacket(t, eth, ip, udp, dns)
}

func tcpPacket(t *testing.T, src, dst layers.TCPPort, payload []byte) []byte {
	t.Helper()
	eth, ip := ethernetIPv4(layers.IPProtocolTCP)
	tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: 1, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	return serializePacket(t, eth, ip, tcp, gopacket.Payload(payload))
}

func ethernetIPv4(protocol layers.IPProtocol) (*layers.Ethernet, *layers.IPv4) {
	return &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: []byte{192, 0, 2, 10}, DstIP: []byte{192, 0, 2, 53}, Protocol: protocol}
}

func serializePacket(t *testing.T, serializable ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializable...))
	return buf.Bytes()
}

func tlsClientHello() []byte {
	extensions := make([]byte, 0, 32)
	extensions = appendTLSExtension(extensions, 0, []byte{0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(handshake)))
	return append(record, handshake...)
}

func appendTLSExtension(dst []byte, typ uint16, value []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}
