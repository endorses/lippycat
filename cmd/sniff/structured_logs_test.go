//go:build cli || all

package sniff

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestStructuredLogFlagsAreInheritedByProtocolCommands(t *testing.T) {
	for _, cmd := range []*cobra.Command{dnsCmd, tlsCmd, httpCmd, emailCmd, voipCmd} {
		require.NotNil(t, cmd.InheritedFlags().Lookup("log-dir"), cmd.Name())
		require.NotNil(t, cmd.InheritedFlags().Lookup("log-streams"), cmd.Name())
	}
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
