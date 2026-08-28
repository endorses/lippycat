//go:build cli || all

package sniff

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineSniffProtocolEventGoldens(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "pkg", "baseline", "testdata", "protocol-events.json"))
	require.NoError(t, err)
	var fixtures []protocolEventFixture
	require.NoError(t, json.Unmarshal(data, &fixtures))
	pcapPath := filepath.Join(t.TempDir(), "representative-protocols.pcap")
	writeProtocolGoldenPCAP(t, pcapPath, fixtures)

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = oldStdout })
	oldQuiet, oldFormat, oldReadFile := quiet, format, readFile
	readFlag := SniffCmd.PersistentFlags().Lookup("read-file")
	formatFlag := SniffCmd.PersistentFlags().Lookup("format")
	oldReadChanged, oldFormatChanged := readFlag.Changed, formatFlag.Changed
	t.Cleanup(func() {
		quiet, format, readFile = oldQuiet, oldFormat, oldReadFile
		readFlag.Changed, formatFlag.Changed = oldReadChanged, oldFormatChanged
		SniffCmd.SetArgs([]string{})
	})
	SniffCmd.SetArgs([]string{"--read-file", pcapPath, "--format", "json"})
	require.NoError(t, SniffCmd.Execute())
	require.NoError(t, writer.Close())
	os.Stdout = oldStdout
	output, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())

	decoder := json.NewDecoder(bytes.NewReader(output))
	gotByTimestamp := make(map[string]types.PacketDisplay, len(fixtures))
	for decoder.More() {
		var got types.PacketDisplay
		require.NoError(t, decoder.Decode(&got), string(output))
		gotByTimestamp[got.Timestamp.UTC().Format(time.RFC3339Nano)] = got
	}
	require.Len(t, gotByTimestamp, len(fixtures))
	for _, want := range fixtures {
		t.Run(want.Protocol, func(t *testing.T) {
			got, ok := gotByTimestamp[want.Timestamp]
			require.True(t, ok, "missing event at %s", want.Timestamp)
			require.Equal(t, want.CLIProtocol, got.Protocol)
			require.Equal(t, want.Timestamp, got.Timestamp.UTC().Format(time.RFC3339Nano))
			require.Equal(t, want.SrcIP, got.SrcIP)
			require.Equal(t, want.DstIP, got.DstIP)
			require.Equal(t, want.SrcPort, got.SrcPort)
			require.Equal(t, want.DstPort, got.DstPort)
			require.Equal(t, want.CLIInfo, got.Info)
		})
	}
}

func writeProtocolGoldenPCAP(t *testing.T, path string, fixtures []protocolEventFixture) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for _, fixture := range fixtures {
		packet := baselinePacket(t, fixture.Protocol)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: mustGoldenTime(t, fixture.Timestamp), CaptureLength: len(packet), Length: len(packet)}, packet))
	}
	require.NoError(t, f.Close())
}

type protocolEventFixture struct {
	Protocol    string `json:"protocol"`
	CLIProtocol string `json:"cli_protocol"`
	CLIInfo     string `json:"cli_info"`
	SourcePCAP  string `json:"source_pcap"`
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     string `json:"src_port"`
	DstPort     string `json:"dst_port"`
	Info        string `json:"info"`
}

func mustGoldenTime(t *testing.T, value string) time.Time {
	t.Helper()
	result, err := time.Parse(time.RFC3339Nano, value)
	require.NoError(t, err)
	return result
}

func baselinePacket(t *testing.T, protocol string) []byte {
	t.Helper()
	switch protocol {
	case "DNS":
		return baselineUDPPacket(t, net.IPv4(198, 51, 100, 53), 53000, 53, nil, true)
	case "TLS":
		return baselineTCPPacket(t, net.IPv4(198, 51, 100, 20), 49152, 443, tlsClientHello())
	case "HTTP":
		return baselineTCPPacket(t, net.IPv4(198, 51, 100, 80), 49153, 80, []byte("GET /baseline HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	case "SMTP":
		return baselineTCPPacket(t, net.IPv4(198, 51, 100, 25), 49154, 25, []byte("MAIL FROM:<alice@example.test>\r\n"))
	case "SIP":
		return baselineUDPPacket(t, net.IPv4(198, 51, 100, 50), 5060, 5060, []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: baseline-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"), false)
	default:
		t.Fatalf("unsupported golden protocol %q", protocol)
		return nil
	}
}

func baselineUDPPacket(t *testing.T, dst net.IP, srcPort, dstPort layers.UDPPort, payload []byte, dns bool) []byte {
	t.Helper()
	eth, ip := baselineEthernetIPv4(dst, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	if dns {
		query := &layers.DNS{ID: 7, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
		return serializePacket(t, eth, ip, udp, query)
	}
	return serializePacket(t, eth, ip, udp, gopacket.Payload(payload))
}

func baselineTCPPacket(t *testing.T, dst net.IP, srcPort, dstPort layers.TCPPort, payload []byte) []byte {
	t.Helper()
	eth, ip := baselineEthernetIPv4(dst, layers.IPProtocolTCP)
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: 1, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	return serializePacket(t, eth, ip, tcp, gopacket.Payload(payload))
}

func baselineEthernetIPv4(dst net.IP, protocol layers.IPProtocol) (*layers.Ethernet, *layers.IPv4) {
	return &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 10).To4(), DstIP: dst.To4(), Protocol: protocol}
}
