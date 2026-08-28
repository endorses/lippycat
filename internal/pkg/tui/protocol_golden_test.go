//go:build tui || all

package tui

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type protocolGolden struct {
	Protocol  string `json:"protocol"`
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   string `json:"src_port"`
	DstPort   string `json:"dst_port"`
	Info      string `json:"info"`
}

func TestLocalTUIProtocolEventGoldens(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "baseline", "testdata", "protocol-events.json"))
	require.NoError(t, err)
	var goldens []protocolGolden
	require.NoError(t, json.Unmarshal(data, &goldens))
	require.Len(t, goldens, 5)

	packets := map[string][]byte{
		"DNS":  goldenDNSPacket(t),
		"TLS":  goldenTCPPacket(t, 49152, 443, goldenTLSClientHello()),
		"HTTP": goldenTCPPacket(t, 49153, 80, []byte("GET /baseline HTTP/1.1\r\nHost: example.test\r\n\r\n")),
		"SMTP": goldenTCPPacket(t, 49154, 25, []byte("MAIL FROM:<alice@example.test>\r\n")),
		"SIP":  goldenUDPPacket(t, 5060, 5060, []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: baseline-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")),
	}
	fileEvents := make([]types.PacketDisplay, 0, len(goldens))
	fileInfos := make([]capture.PacketInfo, 0, len(goldens))
	liveInfos := make([]capture.PacketInfo, 0, len(goldens))
	for _, want := range goldens {
		ts, err := time.Parse(time.RFC3339Nano, want.Timestamp)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), want.Protocol+".pcap")
		writeGoldenPCAP(t, path, packets[want.Protocol], ts)
		file, err := os.Open(path)
		require.NoError(t, err)
		var observed []types.PacketDisplay
		capture.RunOfflineOrdered([]pcaptypes.PcapInterface{pcaptypes.CreateOfflineInterface(file)}, "", func(ch <-chan capture.PacketInfo, _ *capture.TCPAssembler) {
			for info := range ch {
				fileInfos = append(fileInfos, info)
				observed = append(observed, convertPacket(info))
			}
		}, nil)
		require.NoError(t, file.Close())
		require.Len(t, observed, 1)
		fileEvents = append(fileEvents, observed[0])

		livePacket := gopacket.NewPacket(packets[want.Protocol], layers.LayerTypeEthernet, gopacket.Default)
		livePacket.Metadata().Timestamp = ts
		livePacket.Metadata().Length = len(livePacket.Data())
		liveInfos = append(liveInfos, capture.PacketInfo{Packet: livePacket, Interface: "golden0", LinkType: layers.LinkTypeEthernet})
	}

	for mode, infos := range map[string][]capture.PacketInfo{"watch-file": fileInfos, "watch-live": liveInfos} {
		bridged := runProtocolGoldenBridge(t, infos, mode == "watch-file")
		require.Len(t, bridged, len(goldens))
		for i, want := range goldens {
			got := bridged[i]
			require.Equal(t, want.Protocol, got.Protocol, mode)
			require.Equal(t, want.Timestamp, got.Timestamp.UTC().Format(time.RFC3339Nano), mode)
			require.Equal(t, want.SrcIP, got.SrcIP, mode)
			require.Equal(t, want.DstIP, got.DstIP, mode)
			require.Equal(t, want.SrcPort, got.SrcPort, mode)
			require.Equal(t, want.DstPort, got.DstPort, mode)
			require.Equal(t, want.Info, got.Info, mode)
		}
		if mode == "watch-file" {
			fileEvents = bridged
		}
	}

	// Cross the actual Bubble Tea message boundary used by both the local bridge
	// and TUIEventHandler, then assert the model/store observable state.
	model := NewModel(32, 32, "", "", []string{"representative-protocols.pcap"}, false, false, "", false)
	t.Cleanup(model.backgroundProcessor.Stop)
	updated, _ := model.Update(PacketBatchMsg{Packets: fileEvents})
	gotModel := updated.(Model)
	stored := gotModel.packetStore.GetPacketsInOrder()
	require.Len(t, stored, len(goldens))
	for i, want := range goldens {
		require.Equal(t, want.Protocol, stored[i].Protocol)
		require.Equal(t, want.Timestamp, stored[i].Timestamp.UTC().Format(time.RFC3339Nano))
		require.Equal(t, "Local", stored[i].NodeID)
	}
}

func runProtocolGoldenBridge(t *testing.T, infos []capture.PacketInfo, offline bool) []types.PacketDisplay {
	t.Helper()
	ResetBridgeStats()
	ClearPendingPackets()
	ClearCallTracker()
	ResetTUIReady()
	SignalTUIReady()
	SetVoIPModeEnabled(false)
	if offline {
		SetCallTracker(NewCallTracker())
		defer ClearCallTracker()
	}
	packetChan := make(chan capture.PacketInfo, len(infos))
	for _, info := range infos {
		packetChan <- info
	}
	close(packetChan)
	StartPacketBridge(packetChan, nil, NewPauseSignal())
	stats := GetBridgeStats()
	require.Equal(t, int64(len(infos)), stats.PacketsReceived)
	require.Equal(t, int64(len(infos)), stats.PacketsDisplayed)
	require.Zero(t, stats.BatchesDropped)
	return pendingPackets.drainPackets(len(infos))
}

func writeGoldenPCAP(t *testing.T, path string, packet []byte, timestamp time.Time) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(packet), Length: len(packet)}, packet))
	require.NoError(t, f.Close())
}

func goldenDNSPacket(t *testing.T) []byte {
	t.Helper()
	eth, ip := goldenEthernetIPv4(layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	dns := &layers.DNS{ID: 7, RD: true, QDCount: 1, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	return goldenSerialize(t, eth, ip, udp, dns)
}

func goldenUDPPacket(t *testing.T, src, dst layers.UDPPort, payload []byte) []byte {
	t.Helper()
	eth, ip := goldenEthernetIPv4(layers.IPProtocolUDP)
	if dst == 5060 {
		ip.DstIP = net.ParseIP("198.51.100.50").To4()
	}
	udp := &layers.UDP{SrcPort: src, DstPort: dst}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	return goldenSerialize(t, eth, ip, udp, gopacket.Payload(payload))
}

func goldenTCPPacket(t *testing.T, src, dst layers.TCPPort, payload []byte) []byte {
	t.Helper()
	eth, ip := goldenEthernetIPv4(layers.IPProtocolTCP)
	switch dst {
	case 443:
		ip.DstIP = net.ParseIP("198.51.100.20").To4()
	case 80:
		ip.DstIP = net.ParseIP("198.51.100.80").To4()
	case 25:
		ip.DstIP = net.ParseIP("198.51.100.25").To4()
	}
	tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: 1, ACK: true, PSH: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	return goldenSerialize(t, eth, ip, tcp, gopacket.Payload(payload))
}

func goldenEthernetIPv4(protocol layers.IPProtocol) (*layers.Ethernet, *layers.IPv4) {
	return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("192.0.2.10").To4(), DstIP: net.ParseIP("198.51.100.53").To4(), Protocol: protocol}
}

func goldenSerialize(t *testing.T, layersToWrite ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, layersToWrite...))
	return buf.Bytes()
}

func goldenTLSClientHello() []byte {
	ext := []byte{0, 0, 0, 16, 0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := binary.BigEndian.AppendUint16([]byte{22, 3, 1}, uint16(len(handshake)))
	return append(record, handshake...)
}
