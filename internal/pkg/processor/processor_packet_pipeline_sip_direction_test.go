//go:build (processor || tap || all) && li

package processor

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestProcessorSIPPacketDisplayKeepsResponseSenderAndRawMessage(t *testing.T) {
	p, _, filterID := newLIProcessor(t, li.DeliveryX2Only)
	var observed []types.PacketDisplay
	p.liManager.SetPacketProcessor(func(_ *li.InterceptTask, packet *types.PacketDisplay) {
		observed = append(observed, *packet)
	})

	const callID = "tcp-direction-processor@example.test"
	invite := []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: " + callID + "\r\nContent-Length: 0\r\n\r\n")
	response := []byte("SIP/2.0 200 OK\r\nWarning: 399 proxy INVITE check\r\nCall-ID: " + callID + "\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	packet := func(payload []byte, srcIP, dstIP string, srcPort, dstPort layers.TCPPort, method string, status uint32) *data.CapturedPacket {
		t.Helper()
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4()}
		tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: 1, ACK: true}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
		return &data.CapturedPacket{
			TimestampNs: time.Now().UnixNano(), Data: buf.Bytes(), LinkType: uint32(layers.LinkTypeEthernet),
			MatchedFilterIds: []string{filterID}, DirectMatchedFilterIds: []string{filterID},
			Metadata: &data.PacketMetadata{
				SrcIp: srcIP, DstIp: dstIP, SrcPort: uint32(srcPort), DstPort: uint32(dstPort), Protocol: "SIP",
				Sip: &data.SIPMetadata{CallId: callID, Method: method, ResponseCode: status, CseqMethod: "INVITE", FromUri: dirTargetURI, ToUri: dirRemoteURI},
			},
		}
	}
	p.processBatch(source.FromProtoBatch(&data.PacketBatch{HunterId: "synthetic-hunter", Packets: []*data.CapturedPacket{
		packet(invite, "192.0.2.10", "198.51.100.20", 9202, 63781, "INVITE", 0),
		packet(response, "198.51.100.20", "192.0.2.10", 63781, 9202, "", 200),
	}}))

	require.Len(t, observed, 2)
	require.Equal(t, "192.0.2.10", observed[0].SrcIP)
	require.Equal(t, "198.51.100.20", observed[0].DstIP)
	require.Equal(t, "9202", observed[0].SrcPort)
	require.Equal(t, "63781", observed[0].DstPort)
	require.Equal(t, invite, observed[0].VoIPData.RawSIP)
	require.Equal(t, "198.51.100.20", observed[1].SrcIP)
	require.Equal(t, "192.0.2.10", observed[1].DstIP)
	require.Equal(t, "63781", observed[1].SrcPort)
	require.Equal(t, "9202", observed[1].DstPort)
	require.Equal(t, response, observed[1].VoIPData.RawSIP)
}
