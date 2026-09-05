package remotecapture

import (
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestPacketDisplayTransportSurvivesApplicationMetadata(t *testing.T) {
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP} {
		t.Run(protocol.String(), func(t *testing.T) {
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: protocol,
				SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
			var transport gopacket.SerializableLayer
			if protocol == layers.IPProtocolTCP {
				tcp := &layers.TCP{SrcPort: 12000, DstPort: 53, SYN: true}
				require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
				transport = tcp
			} else {
				udp := &layers.UDP{SrcPort: 12000, DstPort: 53}
				require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
				transport = udp
			}
			buf := gopacket.NewSerializeBuffer()
			require.NoError(t, gopacket.SerializeLayers(buf,
				gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, transport))
			client := &Client{}
			display := client.convertToPacketDisplay(&data.CapturedPacket{
				Data: buf.Bytes(), LinkType: uint32(layers.LinkTypeRaw), InterfaceName: "test0",
				Metadata: &data.PacketMetadata{Protocol: "DNS"},
			}, "hunter-1")
			require.Equal(t, "DNS", display.Protocol)
			require.Equal(t, uint8(protocol), display.Transport)
		})
	}
}

func TestPacketDisplayTransportFromMetadataWithoutDecodedBytes(t *testing.T) {
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP} {
		t.Run(protocol.String(), func(t *testing.T) {
			client := &Client{}
			display := client.convertToPacketDisplay(&data.CapturedPacket{
				InterfaceName: "test0",
				Metadata: &data.PacketMetadata{Protocol: "DNS", Transport: protocol.String(),
					SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 12000, DstPort: 53},
			}, "hunter-1")
			require.Equal(t, uint8(protocol), display.Transport)
			require.Equal(t, "192.0.2.1", display.SrcIP)
			require.Equal(t, "12000", display.SrcPort)
		})
	}
}
