package detector

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSIPWithGopacketDecodedSDP verifies that SDP is extracted correctly
// when gopacket decodes the SIP layer (which returns only headers in LayerContents).
// This was a bug where ApplicationLayer().LayerContents() returned only SIP headers,
// missing the SDP body which is only available in TransportLayer().LayerPayload().
func TestSIPWithGopacketDecodedSDP(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=alice 1 1 IN IP4 192.0.2.20\r\n" +
		"s=Synthetic call\r\n" +
		"c=IN IP4 192.0.2.20\r\n" +
		"t=0 0\r\n" +
		"m=audio 17802 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"
	sip := "INVITE sip:bob@example.test SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-synthetic\r\n" +
		"From: <sip:alice@example.test>;tag=alice\r\n" +
		"To: <sip:bob@example.test>\r\n" +
		"Call-ID: synthetic-sdp@example.test\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(sdp), sdp)
	ethernet := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2),
	}
	udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet, ip, udp, gopacket.Payload(sip)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	require.Nil(t, packet.ErrorLayer())

	det := InitDefault()
	t.Cleanup(det.Shutdown)

	// Verify gopacket decoded this as SIP (this is the condition that triggers the bug)
	packetLayers := packet.Layers()
	var hasSIPLayer bool
	for _, layer := range packetLayers {
		if layer.LayerType().String() == "SIP" {
			hasSIPLayer = true
			break
		}
	}
	require.True(t, hasSIPLayer, "Expected gopacket to decode SIP layer")

	// Run detection
	result := det.Detect(packet)
	require.NotNil(t, result)
	assert.Equal(t, "SIP", result.Protocol)

	// Verify Call-ID is extracted
	callID, ok := result.Metadata["call_id"].(string)
	assert.True(t, ok, "call_id should be in metadata")
	assert.Equal(t, "synthetic-sdp@example.test", callID)

	// Verify SDP media_ports is extracted (this was the bug - it was empty before the fix)
	mediaPorts, ok := result.Metadata["media_ports"].([]uint16)
	assert.True(t, ok, "media_ports should be in metadata")
	assert.NotEmpty(t, mediaPorts, "media_ports should not be empty")
	assert.Contains(t, mediaPorts, uint16(17802), "Should contain port 17802 from SDP")

	// Verify media_ip is extracted
	mediaIP, ok := result.Metadata["media_ip"].(string)
	assert.True(t, ok, "media_ip should be in metadata")
	assert.Equal(t, "192.0.2.20", mediaIP)
}
