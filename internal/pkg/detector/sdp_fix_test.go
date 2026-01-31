package detector

import (
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSIPWithGopacketDecodedSDP verifies that SDP is extracted correctly
// when gopacket decodes the SIP layer (which returns only headers in LayerContents).
// This was a bug where ApplicationLayer().LayerContents() returned only SIP headers,
// missing the SDP body which is only available in TransportLayer().LayerPayload().
func TestSIPWithGopacketDecodedSDP(t *testing.T) {
	pcapFile := "/home/grischa/Downloads/pcaps/gk_72_sip_65f935f1-10d1-411a-8d6f-0ab721165c46.pcap"

	// Skip if pcap file doesn't exist
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("Test pcap file not found")
	}

	handle, err := pcap.OpenOffline(pcapFile)
	require.NoError(t, err)
	defer handle.Close()

	det := InitDefault()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packet, err := packetSource.NextPacket()
	require.NoError(t, err)
	require.NotNil(t, packet)

	// Verify gopacket decoded this as SIP (this is the condition that triggers the bug)
	layers := packet.Layers()
	var hasSIPLayer bool
	for _, layer := range layers {
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
	assert.Equal(t, "65f935f1-10d1-411a-8d6f-0ab721165c46", callID)

	// Verify SDP media_ports is extracted (this was the bug - it was empty before the fix)
	mediaPorts, ok := result.Metadata["media_ports"].([]uint16)
	assert.True(t, ok, "media_ports should be in metadata")
	assert.NotEmpty(t, mediaPorts, "media_ports should not be empty")
	assert.Contains(t, mediaPorts, uint16(17802), "Should contain port 17802 from SDP")

	// Verify media_ip is extracted
	mediaIP, ok := result.Metadata["media_ip"].(string)
	assert.True(t, ok, "media_ip should be in metadata")
	assert.Equal(t, "78.111.74.204", mediaIP)
}
