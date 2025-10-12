package pcap

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPacketDisplayToGopacket tests the conversion helper
func TestPacketDisplayToGopacket(t *testing.T) {
	now := time.Now()
	rawData := []byte{0x01, 0x02, 0x03, 0x04}

	pkt := types.PacketDisplay{
		Timestamp: now,
		Length:    100,
		RawData:   rawData,
	}

	ci, data, err := PacketDisplayToGopacket(pkt)
	require.NoError(t, err)
	assert.Equal(t, now, ci.Timestamp)
	assert.Equal(t, len(rawData), ci.CaptureLength)
	assert.Equal(t, 100, ci.Length)
	assert.Equal(t, rawData, data)
}

func TestPacketDisplayToGopacket_NoRawData(t *testing.T) {
	pkt := types.PacketDisplay{
		Timestamp: time.Now(),
		Length:    100,
		RawData:   nil,
	}

	_, _, err := PacketDisplayToGopacket(pkt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no raw data")
}

func TestPacketDisplayToGopacket_ZeroLength(t *testing.T) {
	rawData := []byte{0x01, 0x02, 0x03}
	pkt := types.PacketDisplay{
		Timestamp: time.Now(),
		Length:    0, // Zero length should use RawData length
		RawData:   rawData,
	}

	ci, _, err := PacketDisplayToGopacket(pkt)
	require.NoError(t, err)
	assert.Equal(t, len(rawData), ci.Length)
}

// Helper to create test packet
func createTestPacket(t *testing.T) types.PacketDisplay {
	// Create a simple UDP packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Ethernet layer
	ethLayer := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP layer
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// UDP layer
	udpLayer := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Payload
	payload := gopacket.Payload([]byte("Test packet data"))

	err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, payload)
	require.NoError(t, err)

	return types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.1",
		DstIP:     "192.168.1.2",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "UDP",
		Length:    len(buf.Bytes()),
		Info:      "Test packet",
		RawData:   buf.Bytes(),
		Interface: "test0",
	}
}

// Helper to verify PCAP file can be read
func verifyPcapFile(t *testing.T, filePath string, expectedCount int) {
	handle, err := pcap.OpenOffline(filePath)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	count := 0
	timeout := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-packets:
			if pkt == nil {
				// EOF
				assert.Equal(t, expectedCount, count, "Packet count mismatch")
				return
			}
			count++
		case <-timeout:
			t.Fatalf("Timeout reading packets, got %d expected %d", count, expectedCount)
		}
	}
}
