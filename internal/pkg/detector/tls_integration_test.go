package detector

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestTLSDetectionIntegration tests TLS detection with full packet parsing
func TestTLSDetectionIntegration(t *testing.T) {
	// Initialize detector with all signatures
	d := InitDefault()

	// Create a TLS ClientHello packet
	tlsPayload := []byte{
		0x16,       // Handshake
		0x03, 0x03, // TLS 1.2
		0x00, 0x05, // Length: 5 bytes
		0x01,             // ClientHello
		0x00, 0x00, 0x01, // Handshake length
		0x03, 0x03, // TLS 1.2 in handshake
	}

	// Build a complete packet with Ethernet, IP, TCP, and TLS payload
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create layers
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		Seq:     1000,
		Ack:     0,
		SYN:     false,
		ACK:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize with TLS payload
	err := gopacket.SerializeLayers(buf, opts,
		eth,
		ip,
		tcp,
		gopacket.Payload(tlsPayload),
	)
	assert.NoError(t, err)

	// Parse the packet
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Debug: Check what layers are present
	t.Logf("Packet layers: %v", packet.Layers())
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		t.Logf("Application layer payload length: %d", len(appLayer.Payload()))
		t.Logf("Application layer payload (hex): %x", appLayer.Payload())
	} else {
		t.Logf("No application layer detected")
	}
	if transLayer := packet.TransportLayer(); transLayer != nil {
		t.Logf("Transport layer payload length: %d", len(transLayer.LayerPayload()))
		t.Logf("Transport layer payload (hex): %x", transLayer.LayerPayload())
	}

	// Detect protocol
	result := d.Detect(packet)

	// Should detect TLS
	assert.NotNil(t, result)
	assert.Equal(t, "TLS", result.Protocol)
	assert.Greater(t, result.Confidence, 0.7)
}
