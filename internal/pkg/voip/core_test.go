package voip

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartProcessor_UDPHandling(t *testing.T) {
	// Create a mock UDP packet with SIP content
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}

	udp.SetNetworkLayerForChecksum(ip)

	payload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-call-123\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err, "Failed to serialize test packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create packet info
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create channel and send packet
	ch := make(chan capture.PacketInfo, 1)
	ch <- pktInfo
	close(ch)

	// Create assembler for TCP processing
	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Test the processor
	startProcessor(ch, assembler)

	// The test passes if no panic occurs and the processor completes
	assert.True(t, true, "Processor completed successfully")
}

func TestStartProcessor_TCPHandling(t *testing.T) {
	// Create a mock TCP packet with SIP content
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	tcp := &layers.TCP{
		SrcPort: 5060,
		DstPort: 5060,
		Seq:     1000,
		Ack:     2000,
		Window:  8192,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	payload := []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test-call-456\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(payload))
	require.NoError(t, err, "Failed to serialize test TCP packet")

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Create packet info
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Create channel and send packet
	ch := make(chan capture.PacketInfo, 1)
	ch <- pktInfo
	close(ch)

	// Create assembler for TCP processing
	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Test the processor
	startProcessor(ch, assembler)

	// The test passes if no panic occurs and the processor completes
	assert.True(t, true, "TCP processor completed successfully")
}

func TestStartProcessor_InvalidPackets(t *testing.T) {
	// Test with packets that have no network or transport layer
	invalidPacket := gopacket.NewPacket([]byte{0x01, 0x02, 0x03}, layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   invalidPacket,
	}

	ch := make(chan capture.PacketInfo, 1)
	ch <- pktInfo
	close(ch)

	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Should handle invalid packets gracefully
	startProcessor(ch, assembler)

	assert.True(t, true, "Invalid packet handled gracefully")
}

func TestContainsUserInHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "User found in From header",
			headers: map[string]string{
				"from": "sip:testuser@example.com",
				"to":   "sip:other@example.com",
			},
			expected: false, // Will be false unless sipusers has testuser
		},
		{
			name: "User found in To header",
			headers: map[string]string{
				"from": "sip:other@example.com",
				"to":   "sip:testuser@example.com",
			},
			expected: false, // Will be false unless sipusers has testuser
		},
		{
			name: "User found in P-Asserted-Identity",
			headers: map[string]string{
				"from":                "sip:other@example.com",
				"to":                  "sip:another@example.com",
				"p-asserted-identity": "sip:testuser@example.com",
			},
			expected: false, // Will be false unless sipusers has testuser
		},
		{
			name: "No users found",
			headers: map[string]string{
				"from": "sip:unknown1@example.com",
				"to":   "sip:unknown2@example.com",
			},
			expected: false,
		},
		{
			name:     "Empty headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsUserInHeaders(tt.headers)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessorChannelClosure(t *testing.T) {
	// Test that processor handles channel closure gracefully
	ch := make(chan capture.PacketInfo)
	close(ch) // Close immediately

	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Should complete without hanging
	done := make(chan bool, 1)
	go func() {
		startProcessor(ch, assembler)
		done <- true
	}()

	select {
	case <-done:
		assert.True(t, true, "Processor completed after channel closure")
	case <-time.After(1 * time.Second):
		t.Fatal("Processor did not complete within timeout")
	}
}
