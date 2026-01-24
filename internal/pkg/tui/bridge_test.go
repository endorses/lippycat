//go:build tui || all

package tui

import (
	"net"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestConvertPacketFast_SIPDetection verifies that SIP INVITE packets
// are correctly detected even in the fast conversion path
func TestConvertPacketFast_SIPDetection(t *testing.T) {
	tests := []struct {
		name          string
		sipPayload    []byte
		expectedProto string
		useTCP        bool
	}{
		{
			name:          "UDP SIP INVITE",
			sipPayload:    []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP REGISTER",
			sipPayload:    []byte("REGISTER sip:example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP ACK",
			sipPayload:    []byte("ACK sip:bob@example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP BYE",
			sipPayload:    []byte("BYE sip:bob@example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP response",
			sipPayload:    []byte("SIP/2.0 200 OK\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "TCP SIP INVITE",
			sipPayload:    []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP"),
			expectedProto: "SIP",
			useTCP:        true,
		},
		{
			name:          "UDP non-SIP",
			sipPayload:    []byte("GET / HTTP/1.1\r\n"),
			expectedProto: "UDP",
			useTCP:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a packet
			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				EthernetType: layers.EthernetTypeIPv4,
			}

			ip := &layers.IPv4{
				Version: 4,
				TTL:     64,
				IHL:     5,
				SrcIP:   net.IP{192, 168, 1, 1},
				DstIP:   net.IP{192, 168, 1, 2},
			}

			var packet gopacket.Packet
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true}

			if tt.useTCP {
				ip.Protocol = layers.IPProtocolTCP
				tcp := &layers.TCP{
					SrcPort:    5060,
					DstPort:    5060,
					SYN:        false,
					ACK:        true,
					PSH:        true, // Data packet
					DataOffset: 5,    // 20 bytes header (5 * 4)
					Seq:        1000,
					Ack:        1000,
					Window:     65535,
				}
				tcp.SetNetworkLayerForChecksum(ip)
				err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(tt.sipPayload))
				assert.NoError(t, err)
			} else {
				ip.Protocol = layers.IPProtocolUDP
				udp := &layers.UDP{
					SrcPort: 5060,
					DstPort: 5060,
				}
				udp.SetNetworkLayerForChecksum(ip)
				err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(tt.sipPayload))
				assert.NoError(t, err)
			}

			packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			// Convert using fast path
			pktInfo := capture.PacketInfo{
				Packet:    packet,
				Interface: "test0",
			}

			display := convertPacketFast(pktInfo)

			// Verify protocol detection
			assert.Equal(t, tt.expectedProto, display.Protocol,
				"Protocol should be %s for %s", tt.expectedProto, tt.name)
		})
	}
}

// TestConvertPacketFast_NonSIPUDP verifies that non-SIP UDP packets
// are still correctly identified as UDP
func TestConvertPacketFast_NonSIPUDP(t *testing.T) {
	// Build a DNS query packet (UDP but not SIP)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Random payload (not SIP)
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	assert.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		Packet:    packet,
		Interface: "test0",
	}
	display := convertPacketFast(pktInfo)

	// Should be detected as UDP, not SIP
	assert.Equal(t, "UDP", display.Protocol)
	assert.Equal(t, "12345", display.SrcPort)
	assert.Equal(t, "53", display.DstPort)
}

// TestTCPSIPFlowCache tests the TCP SIP flow cache functionality
func TestTCPSIPFlowCache(t *testing.T) {
	// Clear cache before test
	ClearTCPSIPFlowCache()

	flowKey := getTCPFlowKey("192.168.1.1", "192.168.1.2", "5060", "5061")

	// Flow should not be cached initially
	assert.False(t, isTCPSIPFlow(flowKey))

	// Mark flow as SIP
	markTCPSIPFlow(flowKey)

	// Flow should now be cached
	assert.True(t, isTCPSIPFlow(flowKey))

	// Symmetric flow key should also be cached
	reverseFlowKey := getTCPFlowKey("192.168.1.2", "192.168.1.1", "5061", "5060")
	assert.Equal(t, flowKey, reverseFlowKey, "Flow keys should be symmetric")

	// Clear cache
	ClearTCPSIPFlowCache()
	assert.False(t, isTCPSIPFlow(flowKey))
}

// TestGetTCPFlowKey tests that flow keys are symmetric
func TestGetTCPFlowKey(t *testing.T) {
	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		srcPort  string
		dstPort  string
		expected string
	}{
		{
			name:     "forward direction",
			srcIP:    "10.0.0.1",
			dstIP:    "10.0.0.2",
			srcPort:  "5060",
			dstPort:  "5061",
			expected: "10.0.0.1:5060-10.0.0.2:5061",
		},
		{
			name:     "reverse direction same key",
			srcIP:    "10.0.0.2",
			dstIP:    "10.0.0.1",
			srcPort:  "5061",
			dstPort:  "5060",
			expected: "10.0.0.1:5060-10.0.0.2:5061",
		},
		{
			name:     "same IP different ports",
			srcIP:    "192.168.1.1",
			dstIP:    "192.168.1.1",
			srcPort:  "1000",
			dstPort:  "2000",
			expected: "192.168.1.1:1000-192.168.1.1:2000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := getTCPFlowKey(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort)
			assert.Equal(t, tt.expected, key)
		})
	}

	// Test symmetry: forward and reverse should produce same key
	forward := getTCPFlowKey("10.0.0.1", "10.0.0.2", "5060", "5061")
	reverse := getTCPFlowKey("10.0.0.2", "10.0.0.1", "5061", "5060")
	assert.Equal(t, forward, reverse, "Flow keys should be symmetric")
}

// TestIsTCPOnSIPPort tests port-based SIP detection
func TestIsTCPOnSIPPort(t *testing.T) {
	tests := []struct {
		srcPort  string
		dstPort  string
		expected bool
	}{
		{"5060", "12345", true},   // Source is SIP port
		{"12345", "5060", true},   // Dest is SIP port
		{"5061", "12345", true},   // Source is SIP/TLS port
		{"12345", "5061", true},   // Dest is SIP/TLS port
		{"5060", "5061", true},    // Both are SIP ports
		{"12345", "54321", false}, // Neither is SIP port
		{"80", "443", false},      // HTTP/HTTPS ports
	}

	for _, tt := range tests {
		t.Run(tt.srcPort+"-"+tt.dstPort, func(t *testing.T) {
			result := isTCPOnSIPPort(tt.srcPort, tt.dstPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContainsSIPHeaders tests SIP header detection in payload
func TestContainsSIPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "Full SIP INVITE",
			payload:  []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 192.168.1.1:5060\r\nCall-ID: abc123@example.com\r\n"),
			expected: true,
		},
		{
			name:     "SIP continuation with Call-ID",
			payload:  []byte("Content-Length: 100\r\nCall-ID: xyz789@example.com\r\n\r\nv=0"),
			expected: true,
		},
		{
			name:     "SIP continuation with Via header",
			payload:  []byte("some other header\r\nVia: SIP/2.0/TCP 10.0.0.1:5060\r\n"),
			expected: true,
		},
		{
			name:     "SIP continuation with compact Call-ID",
			payload:  []byte("f: alice@example.com\r\ni: call123\r\n"),
			expected: true,
		},
		{
			name:     "SIP continuation with CSeq",
			payload:  []byte("random data\r\nCSeq: 1 INVITE\r\n"),
			expected: true,
		},
		{
			name:     "HTTP request",
			payload:  []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n"),
			expected: false,
		},
		{
			name:     "Random binary data",
			payload:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "Short payload",
			payload:  []byte("Hi"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSIPHeaders(tt.payload)
			assert.Equal(t, tt.expected, result, "Payload: %s", string(tt.payload))
		})
	}
}

// TestConvertPacketFast_TCPSIPContinuation tests detection of TCP SIP
// continuation packets that don't start with a SIP method
func TestConvertPacketFast_TCPSIPContinuation(t *testing.T) {
	// Clear cache before test
	ClearTCPSIPFlowCache()

	// Build a TCP packet with SIP headers but not starting with a method
	// (simulating a continuation packet)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 2},
	}

	tcp := &layers.TCP{
		SrcPort:    5060,
		DstPort:    5060,
		SYN:        false,
		ACK:        true,
		PSH:        true,
		DataOffset: 5,
		Seq:        2000, // Second packet in stream
		Ack:        1000,
		Window:     65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Payload that looks like SIP continuation (has headers but no method at start)
	continuationPayload := []byte("Content-Type: application/sdp\r\nCall-ID: test123@example.com\r\n\r\nv=0\r\no=- 123 456 IN IP4 192.168.1.1")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(continuationPayload))
	assert.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		Packet:    packet,
		Interface: "test0",
	}

	display := convertPacketFast(pktInfo)

	// Should be detected as SIP due to port-based hinting (5060)
	assert.Equal(t, "SIP", display.Protocol,
		"TCP SIP on port 5060 should be detected as SIP even without method prefix")

	// Clean up
	ClearTCPSIPFlowCache()
}

// TestConvertPacketFast_TCPSIPFlowMemory tests that once a flow is
// marked as SIP, subsequent packets are also detected as SIP
func TestConvertPacketFast_TCPSIPFlowMemory(t *testing.T) {
	// Clear cache before test
	ClearTCPSIPFlowCache()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}

	// First packet: SIP INVITE on non-standard port
	tcp1 := &layers.TCP{
		SrcPort:    8888,
		DstPort:    9999,
		SYN:        false,
		ACK:        true,
		PSH:        true,
		DataOffset: 5,
		Seq:        1000,
		Ack:        1000,
		Window:     65535,
	}
	tcp1.SetNetworkLayerForChecksum(ip)

	sipInvite := []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 10.0.0.1:8888\r\n")

	buffer1 := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer1, options, eth, ip, tcp1, gopacket.Payload(sipInvite))
	assert.NoError(t, err)

	packet1 := gopacket.NewPacket(buffer1.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo1 := capture.PacketInfo{Packet: packet1, Interface: "test0"}

	display1 := convertPacketFast(pktInfo1)
	assert.Equal(t, "SIP", display1.Protocol, "First packet with INVITE should be detected as SIP")

	// Second packet: continuation (no SIP method, no SIP headers, just data)
	tcp2 := &layers.TCP{
		SrcPort:    8888,
		DstPort:    9999,
		SYN:        false,
		ACK:        true,
		PSH:        true,
		DataOffset: 5,
		Seq:        2000,
		Ack:        1500,
		Window:     65535,
	}
	tcp2.SetNetworkLayerForChecksum(ip)

	// Pure binary payload with no SIP indicators
	binaryPayload := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

	buffer2 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer2, options, eth, ip, tcp2, gopacket.Payload(binaryPayload))
	assert.NoError(t, err)

	packet2 := gopacket.NewPacket(buffer2.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo2 := capture.PacketInfo{Packet: packet2, Interface: "test0"}

	display2 := convertPacketFast(pktInfo2)
	assert.Equal(t, "SIP", display2.Protocol,
		"Second packet on same flow should be detected as SIP due to flow memory")

	// Clean up
	ClearTCPSIPFlowCache()
}
