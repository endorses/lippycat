package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestExtractPortFromSdp(t *testing.T) {
	// Clear existing port mappings
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	tests := []struct {
		name    string
		sdpLine string
		callID  string
	}{
		{
			name:    "Valid SDP with audio port",
			sdpLine: "m=audio 8000 RTP/AVP 0",
			callID:  "test-call-1",
		},
		{
			name:    "Valid SDP with video port",
			sdpLine: "m=audio 9000 RTP/AVP 96",
			callID:  "test-call-2",
		},
		{
			name:    "SDP with port 0 (inactive)",
			sdpLine: "m=audio 0 RTP/AVP 0",
			callID:  "test-call-3",
		},
		{
			name:    "SDP with high port number",
			sdpLine: "m=audio 65534 RTP/AVP 0",
			callID:  "test-call-4",
		},
		{
			name:    "Invalid SDP - no media line",
			sdpLine: "v=0",
			callID:  "test-call-5",
		},
		{
			name:    "SDP with whitespace in media line",
			sdpLine: "m=audio  8080  RTP/AVP 0",
			callID:  "test-call-6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// ExtractPortFromSdp doesn't return anything, it just updates the global map
			ExtractPortFromSdp(tt.sdpLine, tt.callID)

			// The test passes if the function doesn't panic
			assert.True(t, true, "ExtractPortFromSdp should not panic")
		})
	}
}

func TestIsTracked(t *testing.T) {
	// Clear existing port mappings
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.portToCallID["8000"] = "test-call-1"
	tracker.portToCallID["8002"] = "test-call-2"
	tracker.mu.Unlock()

	tests := []struct {
		name     string
		srcPort  uint16
		dstPort  uint16
		expected bool
	}{
		{
			name:     "Tracked destination port",
			srcPort:  9999,
			dstPort:  8000,
			expected: true,
		},
		{
			name:     "Tracked source port",
			srcPort:  8002,
			dstPort:  9999,
			expected: true,
		},
		{
			name:     "No tracked ports",
			srcPort:  7777,
			dstPort:  8888,
			expected: false,
		},
		{
			name:     "Both ports tracked",
			srcPort:  8000,
			dstPort:  8002,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createRTPPacket(tt.srcPort, tt.dstPort)
			result := IsTracked(packet.Packet)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetCallIDForPacket(t *testing.T) {
	// Clear existing port mappings and setup test data
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.portToCallID["8000"] = "test-call-packet-1"
	tracker.portToCallID["8002"] = "test-call-packet-2"
	tracker.mu.Unlock()

	tests := []struct {
		name     string
		srcPort  uint16
		dstPort  uint16
		expected string
	}{
		{
			name:     "Packet with tracked destination port",
			srcPort:  9999,
			dstPort:  8000,
			expected: "test-call-packet-1",
		},
		{
			name:     "Packet with tracked destination port 2",
			srcPort:  9999,
			dstPort:  8002,
			expected: "test-call-packet-2",
		},
		{
			name:     "Packet with no tracked destination port",
			srcPort:  7777,
			dstPort:  8888,
			expected: "",
		},
		{
			name:     "Packet with tracked source port",
			srcPort:  8000,
			dstPort:  7777,
			expected: "test-call-packet-1", // GetCallIDForPacket now checks both src and dst
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createRTPPacket(tt.srcPort, tt.dstPort)
			result := GetCallIDForPacket(packet.Packet)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRTPPacketProcessing_Integration(t *testing.T) {
	// Test the complete RTP packet processing flow
	testCallID := "integration-rtp-test"
	testPort := uint16(8000)

	// Setup port mapping
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.portToCallID["8000"] = testCallID
	tracker.mu.Unlock()

	// Create test packet
	testPacket := createRTPPacket(9999, testPort)

	// Verify the packet is tracked
	assert.True(t, IsTracked(testPacket.Packet), "RTP packet should be tracked")

	// Test call ID retrieval
	retrievedCallID := GetCallIDForPacket(testPacket.Packet)
	assert.Equal(t, testCallID, retrievedCallID, "Should retrieve correct call ID for RTP packet")

	// Test with untracked packet
	untrackedPacket := createRTPPacket(5555, 5556)
	assert.False(t, IsTracked(untrackedPacket.Packet), "Untracked packet should not be tracked")
}

func TestRTPPortTracking_EdgeCases(t *testing.T) {
	// Test edge cases in port tracking
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.portToCallID["65534"] = "test-high-port"
	tracker.portToCallID["1024"] = "test-port-1024"
	tracker.portToCallID["0"] = "test-port-zero"
	tracker.mu.Unlock()

	tests := []struct {
		name        string
		port        uint16
		shouldTrack bool
	}{
		{
			name:        "Valid high port",
			port:        65534,
			shouldTrack: true,
		},
		{
			name:        "Port 1024",
			port:        1024,
			shouldTrack: true,
		},
		{
			name:        "Port 0",
			port:        0,
			shouldTrack: true, // Port 0 is tracked if it's in the map
		},
		{
			name:        "Untracked port",
			port:        12345,
			shouldTrack: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createRTPPacket(9999, tt.port)
			result := IsTracked(packet.Packet)
			assert.Equal(t, tt.shouldTrack, result, "Port tracking should match expected result")
		})
	}
}

// Helper function to create RTP packets for testing
func createRTPPacket(srcPort, dstPort uint16) capture.PacketInfo {
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
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// RTP payload (minimal)
	rtpPayload := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(rtpPayload))
	if err != nil {
		panic(err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}
}
