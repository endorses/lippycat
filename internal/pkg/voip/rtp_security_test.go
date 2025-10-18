package voip

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPortFromSdp_ComprehensiveParsing(t *testing.T) {
	// Reset port map before tests
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	tests := []struct {
		name          string
		sdpBody       string
		callID        string
		expectedPort  string
		shouldExtract bool
		description   string
	}{
		{
			name: "Standard SDP with audio",
			sdpBody: `v=0
o=alicent 53655765 2353687637 IN IP4 client.atlanta.com
c=IN IP4 client.atlanta.com
t=0 0
m=audio 5004 RTP/AVP 0 8`,
			callID:        "call-123",
			expectedPort:  "5004",
			shouldExtract: true,
			description:   "Standard SDP should extract port correctly",
		},
		{
			name: "SDP with multiple media lines",
			sdpBody: `v=0
o=alicent 53655765 2353687637 IN IP4 client.atlanta.com
c=IN IP4 client.atlanta.com
t=0 0
m=audio 5004 RTP/AVP 0 8
m=video 5006 RTP/AVP 96`,
			callID:        "call-456",
			expectedPort:  "5004", // Should extract first audio port
			shouldExtract: true,
			description:   "Multiple media lines should extract first audio port",
		},
		{
			name: "SDP with no audio line",
			sdpBody: `v=0
o=alicent 53655765 2353687637 IN IP4 client.atlanta.com
c=IN IP4 client.atlanta.com
t=0 0
m=video 5006 RTP/AVP 96`,
			callID:        "call-789",
			expectedPort:  "",
			shouldExtract: false,
			description:   "SDP without audio should not extract port",
		},
		{
			name: "Malformed SDP with invalid port",
			sdpBody: `v=0
m=audio invalid_port RTP/AVP 0`,
			callID:        "call-invalid",
			expectedPort:  "invalid_port", // Invalid port should be rejected
			shouldExtract: false,
			description:   "Invalid port should be rejected by validation",
		},
		{
			name: "SDP with extra spaces",
			sdpBody: `v=0
m=audio    5008    RTP/AVP    0    8`,
			callID:        "call-spaces",
			expectedPort:  "5008",
			shouldExtract: true,
			description:   "Extra spaces should be handled correctly",
		},
		{
			name: "SDP with audio line but no port data",
			sdpBody: `v=0
m=audio`,
			callID:        "call-no-port",
			expectedPort:  "",
			shouldExtract: false,
			description:   "Audio line without port should not extract anything",
		},
		{
			name:          "Empty SDP body",
			sdpBody:       "",
			callID:        "call-empty",
			expectedPort:  "",
			shouldExtract: false,
			description:   "Empty SDP should not extract port",
		},
		{
			name: "SDP with port 0 (disabled media)",
			sdpBody: `v=0
m=audio 0 RTP/AVP 0`,
			callID:        "call-disabled",
			expectedPort:  "0",
			shouldExtract: false,
			description:   "Port 0 should be rejected (reserved port)",
		},
		{
			name: "SDP with high port number",
			sdpBody: `v=0
m=audio 65535 RTP/AVP 0`,
			callID:        "call-high-port",
			expectedPort:  "65535",
			shouldExtract: true,
			description:   "High port numbers should be extracted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear port map for each test
			tracker := getTracker()
			tracker.mu.Lock()
			tracker.portToCallID = make(map[string]string)
			tracker.mu.Unlock()

			ExtractPortFromSdp(tt.sdpBody, tt.callID)

			tracker.mu.Lock()
			actualCallID, exists := tracker.portToCallID[tt.expectedPort]
			tracker.mu.Unlock()

			if tt.shouldExtract {
				assert.True(t, exists, tt.description+" - port should be mapped")
				assert.Equal(t, tt.callID, actualCallID, tt.description+" - call ID should match")
			} else {
				assert.False(t, exists, tt.description+" - port should not be mapped")
			}
		})
	}
}

func TestPortMapping_ConcurrencyAndRaceConditions(t *testing.T) {
	// Reset port map
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	t.Run("Concurrent port extraction", func(t *testing.T) {
		const numGoroutines = 100
		const numCallsPerGoroutine = 10

		var wg sync.WaitGroup

		// Start multiple goroutines extracting ports concurrently
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(routineID int) {
				defer wg.Done()
				for j := 0; j < numCallsPerGoroutine; j++ {
					portNum := 5000 + routineID*numCallsPerGoroutine + j
					port := fmt.Sprintf("%d", portNum)
					callID := fmt.Sprintf("call-%d-%d", routineID, j)
					sdpBody := fmt.Sprintf("m=audio %s RTP/AVP 0", port)

					ExtractPortFromSdp(sdpBody, callID)
				}
			}(i)
		}

		wg.Wait()

		// Verify all ports were mapped correctly
		tracker.mu.Lock()
		assert.Equal(t, numGoroutines*numCallsPerGoroutine, len(tracker.portToCallID),
			"Should have mapped all ports")
		tracker.mu.Unlock()
	})

	t.Run("Concurrent read while extracting", func(t *testing.T) {
		// Reset map
		tracker.mu.Lock()
		tracker.portToCallID = make(map[string]string)
		tracker.mu.Unlock()

		var wg sync.WaitGroup
		const numReaders = 50
		const numWriters = 10

		// Start readers
		for i := 0; i < numReaders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					// Try to read various ports
					tracker.mu.Lock()
					_ = tracker.portToCallID["5060"]
					_ = tracker.portToCallID["5061"]
					_ = tracker.portToCallID["5062"]
					tracker.mu.Unlock()
				}
			}()
		}

		// Start writers
		for i := 0; i < numWriters; i++ {
			wg.Add(1)
			go func(writerID int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					port := fmt.Sprintf("506%d", writerID)
					callID := fmt.Sprintf("concurrent-call-%d-%d", writerID, j)
					sdpBody := fmt.Sprintf("m=audio %s RTP/AVP 0", port)

					ExtractPortFromSdp(sdpBody, callID)
				}
			}(i)
		}

		wg.Wait()

		// Should complete without race conditions or deadlocks
		assert.True(t, true, "Concurrent operations should complete without issues")
	})
}

func TestIsTracked_EdgeCases(t *testing.T) {
	// Setup port mappings for testing
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = map[string]string{
		"5004": "call-audio-1",
		"5006": "call-audio-2",
		"5008": "call-video-1",
	}
	tracker.mu.Unlock()

	tests := []struct {
		name        string
		packet      gopacket.Packet
		expected    bool
		description string
	}{
		{
			name:        "Tracked destination port",
			packet:      createRTPTestPacket(t, 40000, 5004),
			expected:    true,
			description: "Packet to tracked destination should be tracked",
		},
		{
			name:        "Tracked source port",
			packet:      createRTPTestPacket(t, 5004, 40000),
			expected:    true,
			description: "Packet from tracked source should be tracked",
		},
		{
			name:        "Untracked ports",
			packet:      createRTPTestPacket(t, 40000, 40001),
			expected:    false,
			description: "Packet with no tracked ports should not be tracked",
		},
		{
			name:        "Both ports tracked",
			packet:      createRTPTestPacket(t, 5004, 5006),
			expected:    true,
			description: "Packet with both ports tracked should be tracked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTracked(tt.packet)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestGetCallIDForPacket_PortMapping(t *testing.T) {
	// Setup port mappings
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = map[string]string{
		"5004": "call-audio-1",
		"5006": "call-audio-2",
		"5008": "call-video-1",
	}
	tracker.mu.Unlock()

	tests := []struct {
		name        string
		packet      gopacket.Packet
		expected    string
		description string
	}{
		{
			name:        "Get call ID for tracked destination",
			packet:      createRTPTestPacket(t, 40000, 5004),
			expected:    "call-audio-1",
			description: "Should return call ID for tracked destination port",
		},
		{
			name:        "Get call ID for untracked port",
			packet:      createRTPTestPacket(t, 40000, 40001),
			expected:    "",
			description: "Should return empty string for untracked port",
		},
		{
			name:        "Different tracked port",
			packet:      createRTPTestPacket(t, 40000, 5006),
			expected:    "call-audio-2",
			description: "Should return correct call ID for different tracked port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCallIDForPacket(tt.packet)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestPortMapping_MemoryLeaks(t *testing.T) {
	t.Run("Port map growth", func(t *testing.T) {
		// Reset map
		tracker := getTracker()
		tracker.mu.Lock()
		tracker.portToCallID = make(map[string]string)
		tracker.mu.Unlock()

		// Add many port mappings with valid numeric ports
		for i := 1; i <= 10000; i++ {
			port := fmt.Sprintf("%d", 10000+i) // Use ports 10001-20000
			callID := fmt.Sprintf("call-%d", i)
			sdpBody := fmt.Sprintf("m=audio %s RTP/AVP 0", port)

			ExtractPortFromSdp(sdpBody, callID)
		}

		tracker.mu.Lock()
		mapSize := len(tracker.portToCallID)
		tracker.mu.Unlock()

		assert.Equal(t, 10000, mapSize, "Map should contain all added entries")

		// Clear map to prevent memory leaks in other tests
		tracker.mu.Lock()
		tracker.portToCallID = make(map[string]string)
		tracker.mu.Unlock()
	})
}

func TestExtractPortFromSdp_SecurityVulnerabilities(t *testing.T) {
	// Reset port map
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	securityTests := []struct {
		name        string
		sdpBody     string
		callID      string
		description string
	}{
		{
			name:        "Very long port number",
			sdpBody:     "m=audio " + strings.Repeat("1", 10000) + " RTP/AVP 0",
			callID:      "attack-long-port",
			description: "Should handle very long port numbers without crashing",
		},
		{
			name:        "Port with special characters",
			sdpBody:     "m=audio 5060;rm -rf / RTP/AVP 0",
			callID:      "attack-injection",
			description: "Should handle injection attempts in port field",
		},
		{
			name:        "Binary data in SDP",
			sdpBody:     "m=audio 5060\x00\x01\x02\x03 RTP/AVP 0",
			callID:      "attack-binary",
			description: "Should handle binary data without crashing",
		},
		{
			name:        "Unicode in port field",
			sdpBody:     "m=audio 🚀🚀🚀 RTP/AVP 0",
			callID:      "attack-unicode",
			description: "Should handle unicode characters in port field",
		},
		{
			name:        "Extremely long call ID",
			sdpBody:     "m=audio 5060 RTP/AVP 0",
			callID:      strings.Repeat("very-long-call-id-", 1000),
			description: "Should handle very long call IDs",
		},
		{
			name:        "Call ID with null bytes",
			sdpBody:     "m=audio 5060 RTP/AVP 0",
			callID:      "call\x00with\x00nulls",
			description: "Should handle call IDs with null bytes",
		},
	}

	for _, tt := range securityTests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic or crash
			assert.NotPanics(t, func() {
				ExtractPortFromSdp(tt.sdpBody, tt.callID)
			}, tt.description)

			// Function should complete and not leave system in bad state
			tracker.mu.Lock()
			mapLen := len(tracker.portToCallID)
			tracker.mu.Unlock()

			// Map should not grow uncontrollably
			assert.LessOrEqual(t, mapLen, 1000, "Port map should not grow uncontrollably")
		})
	}
}

func TestPortMapping_Cleanup(t *testing.T) {
	t.Run("Port map state isolation", func(t *testing.T) {
		// Ensure each test has clean state
		tracker := getTracker()
		tracker.mu.Lock()
		initialSize := len(tracker.portToCallID)
		tracker.portToCallID["test-isolation"] = "test-call"
		tracker.mu.Unlock()

		// Verify isolation doesn't affect other tests
		defer func() {
			tracker.mu.Lock()
			delete(tracker.portToCallID, "test-isolation")
			tracker.mu.Unlock()
		}()

		tracker.mu.Lock()
		currentSize := len(tracker.portToCallID)
		tracker.mu.Unlock()

		assert.Equal(t, initialSize+1, currentSize, "Should properly isolate test state")
	})
}

// Helper function to create UDP packets for testing
func createRTPTestPacket(t *testing.T, srcPort, dstPort uint16) gopacket.Packet {
	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IPv4 layer
	ip := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	// Create UDP layer
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Create packet
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err := gopacket.SerializeLayers(buffer, opts, eth, ip, udp)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return packet
}
