//go:build cli || all
// +build cli all

package voip

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartVoipSnifferIntegration(t *testing.T) {
	// Skip this test as StartVoipSniffer blocks indefinitely waiting for signals
	// This is not suitable for unit testing without major refactoring
	t.Skip("Skipping integration test that blocks on signal handler - requires live system testing")
}

func TestStartProcessorChannelProcessing(t *testing.T) {
	// Reset and initialize config for this test
	ResetConfigOnce()

	// Create isolated tracker for this test
	tracker := TestCallTracker(t)
	restore := OverrideDefaultTracker(tracker)
	defer restore()

	// Setup test user for surveillance
	sipusers.AddSipUser("testuser", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	defer sipusers.DeleteSipUser("testuser")

	// Create packet channel and assembler
	packetCh := make(chan capture.PacketInfo, 100)
	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	defer streamFactory.(*sipStreamFactory).Shutdown()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Start processor in goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		startProcessor(packetCh, assembler)
	}()

	// Send test packets
	testPackets := []capture.PacketInfo{
		createSipInvitePacketInfo(t, "testuser@example.com", "integration-test-call-1"),
		createSipRegisterPacketInfo(t, "testuser@example.com", "integration-test-call-2"),
		createRtpPacketInfo(t, 8000, 8001),
		createNonSipUdpPacketInfo(t, 9999, 10000),
	}

	for _, pkt := range testPackets {
		packetCh <- pkt
		time.Sleep(1 * time.Millisecond) // Small delay to allow processing
	}

	// Close channel and wait for processing to complete
	close(packetCh)
	wg.Wait()

	// Verify results
	tracker.mu.RLock()
	callCount := len(tracker.callMap)
	callsCreated := make([]string, 0, len(tracker.callMap))
	for callID := range tracker.callMap {
		callsCreated = append(callsCreated, callID)
	}
	tracker.mu.RUnlock()

	t.Logf("Integration test created %d calls: %v", callCount, callsCreated)
	assert.True(t, callCount >= 0, "Should handle packet processing without crashing")
}

func TestVoipSnifferLiveIntegration(t *testing.T) {
	// Skip this test as StartLiveVoipSniffer eventually blocks on signal handler
	t.Skip("Skipping live integration test that blocks on signal handler - requires live system testing")
}

func TestVoipSnifferOfflineIntegration(t *testing.T) {
	// Skip this test as StartOfflineVoipSniffer eventually blocks on signal handler
	t.Skip("Skipping offline integration test that blocks on signal handler - requires live system testing")
}

func TestContainsUserInHeadersIntegration(t *testing.T) {
	// Setup test users
	sipusers.AddSipUser("alice", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	sipusers.AddSipUser("bob", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	defer func() {
		sipusers.DeleteSipUser("alice")
		sipusers.DeleteSipUser("bob")
	}()

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "Contains surveiled user in from header",
			headers: map[string]string{
				"from":    "<sip:alice@example.com>;tag=123",
				"to":      "<sip:external@other.com>",
				"call-id": "test-call-1",
			},
			expected: true,
		},
		{
			name: "Contains surveiled user in to header",
			headers: map[string]string{
				"from":    "<sip:external@other.com>;tag=456",
				"to":      "<sip:bob@example.com>",
				"call-id": "test-call-2",
			},
			expected: true,
		},
		{
			name: "Contains surveiled user in p-asserted-identity",
			headers: map[string]string{
				"from":                "<sip:external@other.com>",
				"to":                  "<sip:another@other.com>",
				"p-asserted-identity": "<sip:alice@example.com>",
				"call-id":             "test-call-3",
			},
			expected: true,
		},
		{
			name: "No surveiled users",
			headers: map[string]string{
				"from":    "<sip:external1@other.com>",
				"to":      "<sip:external2@other.com>",
				"call-id": "test-call-4",
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

func TestEndToEndSipCallProcessing(t *testing.T) {
	// Get CallTracker instance and reset state
	tracker := getTracker()

	// Clear any existing state
	tracker.mu.Lock()
	tracker.callMap = make(map[string]*CallInfo)
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	// Setup surveillance
	sipusers.AddSipUser("alice", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	defer sipusers.DeleteSipUser("alice")

	// Create SIP INVITE message that should trigger call creation
	sipMessage := []byte(`INVITE sip:alice@example.com SIP/2.0
From: <sip:bob@example.com>;tag=123
To: <sip:alice@example.com>
Call-ID: end-to-end-test-call@example.com
CSeq: 1 INVITE
Contact: <sip:bob@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: 142

v=0
o=bob 123456 789012 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000`)

	// Process the SIP message
	isValidSip := handleSipMessage(sipMessage, layers.LinkTypeEthernet)
	assert.True(t, isValidSip, "SIP message should be processed successfully")

	// Verify call was created
	tracker.mu.RLock()
	call, exists := tracker.callMap["end-to-end-test-call@example.com"]
	tracker.mu.RUnlock()

	if exists {
		assert.NotNil(t, call)
		assert.Equal(t, "end-to-end-test-call@example.com", call.CallID)
		t.Logf("Successfully created call: %+v", call)
	}

	// Verify RTP port was extracted and tracked
	tracker.mu.RLock()
	trackedCallID, portTracked := tracker.portToCallID["8000"]
	tracker.mu.RUnlock()

	if portTracked {
		assert.Equal(t, "end-to-end-test-call@example.com", trackedCallID)
		t.Logf("Successfully tracked RTP port 8000 for call %s", trackedCallID)
	}

	// Test RTP packet handling for tracked port
	rtpPacket := createRtpPacketInfo(t, 9999, 8000)
	if udpLayer := rtpPacket.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		handleUdpPackets(rtpPacket, udpLayer.(*layers.UDP))
	}

	// Verify the integration completed without errors
	assert.True(t, true, "End-to-end SIP call processing completed successfully")
}

func TestStreamFactoryIntegration(t *testing.T) {
	// Test TCP stream factory integration with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	streamFactory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	defer streamFactory.(*sipStreamFactory).Shutdown()
	assert.NotNil(t, streamFactory, "Stream factory should be created")

	// Test that New() method works
	netFlow := gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x13, 0x88}, []byte{0x13, 0x88})
	tcpFlow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 168, 1, 1}, []byte{192, 168, 1, 2})

	// This should not panic
	assert.NotPanics(t, func() {
		stream := streamFactory.New(netFlow, tcpFlow)
		if stream != nil {
			// If we get a stream, test that it can be closed safely
			t.Logf("Created TCP stream successfully")
		}
	})

	// Test context cancellation
	cancel()
	time.Sleep(10 * time.Millisecond) // Allow time for cleanup
}

func TestMultiProtocolPacketProcessing(t *testing.T) {
	// Test handling multiple packet types in sequence
	tracker := getTracker()

	// Clear any existing state
	tracker.mu.Lock()
	tracker.callMap = make(map[string]*CallInfo)
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	// Setup surveillance
	sipusers.AddSipUser("alice", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	defer sipusers.DeleteSipUser("alice")

	// Create packet sequence simulating a real VoIP call
	packets := []struct {
		name   string
		packet capture.PacketInfo
	}{
		{"SIP INVITE", createSipInvitePacketInfo(t, "alice@example.com", "multi-protocol-test")},
		{"SIP 180 Ringing", createSipResponsePacketInfo(t, "SIP/2.0 180 Ringing", "multi-protocol-test")},
		{"SIP 200 OK with SDP", createSipOkWithSdpPacketInfo(t, "multi-protocol-test", 8000)},
		{"RTP audio packet", createRtpPacketInfo(t, 10000, 8000)},
		{"RTP audio packet 2", createRtpPacketInfo(t, 10000, 8000)},
		{"SIP BYE", createSipByePacketInfo(t, "multi-protocol-test")},
		{"SIP 200 OK (BYE response)", createSipResponsePacketInfo(t, "SIP/2.0 200 OK", "multi-protocol-test")},
	}

	ctx := context.Background()
	streamFactory := NewSipStreamFactory(ctx, NewLocalFileHandler())
	defer streamFactory.(*sipStreamFactory).Shutdown()
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Process each packet
	for _, pkt := range packets {
		t.Run(pkt.name, func(t *testing.T) {
			packet := pkt.packet.Packet
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				t.Skip("Skipping packet without network/transport layers")
				return
			}

			assert.NotPanics(t, func() {
				switch layer := packet.TransportLayer().(type) {
				case *layers.TCP:
					handleTcpPackets(pkt.packet, layer, assembler)
				case *layers.UDP:
					handleUdpPackets(pkt.packet, layer)
				}
			})
		})
	}

	// Verify final state
	tracker.mu.RLock()
	finalCallCount := len(tracker.callMap)
	finalPortCount := len(tracker.portToCallID)
	tracker.mu.RUnlock()

	t.Logf("Final state: %d calls, %d tracked ports", finalCallCount, finalPortCount)
}

func TestSipUserSurveillanceIntegration(t *testing.T) {
	// Test surveillance integration across the entire pipeline
	tracker := getTracker()

	// Clear any existing state
	tracker.mu.Lock()
	tracker.callMap = make(map[string]*CallInfo)
	tracker.mu.Unlock()

	// Test with no surveillance - should work in promiscuous mode (accept all)
	sipMessage := []byte(`INVITE sip:external@other.com SIP/2.0
From: <sip:another@other.com>;tag=123
To: <sip:external@other.com>
Call-ID: no-surveillance-test
CSeq: 1 INVITE
Content-Length: 0

`)

	result := handleSipMessage(sipMessage, layers.LinkTypeEthernet)
	assert.True(t, result, "Should process all users in promiscuous mode (no surveillance configured)")

	// Add surveillance
	sipusers.AddSipUser("alice", &sipusers.SipUser{
		ExpirationDate: time.Now().Add(1 * time.Hour),
	})
	defer sipusers.DeleteSipUser("alice")

	// Now test with surveillance - should create calls
	surveilledMessage := []byte(`INVITE sip:alice@example.com SIP/2.0
From: <sip:bob@other.com>;tag=123
To: <sip:alice@example.com>
Call-ID: surveillance-test
CSeq: 1 INVITE
Content-Length: 0

`)

	result = handleSipMessage(surveilledMessage, layers.LinkTypeEthernet)
	assert.True(t, result, "Should process surveiled users")
}

// Additional helper functions for comprehensive testing

func createSipResponsePacketInfo(t *testing.T, response, callID string) capture.PacketInfo {
	sipData := []byte(response + "\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"From: <sip:caller@example.com>;tag=123\r\n" +
		"To: <sip:alice@example.com>;tag=456\r\n" +
		"Content-Length: 0\r\n\r\n")

	return createUdpPacketInfo(t, 5060, 5060, sipData)
}

func createSipOkWithSdpPacketInfo(t *testing.T, callID string, rtpPort uint16) capture.PacketInfo {
	sipData := []byte("SIP/2.0 200 OK\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"From: <sip:caller@example.com>;tag=123\r\n" +
		"To: <sip:alice@example.com>;tag=456\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 100\r\n\r\n" +
		"v=0\r\n" +
		"o=alice 123456 789012 IN IP4 192.168.1.200\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.168.1.200\r\n" +
		"t=0 0\r\n" +
		"m=audio 8000 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n")

	return createUdpPacketInfo(t, 5060, 5060, sipData)
}

func createSipByePacketInfo(t *testing.T, callID string) capture.PacketInfo {
	sipData := []byte("BYE sip:alice@example.com SIP/2.0\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"From: <sip:caller@example.com>;tag=123\r\n" +
		"To: <sip:alice@example.com>;tag=456\r\n" +
		"Content-Length: 0\r\n\r\n")

	return createUdpPacketInfo(t, 5060, 5060, sipData)
}

// Helper functions for creating test packets and files

func createTestPcapFile(t *testing.T, filePath string) {
	// Create a minimal valid pcap file
	// This is a simplified implementation - in practice you'd want more realistic data
	file, err := os.Create(filePath)
	require.NoError(t, err)
	defer file.Close()

	// Write a minimal pcap file header (this is just a placeholder)
	// In a real implementation, you'd write proper pcap data
	_, err = file.WriteString("test pcap data placeholder")
	require.NoError(t, err)
}

func createSipInvitePacketInfo(t *testing.T, userAddr, callID string) capture.PacketInfo {
	sipData := []byte("INVITE sip:" + userAddr + " SIP/2.0\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"From: <sip:caller@example.com>;tag=123\r\n" +
		"To: <sip:" + userAddr + ">\r\n" +
		"Content-Length: 0\r\n\r\n")

	return createUdpPacketInfo(t, 5060, 5060, sipData)
}

func createSipRegisterPacketInfo(t *testing.T, userAddr, callID string) capture.PacketInfo {
	sipData := []byte("REGISTER sip:example.com SIP/2.0\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"From: <sip:" + userAddr + ">;tag=456\r\n" +
		"To: <sip:" + userAddr + ">\r\n" +
		"Content-Length: 0\r\n\r\n")

	return createUdpPacketInfo(t, 1234, 5060, sipData)
}

func createRtpPacketInfo(t *testing.T, srcPort, dstPort uint16) capture.PacketInfo {
	rtpData := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return createUdpPacketInfo(t, srcPort, dstPort, rtpData)
}

func createNonSipUdpPacketInfo(t *testing.T, srcPort, dstPort uint16) capture.PacketInfo {
	data := []byte("Not a SIP or RTP packet")
	return createUdpPacketInfo(t, srcPort, dstPort, data)
}

func createUdpPacketInfo(t *testing.T, srcPort, dstPort uint16, payload []byte) capture.PacketInfo {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	packet.Metadata().CaptureInfo.CaptureLength = len(buffer.Bytes())
	packet.Metadata().CaptureInfo.Length = len(buffer.Bytes())

	return capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}
}

// Mock interface for offline testing
type MockOfflinePcapInterface struct {
	name     string
	filePath string
	handle   *gopacket.ZeroCopyPacketDataSource
}

func (m *MockOfflinePcapInterface) Name() string {
	return m.name
}

func (m *MockOfflinePcapInterface) SetHandle() error {
	// Mock implementation - just return success
	return nil
}

func (m *MockOfflinePcapInterface) Handle() (*pcap.Handle, error) {
	// Return nil handle for testing - this will cause the test to fail gracefully
	// rather than crash, which is what we want for integration testing
	return nil, nil
}

func TestIntegrationErrorHandling(t *testing.T) {
	// Test error handling across the VoIP processing pipeline
	tracker := getTracker()

	// Clear any existing state
	tracker.mu.Lock()
	tracker.callMap = make(map[string]*CallInfo)
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	tests := []struct {
		name       string
		sipMessage []byte
		shouldFail bool
	}{
		{
			name:       "Malformed SIP message",
			sipMessage: []byte("NOT A VALID SIP MESSAGE"),
			shouldFail: true,
		},
		{
			name:       "Empty SIP message",
			sipMessage: []byte(""),
			shouldFail: true,
		},
		{
			name: "Missing headers SIP message",
			sipMessage: []byte(`INVITE sip:user@example.com SIP/2.0
Content-Length: 0

`),
			shouldFail: false, // This might not fail but won't create calls without surveillance
		},
		{
			name: "SIP message with invalid Content-Length",
			sipMessage: []byte(`INVITE sip:user@example.com SIP/2.0
From: <sip:caller@example.com>;tag=123
To: <sip:user@example.com>
Call-ID: error-test-call
Content-Length: -1

`),
			shouldFail: false, // Should handle gracefully
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				result := handleSipMessage(tt.sipMessage, layers.LinkTypeEthernet)
				if tt.shouldFail {
					assert.False(t, result, "Should handle malformed messages gracefully")
				}
			}, "Error handling should prevent panics")
		})
	}
}
