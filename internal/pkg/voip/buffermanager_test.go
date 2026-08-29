package voip

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferManagerTypedCallbackPreservesResultsAndRunsUnlocked(t *testing.T) {
	bm := NewBufferManager(time.Minute, 10)
	t.Cleanup(bm.Close)
	callID := "typed-buffer@example.com"
	packet := createUDPPacket(5060, 5060, []byte("SIP/2.0 180 Ringing\r\n"))
	result := pipeline.SIPResult{CallID: callID, Method: "INVITE"}
	metadata := &CallMetadata{CallID: callID, From: "alice", SDPBody: "m=audio 40000 RTP/AVP 0\r\n"}

	require.False(t, bm.AddSIPResult(callID, packet, result, metadata, "eth0", layers.LinkTypeEthernet))
	called := false
	require.True(t, bm.CheckFilterWithTypedCallback(callID, func(*CallMetadata) bool { return true },
		func(id string, sip []BufferedSIPPacket, rtp []gopacket.Packet, _ *CallMetadata, iface string, link layers.LinkType) {
			called = true
			require.True(t, bm.IsCallMatched(id), "callback must run after the manager lock is released")
			require.Len(t, sip, 1)
			require.Empty(t, rtp)
			require.Equal(t, result, sip[0].Result)
			require.Same(t, packet, sip[0].Packet)
			require.Equal(t, "eth0", iface)
			require.Equal(t, layers.LinkTypeEthernet, link)
		}))
	require.True(t, called)
}

func TestNewBufferManager(t *testing.T) {
	maxAge := 5 * time.Second
	maxSize := 200

	bm := NewBufferManager(maxAge, maxSize)
	defer bm.Close()

	assert.NotNil(t, bm, "NewBufferManager should return non-nil")
	assert.Equal(t, 0, bm.GetBufferCount(), "Initial buffer count should be 0")
}

func TestBufferManager_AddSIPPacket(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"
	packet := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
		Method: "INVITE",
	}

	bm.AddSIPPacket(callID, packet, metadata, "eth0", layers.LinkTypeEthernet)

	assert.Equal(t, 1, bm.GetBufferCount(), "Should have 1 buffer")
}

func TestBufferManager_AddRTPPacket(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// First add SIP packet to create buffer with RTP port
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		Method:  "INVITE",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Now add RTP packet
	rtpPacket := createTestUDPPacket(t, 8000, 9000, []byte{0x80, 0x00})
	shouldForward := bm.AddRTPPacket(callID, "8000", rtpPacket)

	assert.False(t, shouldForward, "Should not forward before filter check")
	assert.Equal(t, 1, bm.GetBufferCount(), "Should still have 1 buffer")
}

func TestBufferManager_CheckFilter_Matched(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		Method:  "INVITE",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Add RTP packets
	rtpPacket1 := createTestUDPPacket(t, 8000, 9000, []byte{0x80, 0x00})
	rtpPacket2 := createTestUDPPacket(t, 8000, 9000, []byte{0x80, 0x01})
	bm.AddRTPPacket(callID, "8000", rtpPacket1)
	bm.AddRTPPacket(callID, "8000", rtpPacket2)

	// Check filter - should match
	filterFunc := func(m *CallMetadata) bool {
		return m.From == "alicent@example.com"
	}

	matched, packets := bm.CheckFilter(callID, filterFunc)

	assert.True(t, matched, "Should match filter")
	assert.Len(t, packets, 3, "Should return all buffered packets (1 SIP + 2 RTP)")
	assert.True(t, bm.IsCallMatched(callID), "Call should be marked as matched")
}

func TestBufferManager_CheckFilter_NotMatched(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
		Method: "INVITE",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Check filter - should not match
	filterFunc := func(m *CallMetadata) bool {
		return m.From == "charlie@example.com"
	}

	matched, packets := bm.CheckFilter(callID, filterFunc)

	assert.False(t, matched, "Should not match filter")
	assert.Nil(t, packets, "Should not return packets")
	assert.Equal(t, 0, bm.GetBufferCount(), "Buffer should be discarded")
}

func TestBufferManager_CheckFilterWithCallback(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add packets
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		Method:  "INVITE",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	rtpPacket := createTestUDPPacket(t, 8000, 9000, []byte{0x80, 0x00})
	bm.AddRTPPacket(callID, "8000", rtpPacket)

	// Check filter with callback
	callbackCalled := false
	var receivedPackets []gopacket.Packet
	var receivedMetadata *CallMetadata

	filterFunc := func(m *CallMetadata) bool {
		return m.From == "alicent@example.com"
	}

	onMatch := func(cid string, packets []gopacket.Packet, meta *CallMetadata, interfaceName string, linkType layers.LinkType) {
		callbackCalled = true
		receivedPackets = packets
		receivedMetadata = meta
	}

	matched := bm.CheckFilterWithCallback(callID, filterFunc, onMatch)

	assert.True(t, matched, "Should match filter")
	assert.True(t, callbackCalled, "Callback should be called")
	assert.Len(t, receivedPackets, 2, "Should receive 2 packets")
	assert.Equal(t, "alicent@example.com", receivedMetadata.From)
}

func TestBufferManager_GetCallIDForRTPPort(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet with SDP
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Look up call ID by RTP port
	foundCallID, exists := bm.GetCallIDForRTPPort("8000")

	assert.True(t, exists, "Port should be found")
	assert.Equal(t, callID, foundCallID, "Should return correct call ID")

	// Try non-existent port
	_, exists = bm.GetCallIDForRTPPort("9999")
	assert.False(t, exists, "Non-existent port should not be found")
}

func TestBufferManager_MultipleCallBuffers(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	// Add buffers for 3 different calls
	for i := 0; i < 3; i++ {
		callID := "test-call-" + string(rune('A'+i))
		sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
		metadata := &CallMetadata{
			CallID: callID,
			From:   "user" + string(rune('A'+i)) + "@example.com",
			To:     "robb@example.com",
		}
		bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)
	}

	assert.Equal(t, 3, bm.GetBufferCount(), "Should have 3 buffers")
}

func TestBufferManager_DiscardBuffer(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add buffer
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	assert.Equal(t, 1, bm.GetBufferCount(), "Should have 1 buffer")

	// Discard buffer
	bm.DiscardBuffer(callID)

	assert.Equal(t, 0, bm.GetBufferCount(), "Buffer should be discarded")
}

func TestBufferManager_IsCallMatched(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add buffer
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Not matched yet
	assert.False(t, bm.IsCallMatched(callID), "Should not be matched initially")

	// Check filter
	filterFunc := func(m *CallMetadata) bool {
		return true
	}
	bm.CheckFilter(callID, filterFunc)

	// Now matched
	assert.True(t, bm.IsCallMatched(callID), "Should be matched after filter check")
}

func TestBufferManager_RTPAfterFilterMatch(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Check filter - matches
	filterFunc := func(m *CallMetadata) bool {
		return true
	}
	bm.CheckFilter(callID, filterFunc)

	// Add RTP packet after filter check
	rtpPacket := createTestUDPPacket(t, 8000, 9000, []byte{0x80, 0x00})
	shouldForward := bm.AddRTPPacket(callID, "8000", rtpPacket)

	assert.True(t, shouldForward, "Should forward immediately after filter match")
}

func TestBufferManager_JanitorCleanup(t *testing.T) {
	// Use very short maxAge for testing
	bm := NewBufferManager(100*time.Millisecond, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add buffer
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	assert.Equal(t, 1, bm.GetBufferCount(), "Should have 1 buffer")

	// Manually trigger cleanup after buffer is old enough
	time.Sleep(150 * time.Millisecond)
	bm.cleanupOldBuffers()

	assert.Equal(t, 0, bm.GetBufferCount(), "Old buffer should be cleaned up")
}

// TestBufferManager_MatchedCallsPersistAfterBufferCleanup verifies that matched calls
// remain accessible via IsCallMatched() even after their buffers are cleaned up.
// This is critical for BYE handling - BYE messages often arrive long after the
// INVITE buffer has been cleaned up.
func TestBufferManager_MatchedCallsPersistAfterBufferCleanup(t *testing.T) {
	// Use very short maxAge for buffer cleanup testing
	bm := NewBufferManager(100*time.Millisecond, 200)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
		Method: "INVITE",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Check filter - should match
	filterFunc := func(m *CallMetadata) bool {
		return m.From == "alicent@example.com"
	}
	matched, _ := bm.CheckFilter(callID, filterFunc)
	require.True(t, matched, "Should match filter")

	// Verify call is matched
	assert.True(t, bm.IsCallMatched(callID), "Call should be matched initially")

	// Wait for buffer to age out and trigger cleanup
	time.Sleep(150 * time.Millisecond)
	bm.cleanupOldBuffers()

	// Buffer should be gone
	assert.Equal(t, 0, bm.GetBufferCount(), "Buffer should be cleaned up")

	// But call should STILL be matched via matchedCalls map
	assert.True(t, bm.IsCallMatched(callID),
		"Call should remain matched after buffer cleanup (via matchedCalls)")
}

// TestBufferManager_MatchedCallsExpireAfterTTL verifies that matched calls
// are eventually removed after the TTL expires.
func TestBufferManager_MatchedCallsExpireAfterTTL(t *testing.T) {
	bm := NewBufferManager(100*time.Millisecond, 200)
	// Override TTL to very short value for testing
	bm.matchedTTL = 200 * time.Millisecond
	defer bm.Close()

	callID := "test-call-123"

	// Add and match a call
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID: callID,
		From:   "alicent@example.com",
		To:     "robb@example.com",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	filterFunc := func(m *CallMetadata) bool { return true }
	bm.CheckFilter(callID, filterFunc)

	assert.True(t, bm.IsCallMatched(callID), "Call should be matched")

	// Wait for matchedTTL to expire
	time.Sleep(250 * time.Millisecond)
	bm.cleanupOldBuffers()

	// Call should no longer be matched
	assert.False(t, bm.IsCallMatched(callID),
		"Call should be removed after matchedTTL expires")
}

func TestBufferManager_CleanupOversizedBuffer(t *testing.T) {
	// Use small maxSize for testing
	bm := NewBufferManager(5*time.Second, 3)
	defer bm.Close()

	callID := "test-call-123"

	// Add SIP packet
	sipPacket := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
	metadata := &CallMetadata{
		CallID:  callID,
		From:    "alicent@example.com",
		To:      "robb@example.com",
		SDPBody: "m=audio 8000 RTP/AVP 0",
	}
	bm.AddSIPPacket(callID, sipPacket, metadata, "eth0", layers.LinkTypeEthernet)

	// Add more packets than maxSize
	for i := 0; i < 5; i++ {
		rtpPacket := createTestUDPPacket(t, 8000, 9000, []byte{0x80, byte(i)})
		bm.AddRTPPacket(callID, "8000", rtpPacket)
	}

	// Trigger cleanup
	bm.cleanupOldBuffers()

	// Buffer should be removed due to size
	assert.Equal(t, 0, bm.GetBufferCount(), "Oversized buffer should be cleaned up")
}

func TestBufferManager_CloseIdempotent(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)

	// Close multiple times should not panic
	assert.NotPanics(t, func() {
		bm.Close()
		bm.Close()
		bm.Close()
	}, "Close should be idempotent")
}

func TestExtractRTPPortsFromSDP(t *testing.T) {
	tests := []struct {
		name     string
		sdpBody  string
		expected []string
	}{
		{
			name:     "Single audio stream",
			sdpBody:  "v=0\nm=audio 8000 RTP/AVP 0\na=rtpmap:0 PCMU/8000",
			expected: []string{"8000"},
		},
		{
			name: "Multiple audio streams",
			sdpBody: `v=0
m=audio 8000 RTP/AVP 0
m=audio 8002 RTP/AVP 0`,
			expected: []string{"8000", "8002"},
		},
		{
			name: "Audio and video",
			sdpBody: `v=0
m=audio 49170 RTP/AVP 0
m=video 51372 RTP/AVP 31`,
			expected: []string{"49170"},
		},
		{
			name:     "No audio",
			sdpBody:  "v=0\nm=video 9000 RTP/AVP 96",
			expected: []string{},
		},
		{
			name:     "Invalid port",
			sdpBody:  "m=audio 99999 RTP/AVP 0",
			expected: []string{},
		},
		{
			name:     "Port 0 (inactive)",
			sdpBody:  "m=audio 0 RTP/AVP 0",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRTPPortsFromSDP(tt.sdpBody)
			assert.Equal(t, tt.expected, result, "Extracted ports should match")
		})
	}
}

func TestBufferManager_ConcurrentAccess(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 200)
	defer bm.Close()

	// Test concurrent writes and reads
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			callID := "call-" + string(rune('A'+i))
			packet := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
			metadata := &CallMetadata{
				CallID: callID,
				From:   "user@example.com",
				To:     "robb@example.com",
			}
			bm.AddSIPPacket(callID, packet, metadata, "eth0", layers.LinkTypeEthernet)
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 10; i++ {
			bm.GetBufferCount()
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Should not panic or deadlock
	assert.True(t, true, "Concurrent access completed successfully")
}

func TestBufferManagerConcurrentSIPAndRTP(t *testing.T) {
	bm := NewBufferManager(5*time.Second, 10000)
	defer bm.Close()

	const callCount = 25
	const packetsPerCall = 40

	var wg sync.WaitGroup
	for i := 0; i < callCount; i++ {
		i := i
		callID := fmt.Sprintf("call-%d", i)
		rtpPort := fmt.Sprintf("%d", 10000+i)

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < packetsPerCall; j++ {
				packet := createTestUDPPacket(t, 5060, 5061, []byte("INVITE"))
				metadata := &CallMetadata{
					CallID:  callID,
					From:    "alicent@example.com",
					To:      "robb@example.com",
					Method:  "INVITE",
					SDPBody: "m=audio " + rtpPort + " RTP/AVP 0",
				}
				bm.AddSIPPacket(callID, packet, metadata, "eth0", layers.LinkTypeEthernet)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < packetsPerCall; j++ {
				packet := createTestUDPPacket(t, uint16(10000+i), 9000, []byte{0x80, byte(j)})
				_ = bm.AddRTPPacket(callID, rtpPort, packet)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < packetsPerCall; j++ {
				_, _ = bm.GetCallIDForRTPPort(rtpPort)
				_ = bm.IsCallMatched(callID)
			}
		}()
	}

	wg.Wait()

	assert.LessOrEqual(t, bm.GetBufferCount(), callCount)
}

// Helper function to create test UDP packets
func createTestUDPPacket(t *testing.T, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
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

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err, "Failed to create test packet")

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}
