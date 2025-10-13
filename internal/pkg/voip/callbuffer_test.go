package voip

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCallBuffer(t *testing.T) {
	callID := "test-call-123"
	buffer := NewCallBuffer(callID)

	assert.NotNil(t, buffer, "NewCallBuffer should return non-nil buffer")
	assert.Equal(t, callID, buffer.GetCallID(), "Call ID should match")
	assert.Equal(t, 0, buffer.GetPacketCount(), "Initial packet count should be 0")
	assert.False(t, buffer.IsFilterChecked(), "Filter should not be checked initially")
	assert.False(t, buffer.IsMatched(), "Buffer should not be matched initially")
	assert.Nil(t, buffer.GetMetadata(), "Metadata should be nil initially")
	assert.NotZero(t, buffer.createdAt, "Created time should be set")
}

func TestCallBuffer_AddSIPPacket(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Create test SIP packet
	packet := createTestBufferPacket(t, 5060, 5061, []byte("INVITE sip:bob@example.com SIP/2.0"))

	buffer.AddSIPPacket(packet)

	assert.Equal(t, 1, buffer.GetPacketCount(), "Should have 1 packet")
	packets := buffer.GetAllPackets()
	assert.Len(t, packets, 1, "GetAllPackets should return 1 packet")
}

func TestCallBuffer_AddRTPPacket(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Add RTP port first
	buffer.AddRTPPort("8000")

	// Create test RTP packet
	packet := createTestBufferPacket(t, 8000, 9000, []byte{0x80, 0x00, 0x00, 0x01})

	buffer.AddRTPPacket(packet)

	assert.Equal(t, 1, buffer.GetPacketCount(), "Should have 1 packet")
}

func TestCallBuffer_MultiplePackets(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Add SIP packets
	sipPacket1 := createTestBufferPacket(t, 5060, 5061, []byte("INVITE"))
	sipPacket2 := createTestBufferPacket(t, 5061, 5060, []byte("200 OK"))
	buffer.AddSIPPacket(sipPacket1)
	buffer.AddSIPPacket(sipPacket2)

	// Add RTP packets
	buffer.AddRTPPort("8000")
	rtpPacket1 := createTestBufferPacket(t, 8000, 9000, []byte{0x80, 0x00})
	rtpPacket2 := createTestBufferPacket(t, 8000, 9000, []byte{0x80, 0x01})
	buffer.AddRTPPacket(rtpPacket1)
	buffer.AddRTPPacket(rtpPacket2)

	assert.Equal(t, 4, buffer.GetPacketCount(), "Should have 4 packets total")

	packets := buffer.GetAllPackets()
	assert.Len(t, packets, 4, "GetAllPackets should return all 4 packets")
}

func TestCallBuffer_SetMetadata(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	metadata := &CallMetadata{
		CallID:            "test-call",
		From:              "alice@example.com",
		To:                "bob@example.com",
		PAssertedIdentity: "alice@provider.com",
		Method:            "INVITE",
		SDPBody:           "m=audio 8000 RTP/AVP 0",
	}

	buffer.SetMetadata(metadata)

	retrieved := buffer.GetMetadata()
	assert.NotNil(t, retrieved, "Metadata should not be nil")
	assert.Equal(t, "alice@example.com", retrieved.From)
	assert.Equal(t, "bob@example.com", retrieved.To)
	assert.Equal(t, "INVITE", retrieved.Method)
}

func TestCallBuffer_RTPPortManagement(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Add multiple RTP ports
	buffer.AddRTPPort("8000")
	buffer.AddRTPPort("8002")
	buffer.AddRTPPort("8004")

	assert.True(t, buffer.IsRTPPort("8000"), "Should recognize port 8000")
	assert.True(t, buffer.IsRTPPort("8002"), "Should recognize port 8002")
	assert.True(t, buffer.IsRTPPort("8004"), "Should recognize port 8004")
	assert.False(t, buffer.IsRTPPort("9000"), "Should not recognize untracked port")
}

func TestCallBuffer_FilterResult(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Initially not checked
	assert.False(t, buffer.IsFilterChecked(), "Filter should not be checked initially")
	assert.False(t, buffer.IsMatched(), "Should not be matched initially")

	// Set matched
	buffer.SetFilterResult(true)
	assert.True(t, buffer.IsFilterChecked(), "Filter should be checked")
	assert.True(t, buffer.IsMatched(), "Should be matched")

	// Set not matched
	buffer.SetFilterResult(false)
	assert.True(t, buffer.IsFilterChecked(), "Filter should still be checked")
	assert.False(t, buffer.IsMatched(), "Should not be matched")
}

func TestCallBuffer_GetAge(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Age should be very small initially
	age := buffer.GetAge()
	assert.Less(t, age, 100*time.Millisecond, "Initial age should be less than 100ms")

	// Wait a bit and check again
	time.Sleep(50 * time.Millisecond)
	age = buffer.GetAge()
	assert.GreaterOrEqual(t, age, 50*time.Millisecond, "Age should be at least 50ms")
}

func TestCallBuffer_DuplicateRTPPorts(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Add same port multiple times
	buffer.AddRTPPort("8000")
	buffer.AddRTPPort("8000")
	buffer.AddRTPPort("8000")

	// Should only be stored once (implementation may vary)
	assert.True(t, buffer.IsRTPPort("8000"), "Port should be recognized")
}

func TestCallBuffer_EmptyPackets(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	assert.Equal(t, 0, buffer.GetPacketCount(), "Empty buffer should have 0 packets")
	packets := buffer.GetAllPackets()
	assert.Empty(t, packets, "GetAllPackets should return empty slice")
}

func TestCallBuffer_LargeSDPBody(t *testing.T) {
	buffer := NewCallBuffer("test-call")

	// Create large SDP body with multiple audio streams
	largeSDPBody := `v=0
o=conference 123456 789012 IN IP4 10.0.0.1
s=Large Conference
c=IN IP4 10.0.0.1
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
m=audio 8002 RTP/AVP 0
a=rtpmap:0 PCMU/8000
m=audio 8004 RTP/AVP 8
a=rtpmap:8 PCMA/8000
m=audio 8006 RTP/AVP 0
a=rtpmap:0 PCMU/8000
m=video 9000 RTP/AVP 96
a=rtpmap:96 H264/90000`

	metadata := &CallMetadata{
		CallID:  "large-conf",
		From:    "admin@conf.com",
		To:      "participants@conf.com",
		Method:  "INVITE",
		SDPBody: largeSDPBody,
	}

	buffer.SetMetadata(metadata)

	retrieved := buffer.GetMetadata()
	assert.Equal(t, largeSDPBody, retrieved.SDPBody, "Large SDP body should be stored correctly")
}

// Helper function to create test packets for buffer tests
func createTestBufferPacket(t *testing.T, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
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
