package processor

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	cfg := DefaultConfig()
	p := New(cfg)
	require.NotNil(t, p)
	defer p.Close()

	assert.Equal(t, cfg.MaxCalls, p.config.MaxCalls)
	assert.Equal(t, cfg.CallTimeout, p.config.CallTimeout)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 10000, cfg.MaxCalls)
	assert.Equal(t, 30*time.Minute, cfg.CallTimeout)
	assert.Equal(t, 30*time.Second, cfg.MaxBufferAge)
	assert.Equal(t, 1000, cfg.MaxBufferSize)
}

func TestProcessor_ProcessNonVoIPPacket(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	// Create a non-UDP packet (TCP)
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload([]byte("GET / HTTP/1.1\r\n")))
	require.NoError(t, err)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	result := p.Process(packet)
	assert.Nil(t, result, "Non-VoIP packet should return nil")
}

func TestProcessor_ProcessSIPPacket(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	// Create a SIP INVITE packet
	sipPayload := []byte(`INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060
From: Alice <sip:alice@example.com>;tag=1234
To: Bob <sip:bob@example.com>
Call-ID: abc123@example.com
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 0

`)

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = udp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(sipPayload))
	require.NoError(t, err)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	result := p.Process(packet)

	require.NotNil(t, result, "SIP packet should be detected")
	assert.True(t, result.IsVoIP)
	assert.Equal(t, PacketTypeSIP, result.PacketType)
	assert.Equal(t, "abc123@example.com", result.CallID)
	assert.NotNil(t, result.Metadata)
	assert.NotNil(t, result.Metadata.Sip)
	assert.Equal(t, "abc123@example.com", result.Metadata.Sip.CallId)
	assert.Equal(t, "alice", result.Metadata.Sip.FromUser)
	assert.Equal(t, "bob", result.Metadata.Sip.ToUser)
	assert.Equal(t, "INVITE", result.Metadata.Sip.Method)
}

func TestProcessor_ProcessSIPWithSDP(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	// Create a SIP INVITE with SDP containing RTP port
	sipPayload := []byte(`INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060
From: Alice <sip:alice@example.com>;tag=1234
To: Bob <sip:bob@example.com>
Call-ID: def456@example.com
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 100

v=0
o=- 12345 12345 IN IP4 192.168.1.1
s=VoIP Call
c=IN IP4 192.168.1.1
t=0 0
m=audio 16384 RTP/AVP 0
`)

	packet := createUDPPacket(t, sipPayload, 5060, 5060)
	result := p.Process(packet)

	require.NotNil(t, result)
	assert.Equal(t, "def456@example.com", result.CallID)

	// Verify RTP port was registered
	callID, exists := p.getCallIDForPort("16384")
	assert.True(t, exists)
	assert.Equal(t, "def456@example.com", callID)
}

func TestProcessor_ProcessRTPPacket(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	// First, register an RTP port via SIP with proper SDP format
	sipPayload := []byte("INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.1:5060\r\n" +
		"From: Alice <sip:alice@example.com>;tag=1234\r\n" +
		"To: Bob <sip:bob@example.com>\r\n" +
		"Call-ID: rtp-test@example.com\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=- 12345 12345 IN IP4 192.168.1.1\r\n" +
		"s=VoIP Call\r\n" +
		"c=IN IP4 192.168.1.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 20000 RTP/AVP 0\r\n")

	sipPacket := createUDPPacket(t, sipPayload, 5060, 5060)
	sipResult := p.Process(sipPacket)
	require.NotNil(t, sipResult, "SIP packet should be processed")
	require.Equal(t, "rtp-test@example.com", sipResult.CallID)

	// Verify the port was registered
	callID, exists := p.getCallIDForPort("20000")
	require.True(t, exists, "RTP port 20000 should be registered")
	require.Equal(t, "rtp-test@example.com", callID)

	// Now create an RTP packet to the registered port
	rtpPayload := createRTPPayload(2, 0, 1, 12345, 0x12345678)
	rtpPacket := createUDPPacket(t, rtpPayload, 12345, 20000)
	result := p.Process(rtpPacket)

	require.NotNil(t, result, "RTP packet should be detected")
	assert.True(t, result.IsVoIP)
	assert.Equal(t, PacketTypeRTP, result.PacketType)
	assert.Equal(t, "rtp-test@example.com", result.CallID)
	assert.NotNil(t, result.Metadata)
	assert.NotNil(t, result.Metadata.Rtp)
	assert.Equal(t, uint32(0x12345678), result.Metadata.Rtp.Ssrc)
}

func TestProcessor_ActiveCalls(t *testing.T) {
	p := New(DefaultConfig())
	defer p.Close()

	// Create a few calls
	sipPayload1 := []byte(`INVITE sip:bob@example.com SIP/2.0
Call-ID: call1@example.com
From: Alice <sip:alice@example.com>
To: Bob <sip:bob@example.com>

`)
	sipPayload2 := []byte(`INVITE sip:carol@example.com SIP/2.0
Call-ID: call2@example.com
From: Dave <sip:dave@example.com>
To: Carol <sip:carol@example.com>

`)

	p.Process(createUDPPacket(t, sipPayload1, 5060, 5060))
	p.Process(createUDPPacket(t, sipPayload2, 5060, 5060))

	calls := p.ActiveCalls()
	assert.Len(t, calls, 2)

	// Verify call IDs are present
	callIDs := make(map[string]bool)
	for _, call := range calls {
		callIDs[call.CallID] = true
	}
	assert.True(t, callIDs["call1@example.com"])
	assert.True(t, callIDs["call2@example.com"])
}

func TestProcessor_CallEviction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCalls = 2
	p := New(cfg)
	defer p.Close()

	// Create 3 calls - the oldest should be evicted
	calls := []string{"call1@example.com", "call2@example.com", "call3@example.com"}
	for _, callID := range calls {
		sipPayload := []byte("INVITE sip:user@example.com SIP/2.0\r\nCall-ID: " + callID + "\r\n\r\n")
		p.Process(createUDPPacket(t, sipPayload, 5060, 5060))
	}

	activeCalls := p.ActiveCalls()
	assert.Len(t, activeCalls, 2, "Should only have 2 calls after eviction")
}

// Helper functions

func createUDPPacket(t *testing.T, payload []byte, srcPort, dstPort uint16) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = udp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	require.NoError(t, err)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func createRTPPayload(version, payloadType uint8, sequence uint16, timestamp, ssrc uint32) []byte {
	payload := make([]byte, 12)
	payload[0] = version << 6
	payload[1] = payloadType
	payload[2] = byte(sequence >> 8)
	payload[3] = byte(sequence)
	payload[4] = byte(timestamp >> 24)
	payload[5] = byte(timestamp >> 16)
	payload[6] = byte(timestamp >> 8)
	payload[7] = byte(timestamp)
	payload[8] = byte(ssrc >> 24)
	payload[9] = byte(ssrc >> 16)
	payload[10] = byte(ssrc >> 8)
	payload[11] = byte(ssrc)
	return payload
}
