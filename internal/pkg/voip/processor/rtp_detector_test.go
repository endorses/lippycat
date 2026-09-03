package processor

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidRTP(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "Valid RTP v2",
			payload:  []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Valid RTP with payload type",
			payload:  []byte{0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Invalid RTP v0",
			payload:  []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Invalid RTP v1",
			payload:  []byte{0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Invalid RTP v3",
			payload:  []byte{0xC0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Too short",
			payload:  []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Empty",
			payload:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidRTP(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetectRTPRefreshesCallActivity(t *testing.T) {
	p := New(Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(p.Close)
	p.AssociateEndpoint("active-call", "192.0.2.2:10000")

	stale := time.Now().Add(-time.Hour)
	p.mu.Lock()
	p.calls["active-call"].lastUpdated = stale
	p.calls["active-call"].info.LastUpdated = stale
	p.mu.Unlock()

	packet := createRTPPacket(t, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), 20000, 10000)
	require.NotNil(t, p.Process(packet))
	call, exists := p.Call("active-call")
	require.True(t, exists)
	require.True(t, call.LastUpdated.After(stale))
}

func TestDetectRTPAuthoritativeResolution(t *testing.T) {
	p := New(Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(p.Close)
	p.AssociateEndpoint("call-a", "192.0.2.1:20000")
	p.AssociateEndpoint("call-a", "192.0.2.2:10000")
	p.AssociateEndpoint("call-b", "192.0.2.2:10000")
	p.AssociateEndpoint("call-b", "192.0.2.3:30000")

	t.Run("intersection resolves one call", func(t *testing.T) {
		result := p.Process(createRTPPacket(t, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), 20000, 10000))
		require.NotNil(t, result)
		require.Equal(t, callregistry.MediaResolution{Status: callregistry.MediaResolved, CallID: "call-a"}, result.MediaResolution)
		require.Equal(t, "call-a", result.CallID)
		require.Equal(t, "call-a", result.Metadata.GetSip().GetCallId())
	})

	t.Run("shared endpoint is ambiguous", func(t *testing.T) {
		beforeA, ok := p.Call("call-a")
		require.True(t, ok)
		beforeB, ok := p.Call("call-b")
		require.True(t, ok)
		result := p.Process(createRTPPacket(t, net.ParseIP("192.0.2.99"), net.ParseIP("192.0.2.2"), 9999, 10000))
		require.NotNil(t, result)
		require.Equal(t, callregistry.MediaResolution{Status: callregistry.MediaAmbiguous}, result.MediaResolution)
		require.Empty(t, result.CallID)
		require.Nil(t, result.Metadata.GetSip())
		afterA, ok := p.Call("call-a")
		require.True(t, ok)
		afterB, ok := p.Call("call-b")
		require.True(t, ok)
		require.Equal(t, beforeA.LastUpdated, afterA.LastUpdated)
		require.Equal(t, beforeB.LastUpdated, afterB.LastUpdated)
	})

	t.Run("contradictory endpoints are unresolved", func(t *testing.T) {
		result := p.Process(createRTPPacket(t, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.3"), 20000, 30000))
		require.NotNil(t, result)
		require.Equal(t, callregistry.MediaResolution{Status: callregistry.MediaUnresolved}, result.MediaResolution)
		require.Empty(t, result.CallID)
	})
}

func createRTPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{Version: 4, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(createRTPPayload(2, 0, 1, 1, 1))))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestExtractRTPMetadata(t *testing.T) {
	// Create a valid RTP header:
	// Version: 2, PT: 8 (PCMA), Seq: 0x1234, Timestamp: 0xABCDEF01, SSRC: 0x12345678
	payload := []byte{
		0x80,       // V=2, P=0, X=0, CC=0
		0x08,       // M=0, PT=8
		0x12, 0x34, // Seq = 0x1234
		0xAB, 0xCD, 0xEF, 0x01, // Timestamp = 0xABCDEF01
		0x12, 0x34, 0x56, 0x78, // SSRC = 0x12345678
	}

	result := extractRTPMetadata(payload)

	assert.NotNil(t, result)
	assert.Equal(t, uint32(0x12345678), result.Ssrc)
	assert.Equal(t, uint32(8), result.PayloadType)
	assert.Equal(t, uint32(0x1234), result.Sequence)
	assert.Equal(t, uint32(0xABCDEF01), result.Timestamp)
}

func TestExtractRTPMetadata_TooShort(t *testing.T) {
	payload := []byte{0x80, 0x00, 0x00}
	result := extractRTPMetadata(payload)
	assert.Nil(t, result)
}

func TestExtractRTPPortsFromSDP(t *testing.T) {
	// extractRTPPortsFromSDP returns only IP:PORT entries — port-only matching
	// would mis-correlate RTP across unrelated calls when ports are reused.
	tests := []struct {
		name     string
		sdp      string
		expected []string
	}{
		{
			name: "Single audio stream",
			sdp: `v=0
o=- 12345 12345 IN IP4 192.168.1.1
s=VoIP Call
c=IN IP4 192.168.1.1
t=0 0
m=audio 16384 RTP/AVP 0 8
`,
			expected: []string{"192.168.1.1:16384"},
		},
		{
			name: "Multiple audio streams",
			sdp: `v=0
o=- 12345 12345 IN IP4 192.168.1.1
s=Conference
c=IN IP4 192.168.1.1
t=0 0
m=audio 16384 RTP/AVP 0
m=audio 16386 RTP/AVP 8
`,
			expected: []string{"192.168.1.1:16384", "192.168.1.1:16386"},
		},
		{
			name: "Video and audio",
			sdp: `v=0
o=- 12345 12345 IN IP4 192.168.1.1
s=Video Call
c=IN IP4 192.168.1.1
t=0 0
m=audio 16384 RTP/AVP 0
m=video 16386 RTP/AVP 96
`,
			expected: []string{"192.168.1.1:16384"},
		},
		{
			name:     "No media lines",
			sdp:      "v=0\r\no=- 12345 12345 IN IP4 192.168.1.1\r\n",
			expected: []string{},
		},
		{
			name:     "Empty SDP",
			sdp:      "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRTPPortsFromSDP(tt.sdp)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		name     string
		port     string
		expected bool
	}{
		{
			name:     "Valid port 1",
			port:     "1",
			expected: true,
		},
		{
			name:     "Valid port 80",
			port:     "80",
			expected: true,
		},
		{
			name:     "Valid port 5060",
			port:     "5060",
			expected: true,
		},
		{
			name:     "Valid port 65535",
			port:     "65535",
			expected: true,
		},
		{
			name:     "Invalid port 0",
			port:     "0",
			expected: false,
		},
		{
			name:     "Invalid port 65536",
			port:     "65536",
			expected: false,
		},
		{
			name:     "Invalid port negative",
			port:     "-1",
			expected: false,
		},
		{
			name:     "Invalid port non-numeric",
			port:     "abc",
			expected: false,
		},
		{
			name:     "Empty port",
			port:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPort(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}
