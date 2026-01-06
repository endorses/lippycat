package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	// Test extractRTPPortsFromSDP which now returns both IP:PORT and port-only entries
	tests := []struct {
		name     string
		sdp      string
		expected []string // Now includes both IP:PORT and port-only entries
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
			expected: []string{"192.168.1.1:16384", "16384"},
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
			expected: []string{"192.168.1.1:16384", "16384", "192.168.1.1:16386", "16386"},
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
			expected: []string{"192.168.1.1:16384", "16384"},
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
