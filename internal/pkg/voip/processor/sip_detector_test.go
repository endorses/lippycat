package processor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSIPMessage(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected bool
	}{
		{
			name:     "SIP INVITE request",
			payload:  []byte("INVITE sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP BYE request",
			payload:  []byte("BYE sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP ACK request",
			payload:  []byte("ACK sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP OPTIONS request",
			payload:  []byte("OPTIONS sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP REGISTER request",
			payload:  []byte("REGISTER sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP CANCEL request",
			payload:  []byte("CANCEL sip:bob@example.com SIP/2.0\r\n"),
			expected: true,
		},
		{
			name:     "SIP response 200 OK",
			payload:  []byte("SIP/2.0 200 OK\r\n"),
			expected: true,
		},
		{
			name:     "SIP response 180 Ringing",
			payload:  []byte("SIP/2.0 180 Ringing\r\n"),
			expected: true,
		},
		{
			name:     "HTTP request",
			payload:  []byte("GET / HTTP/1.1\r\n"),
			expected: false,
		},
		{
			name:     "Empty payload",
			payload:  []byte{},
			expected: false,
		},
		{
			name:     "Short payload",
			payload:  []byte("SIP"),
			expected: false,
		},
		{
			name:     "Random data",
			payload:  []byte("This is not a SIP message"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSIPMessage(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSIPHeaders(t *testing.T) {
	payload := []byte(`INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060
From: Alice <sip:alice@example.com>;tag=1234
To: Bob <sip:bob@example.com>
Call-ID: abc123@example.com
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 50

v=0
o=- 12345 12345 IN IP4 192.168.1.1
`)

	headers, body := parseSIPHeaders(payload)

	assert.Equal(t, "abc123@example.com", headers["call-id"])
	assert.Contains(t, headers["from"], "alice@example.com")
	assert.Contains(t, headers["to"], "bob@example.com")
	assert.Equal(t, "1 INVITE", headers["cseq"])
	assert.Contains(t, body, "v=0")
}

func TestParseSIPHeaders_CompactForm(t *testing.T) {
	payload := []byte(`INVITE sip:bob@example.com SIP/2.0
v: SIP/2.0/UDP 192.168.1.1:5060
f: Alice <sip:alice@example.com>;tag=1234
t: Bob <sip:bob@example.com>
i: abc123@example.com
l: 0

`)

	headers, _ := parseSIPHeaders(payload)

	assert.Equal(t, "abc123@example.com", headers["call-id"])
	assert.Contains(t, headers["from"], "alice@example.com")
	assert.Contains(t, headers["to"], "bob@example.com")
}

func TestDetectSIPMethod(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{
			name:     "INVITE",
			payload:  []byte("INVITE sip:bob@example.com SIP/2.0\r\n"),
			expected: "INVITE",
		},
		{
			name:     "BYE",
			payload:  []byte("BYE sip:bob@example.com SIP/2.0\r\n"),
			expected: "BYE",
		},
		{
			name:     "ACK",
			payload:  []byte("ACK sip:bob@example.com SIP/2.0\r\n"),
			expected: "ACK",
		},
		{
			name:     "CANCEL",
			payload:  []byte("CANCEL sip:bob@example.com SIP/2.0\r\n"),
			expected: "CANCEL",
		},
		{
			name:     "Response",
			payload:  []byte("SIP/2.0 200 OK\r\n"),
			expected: "RESPONSE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSIPMethod(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractSIPResponseCode(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected uint32
	}{
		{
			name:     "200 OK",
			payload:  []byte("SIP/2.0 200 OK\r\n"),
			expected: 200,
		},
		{
			name:     "180 Ringing",
			payload:  []byte("SIP/2.0 180 Ringing\r\n"),
			expected: 180,
		},
		{
			name:     "404 Not Found",
			payload:  []byte("SIP/2.0 404 Not Found\r\n"),
			expected: 404,
		},
		{
			name:     "486 Busy Here",
			payload:  []byte("SIP/2.0 486 Busy Here\r\n"),
			expected: 486,
		},
		{
			name:     "Request (not response)",
			payload:  []byte("INVITE sip:bob@example.com SIP/2.0\r\n"),
			expected: 0,
		},
		{
			name:     "Invalid response",
			payload:  []byte("SIP/2.0 XXX Invalid\r\n"),
			expected: 0,
		},
		{
			name:     "Short payload",
			payload:  []byte("SIP/2.0"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSIPResponseCode(tt.payload)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractUserFromSIPURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "Full URI with display name",
			uri:      "Alice <sip:alice@example.com>;tag=1234",
			expected: "alice",
		},
		{
			name:     "URI without display name",
			uri:      "sip:bob@example.com",
			expected: "bob",
		},
		{
			name:     "Phone number URI",
			uri:      "sip:+49123456789@carrier.com",
			expected: "+49123456789",
		},
		{
			name:     "SIPS URI",
			uri:      "sips:secure@example.com",
			expected: "secure",
		},
		{
			name:     "Empty URI",
			uri:      "",
			expected: "",
		},
		{
			name:     "No sip: prefix",
			uri:      "alice@example.com",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractUserFromSIPURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractFullSIPURI(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "URI in angle brackets",
			header:   "Alice <sip:alice@example.com>;tag=1234",
			expected: "sip:alice@example.com",
		},
		{
			name:     "URI without brackets",
			header:   "sip:bob@example.com",
			expected: "sip:bob@example.com",
		},
		{
			name:     "URI with parameters",
			header:   "sip:bob@example.com;transport=tcp",
			expected: "sip:bob@example.com",
		},
		{
			name:     "Empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractFullSIPURI(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractTagFromHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "Tag present",
			header:   "Alice <sip:alice@example.com>;tag=abc123",
			expected: "abc123",
		},
		{
			name:     "Tag with other params",
			header:   "Alice <sip:alice@example.com>;tag=xyz789;other=param",
			expected: "xyz789",
		},
		{
			name:     "No tag",
			header:   "Alice <sip:alice@example.com>",
			expected: "",
		},
		{
			name:     "Empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTagFromHeader(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateCallID(t *testing.T) {
	tests := []struct {
		name    string
		callID  string
		wantErr bool
	}{
		{
			name:    "Valid Call-ID",
			callID:  "abc123@example.com",
			wantErr: false,
		},
		{
			name:    "Valid UUID format",
			callID:  "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "Too long",
			callID:  string(make([]byte, 2000)),
			wantErr: true,
		},
		{
			name:    "Contains null byte",
			callID:  "abc\x00123",
			wantErr: true,
		},
		{
			name:    "Contains newline",
			callID:  "abc\n123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCallID(tt.callID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNormalizeHeaderName(t *testing.T) {
	tests := []struct {
		compact  string
		expected string
	}{
		{"i", "call-id"},
		{"f", "from"},
		{"t", "to"},
		{"v", "via"},
		{"c", "contact"},
		{"l", "content-length"},
		{"call-id", "call-id"}, // Not a compact form
		{"from", "from"},
	}

	for _, tt := range tests {
		t.Run(tt.compact, func(t *testing.T) {
			result := normalizeHeaderName(tt.compact)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name           string
		header         string
		wantAccessType string
		wantBSSID      string
		wantCellID     string
		wantLocalIP    string
		wantParams     map[string]string
	}{
		{
			name:           "WiFi with BSSID",
			header:         "IEEE-802.11; i-wlan-node-id=00:11:22:33:44:55",
			wantAccessType: "IEEE-802.11",
			wantBSSID:      "00:11:22:33:44:55",
			wantCellID:     "",
			wantLocalIP:    "",
			wantParams:     map[string]string{"i-wlan-node-id": "00:11:22:33:44:55"},
		},
		{
			name:           "LTE with CGI",
			header:         "3GPP-E-UTRAN-FDD; cgi-3gpp=234150012345678901234",
			wantAccessType: "3GPP-E-UTRAN-FDD",
			wantBSSID:      "",
			wantCellID:     "234150012345678901234",
			wantLocalIP:    "",
			wantParams:     map[string]string{"cgi-3gpp": "234150012345678901234"},
		},
		{
			name:           "5G NR with NCGI",
			header:         "3GPP-NR; ncgi=234150123456789",
			wantAccessType: "3GPP-NR",
			wantBSSID:      "",
			wantCellID:     "234150123456789",
			wantLocalIP:    "",
			wantParams:     map[string]string{"ncgi": "234150123456789"},
		},
		{
			name:           "GERAN with local IP",
			header:         "3GPP-GERAN; cgi-3gpp=234150012345; local-ip=10.0.0.1",
			wantAccessType: "3GPP-GERAN",
			wantBSSID:      "",
			wantCellID:     "234150012345",
			wantLocalIP:    "10.0.0.1",
			wantParams: map[string]string{
				"cgi-3gpp": "234150012345",
				"local-ip": "10.0.0.1",
			},
		},
		{
			name:           "WiFi with quoted BSSID",
			header:         `IEEE-802.11; i-wlan-node-id="AA:BB:CC:DD:EE:FF"`,
			wantAccessType: "IEEE-802.11",
			wantBSSID:      "AA:BB:CC:DD:EE:FF",
			wantCellID:     "",
			wantLocalIP:    "",
			wantParams:     map[string]string{"i-wlan-node-id": "AA:BB:CC:DD:EE:FF"},
		},
		{
			name:           "Access type only",
			header:         "IEEE-802.11",
			wantAccessType: "IEEE-802.11",
			wantBSSID:      "",
			wantCellID:     "",
			wantLocalIP:    "",
			wantParams:     map[string]string{},
		},
		{
			name:           "Empty header",
			header:         "",
			wantAccessType: "",
			wantBSSID:      "",
			wantCellID:     "",
			wantLocalIP:    "",
			wantParams:     nil,
		},
		{
			name:           "UTRAN cell ID",
			header:         "3GPP-UTRAN; utran-cell-id-3gpp=234150012345678",
			wantAccessType: "3GPP-UTRAN",
			wantBSSID:      "",
			wantCellID:     "234150012345678",
			wantLocalIP:    "",
			wantParams:     map[string]string{"utran-cell-id-3gpp": "234150012345678"},
		},
		{
			name:           "ECGI format",
			header:         "3GPP-E-UTRAN; ecgi=234150012345",
			wantAccessType: "3GPP-E-UTRAN",
			wantBSSID:      "",
			wantCellID:     "234150012345",
			wantLocalIP:    "",
			wantParams:     map[string]string{"ecgi": "234150012345"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessType, bssid, cellID, localIP, params := parseAccessNetworkInfo(tt.header)
			assert.Equal(t, tt.wantAccessType, accessType)
			assert.Equal(t, tt.wantBSSID, bssid)
			assert.Equal(t, tt.wantCellID, cellID)
			assert.Equal(t, tt.wantLocalIP, localIP)
			assert.Equal(t, tt.wantParams, params)
		})
	}
}

func TestParseVisitedNetworkID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "Quoted network name",
			header:   `"Visited Network Name"`,
			expected: "Visited Network Name",
		},
		{
			name:     "Unquoted domain",
			header:   "visited.network.example.com",
			expected: "visited.network.example.com",
		},
		{
			name:     "With whitespace",
			header:   "  carrier.example.org  ",
			expected: "carrier.example.org",
		},
		{
			name:     "Empty",
			header:   "",
			expected: "",
		},
		{
			name:     "Whitespace only",
			header:   "   ",
			expected: "",
		},
		{
			name:     "Quoted with spaces",
			header:   `  "MNO Roaming Partner"  `,
			expected: "MNO Roaming Partner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVisitedNetworkID(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}
