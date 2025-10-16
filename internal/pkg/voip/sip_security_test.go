package voip

import (
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestSipParsing_SecurityVulnerabilities tests SIP parsing against various attack vectors
func TestSipParsing_SecurityVulnerabilities(t *testing.T) {
	// Setup test environment with surveilled user
	sipusers.DeleteMultipleSipUsers([]string{"alice", "testuser"})
	testUsers := map[string]*sipusers.SipUser{
		"alice": {ExpirationDate: time.Now().Add(1 * time.Hour)},
	}
	sipusers.AddMultipleSipUsers(testUsers)
	defer sipusers.DeleteMultipleSipUsers([]string{"alice"})

	tests := []struct {
		name           string
		sipMessage     string
		expectedResult bool
		description    string
	}{
		{
			name: "Header injection attack",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: normal-call-123
From: alice@example.com
To: victim@example.com
Malicious-Header: injected
X-Evil: ` + strings.Repeat("A", 10000) + `

m=audio 5004 RTP/AVP 0`,
			expectedResult: true, // Should be processed but safely
			description:    "Very long header values should not crash parser",
		},
		{
			name: "Missing colon in header",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-call-456
From alice@example.com
To: victim@example.com

m=audio 5004 RTP/AVP 0`,
			expectedResult: false, // Malformed From header is ignored, no surveilled user found
			description:    "Headers without colons should be ignored",
		},
		{
			name: "Empty header lines",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-call-789
From: alice@example.com

To: victim@example.com

m=audio 5004 RTP/AVP 0`,
			expectedResult: true,
			description:    "Multiple empty lines should not break parsing",
		},
		{
			name: "Unicode and special characters",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-call-unicode-123
From: alice@™£¥€øπ∫∆.com
To: victim@example.com
Subject: 测试消息 ñoño 🚀

m=audio 5004 RTP/AVP 0`,
			expectedResult: true,
			description:    "Unicode characters should be handled safely",
		},
		{
			name: "Null bytes in message",
			sipMessage: "INVITE sip:user@example.com SIP/2.0\x00\r\n" +
				"Call-ID: test-call-null-456\r\n" +
				"From: alice@example.com\x00\r\n" +
				"To: victim@example.com\r\n\r\n" +
				"m=audio 5004 RTP/AVP 0\x00",
			expectedResult: true,
			description:    "Null bytes should not crash parser",
		},
		{
			name: "Extremely long Call-ID",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: ` + strings.Repeat("very-long-call-id-", 1000) + `
From: alice@example.com
To: victim@example.com

m=audio 5004 RTP/AVP 0`,
			expectedResult: true,
			description:    "Very long Call-ID should be handled (but may be truncated)",
		},
		{
			name: "Missing body separator",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-no-separator
From: alice@example.com
To: victim@example.com
m=audio 5004 RTP/AVP 0`,
			expectedResult: true, // Should handle missing empty line separator
			description:    "Missing empty line between headers and body",
		},
		{
			name: "CRLF vs LF line endings",
			sipMessage: "INVITE sip:user@example.com SIP/2.0\r\n" +
				"Call-ID: test-crlf-123\r\n" +
				"From: alice@example.com\r\n" +
				"To: victim@example.com\r\n\r\n" +
				"m=audio 5004 RTP/AVP 0",
			expectedResult: true,
			description:    "Different line endings should be handled",
		},
		{
			name: "Malformed SDP in body",
			sipMessage: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-malformed-sdp-789
From: alice@example.com
To: victim@example.com

m=audio invalid_port RTP/AVP 0
c=IN IP4 malformed.ip.address
a=sendrecv malformed`,
			expectedResult: true,
			description:    "Malformed SDP should not crash the parser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test should not panic
			assert.NotPanics(t, func() {
				result := handleSipMessage([]byte(tt.sipMessage), layers.LinkTypeEthernet)
				assert.Equal(t, tt.expectedResult, result, tt.description)
			})
		})
	}
}

func TestParseSipHeaders_EdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedHeaders map[string]string
		expectedBody    string
		description     string
	}{
		{
			name: "Headers with no values",
			input: `INVITE sip:user@example.com SIP/2.0
Call-ID:
From:
To: user@example.com

body content`,
			expectedHeaders: map[string]string{
				"call-id": "",
				"from":    "",
				"to":      "user@example.com",
			},
			expectedBody: "body content\n",
			description:  "Empty header values should be preserved",
		},
		{
			name: "Headers with excessive whitespace",
			input: `INVITE sip:user@example.com SIP/2.0
Call-ID:        test-call-123
From:    alice@example.com
To:user@example.com

body content`,
			expectedHeaders: map[string]string{
				"call-id": "test-call-123",
				"from":    "alice@example.com",
				"to":      "user@example.com",
			},
			expectedBody: "body content\n",
			description:  "Whitespace should be trimmed from headers",
		},
		{
			name: "Case insensitive headers",
			input: `INVITE sip:user@example.com SIP/2.0
CALL-ID: test-call-456
From: alice@example.com
TO: user@example.com
Content-Type: application/sdp

body content`,
			expectedHeaders: map[string]string{
				"call-id":      "test-call-456",
				"from":         "alice@example.com",
				"to":           "user@example.com",
				"content-type": "application/sdp",
			},
			expectedBody: "body content\n",
			description:  "Header names should be case-insensitive",
		},
		{
			name:            "Empty input",
			input:           "",
			expectedHeaders: map[string]string{},
			expectedBody:    "",
			description:     "Empty input should return empty results",
		},
		{
			name: "Only headers, no body",
			input: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-call-789
From: alice@example.com
To: user@example.com`,
			expectedHeaders: map[string]string{
				"call-id": "test-call-789",
				"from":    "alice@example.com",
				"to":      "user@example.com",
			},
			expectedBody: "",
			description:  "Messages without body should be handled",
		},
		{
			name: "Multiple colons in header value",
			input: `INVITE sip:user@example.com SIP/2.0
Call-ID: test-call-123
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8
From: alice@example.com

body content`,
			expectedHeaders: map[string]string{
				"call-id": "test-call-123",
				"via":     "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8",
				"from":    "alice@example.com",
			},
			expectedBody: "body content\n",
			description:  "Headers with multiple colons should preserve the value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body := parseSipHeaders([]byte(tt.input))

			// Check headers
			for expectedKey, expectedValue := range tt.expectedHeaders {
				actualValue, exists := headers[expectedKey]
				assert.True(t, exists, "Header %s should exist", expectedKey)
				assert.Equal(t, expectedValue, actualValue, "Header %s value should match", expectedKey)
			}

			// Check for unexpected headers
			for actualKey := range headers {
				_, expected := tt.expectedHeaders[actualKey]
				assert.True(t, expected, "Unexpected header found: %s", actualKey)
			}

			// Check body
			assert.Equal(t, tt.expectedBody, body, tt.description)
		})
	}
}

func TestDetectSipMethod_Comprehensive(t *testing.T) {
	tests := []struct {
		name           string
		startLine      string
		expectedMethod string
	}{
		{
			name:           "INVITE method",
			startLine:      "INVITE sip:user@example.com SIP/2.0",
			expectedMethod: "INVITE",
		},
		{
			name:           "BYE method",
			startLine:      "BYE sip:user@example.com SIP/2.0",
			expectedMethod: "BYE",
		},
		{
			name:           "ACK method",
			startLine:      "ACK sip:user@example.com SIP/2.0",
			expectedMethod: "ACK",
		},
		{
			name:           "200 OK response",
			startLine:      "SIP/2.0 200 OK",
			expectedMethod: "",
		},
		{
			name:           "404 Not Found response",
			startLine:      "SIP/2.0 404 Not Found",
			expectedMethod: "",
		},
		{
			name:           "REGISTER method",
			startLine:      "REGISTER sip:example.com SIP/2.0",
			expectedMethod: "REGISTER",
		},
		{
			name:           "Empty line",
			startLine:      "",
			expectedMethod: "",
		},
		{
			name:           "Malformed line",
			startLine:      "NOT A SIP LINE",
			expectedMethod: "",
		},
		{
			name:           "INVITE with extra spaces",
			startLine:      "  INVITE sip:user@example.com SIP/2.0  ",
			expectedMethod: "", // strings.HasPrefix is strict
		},
		{
			name:           "Case sensitivity test",
			startLine:      "invite sip:user@example.com SIP/2.0",
			expectedMethod: "", // Case sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := detectSipMethod(tt.startLine)
			assert.Equal(t, tt.expectedMethod, method)
		})
	}
}

func TestIsSipStartLine_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "Valid INVITE",
			line:     "INVITE sip:user@example.com SIP/2.0",
			expected: true,
		},
		{
			name:     "Valid BYE",
			line:     "BYE sip:user@example.com SIP/2.0",
			expected: true,
		},
		{
			name:     "Valid OPTIONS",
			line:     "OPTIONS sip:user@example.com SIP/2.0",
			expected: true,
		},
		{
			name:     "Valid REGISTER",
			line:     "REGISTER sip:example.com SIP/2.0",
			expected: true,
		},
		{
			name:     "Valid CANCEL",
			line:     "CANCEL sip:user@example.com SIP/2.0",
			expected: true,
		},
		{
			name:     "Valid response",
			line:     "SIP/2.0 404 Not Found",
			expected: true,
		},
		{
			name:     "Invalid HTTP request",
			line:     "GET / HTTP/1.1",
			expected: false,
		},
		{
			name:     "Empty line",
			line:     "",
			expected: false,
		},
		{
			name:     "Random text",
			line:     "This is not a SIP message",
			expected: false,
		},
		{
			name:     "Partial SIP method",
			line:     "INV sip:user@example.com SIP/2.0",
			expected: false,
		},
		{
			name:     "Case sensitivity",
			line:     "invite sip:user@example.com SIP/2.0",
			expected: false, // Case sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSipStartLine(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleSipMessage_CompleteFlow(t *testing.T) {
	// Setup test users
	sipusers.DeleteMultipleSipUsers([]string{"alice", "bob"})
	testUsers := map[string]*sipusers.SipUser{
		"alice": {ExpirationDate: time.Now().Add(1 * time.Hour)},
		"bob":   {ExpirationDate: time.Now().Add(1 * time.Hour)},
	}
	sipusers.AddMultipleSipUsers(testUsers)
	defer sipusers.DeleteMultipleSipUsers([]string{"alice", "bob"})

	tests := []struct {
		name           string
		sipMessage     string
		expectedResult bool
		description    string
	}{
		{
			name: "Complete INVITE with audio",
			sipMessage: `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8
From: alice@example.com;tag=1928301774
To: bob@example.com
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alice@client.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 53655765 2353687637 IN IP4 client.atlanta.com
c=IN IP4 client.atlanta.com
t=0 0
m=audio 5004 RTP/AVP 0`,
			expectedResult: true,
			description:    "Complete SIP INVITE with audio should be processed",
		},
		{
			name: "SIP message without audio",
			sipMessage: `BYE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8
From: alice@example.com;tag=1928301774
To: bob@example.com
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314160 BYE

`,
			expectedResult: true, // Should still be processed even without audio
			description:    "SIP BYE without audio should be processed",
		},
		{
			name: "Non-surveilled users",
			sipMessage: `INVITE sip:charlie@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8
From: dave@example.com;tag=1928301774
To: charlie@example.com
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE

v=0
o=dave 53655765 2353687637 IN IP4 client.atlanta.com
m=audio 5004 RTP/AVP 0`,
			expectedResult: false,
			description:    "Message with no surveilled users should not be processed",
		},
		{
			name: "Missing Call-ID",
			sipMessage: `INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8
From: alice@example.com;tag=1928301774
To: bob@example.com
CSeq: 314159 INVITE

m=audio 5004 RTP/AVP 0`,
			expectedResult: true, // Should be processed but won't extract ports
			description:    "Message without Call-ID should be processed but limited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handleSipMessage([]byte(tt.sipMessage), layers.LinkTypeEthernet)
			assert.Equal(t, tt.expectedResult, result, tt.description)
		})
	}
}

func TestParseHeaderLine_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectedKey string
		expectedVal string
		description string
	}{
		{
			name:        "Normal header",
			line:        "Call-ID: test123",
			expectedKey: "call-id",
			expectedVal: "test123",
			description: "Normal header should parse correctly",
		},
		{
			name:        "No colon",
			line:        "InvalidHeader",
			expectedKey: "",
			expectedVal: "",
			description: "Line without colon should return empty values",
		},
		{
			name:        "Empty value",
			line:        "Call-ID:",
			expectedKey: "call-id",
			expectedVal: "",
			description: "Header with empty value should work",
		},
		{
			name:        "Multiple colons",
			line:        "Via: SIP/2.0/UDP 192.168.1.1:5060",
			expectedKey: "via",
			expectedVal: "SIP/2.0/UDP 192.168.1.1:5060",
			description: "Multiple colons should preserve the rest as value",
		},
		{
			name:        "Whitespace handling",
			line:        "  Call-ID  :  test123  ",
			expectedKey: "call-id",
			expectedVal: "test123",
			description: "Whitespace should be trimmed",
		},
		{
			name:        "Empty line",
			line:        "",
			expectedKey: "",
			expectedVal: "",
			description: "Empty line should return empty values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, val := parseHeaderLine(tt.line)
			assert.Equal(t, tt.expectedKey, key, tt.description)
			assert.Equal(t, tt.expectedVal, val, tt.description)
		})
	}
}
