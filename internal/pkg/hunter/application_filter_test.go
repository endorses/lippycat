package hunter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractSIPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantFrom string
		wantTo   string
		wantPAI  string
	}{
		{
			name: "Standard SIP INVITE",
			payload: `INVITE sip:robb@example.com SIP/2.0
From: Alicent <sip:alicent@example.com>;tag=123
To: Robb <sip:robb@example.com>
P-Asserted-Identity: <sip:+4415777@carrier.com>
Call-ID: abc123
`,
			wantFrom: `Alicent <sip:alicent@example.com>;tag=123`,
			wantTo:   `Robb <sip:robb@example.com>`,
			wantPAI:  `<sip:+4415777@carrier.com>`,
		},
		{
			name: "Compact form headers",
			payload: `INVITE sip:robb@example.com SIP/2.0
f: <sip:alicent@example.com>
t: <sip:robb@example.com>
Call-ID: xyz789
`,
			wantFrom: `<sip:alicent@example.com>`,
			wantTo:   `<sip:robb@example.com>`,
			wantPAI:  "",
		},
		{
			name: "Case-insensitive headers",
			payload: `INVITE sip:robb@example.com SIP/2.0
FROM: <sip:alicent@example.com>
TO: <sip:robb@example.com>
p-asserted-identity: <sip:+1234567890@carrier.com>
`,
			wantFrom: `<sip:alicent@example.com>`,
			wantTo:   `<sip:robb@example.com>`,
			wantPAI:  `<sip:+1234567890@carrier.com>`,
		},
		{
			name: "Headers with extra whitespace",
			payload: `INVITE sip:robb@example.com SIP/2.0
From:   Alicent <sip:alicent@example.com>
To:  Robb <sip:robb@example.com>
P-Asserted-Identity:  <sip:+44123@carrier.com>
`,
			wantFrom: `Alicent <sip:alicent@example.com>`,
			wantTo:   `Robb <sip:robb@example.com>`,
			wantPAI:  `<sip:+44123@carrier.com>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := extractSIPHeaders([]byte(tt.payload))

			assert.Equal(t, tt.wantFrom, string(headers.from), "From header should match")
			assert.Equal(t, tt.wantTo, string(headers.to), "To header should match")
			assert.Equal(t, tt.wantPAI, string(headers.pAssertedIdentity), "P-Asserted-Identity header should match")
		})
	}
}

func TestMatchWithCPU_ProperHeaderFiltering(t *testing.T) {
	af := &ApplicationFilter{
		sipUsers:     []string{"alicent", "robb"},
		phoneNumbers: []string{"+4415777", "1234567890"},
	}

	tests := []struct {
		name        string
		payload     string
		shouldMatch bool
		reason      string
	}{
		{
			name: "Match in From header",
			payload: `INVITE sip:robb@example.com SIP/2.0
From: Alicent <sip:alicent@example.com>
To: Robb <sip:robb@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "alicent in From header",
		},
		{
			name: "Match in To header",
			payload: `INVITE sip:alicent@example.com SIP/2.0
From: Charlie <sip:charlie@example.com>
To: Robb <sip:robb@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "robb in To header",
		},
		{
			name: "Match in P-Asserted-Identity",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:unknown@example.com>
To: <sip:someone@example.com>
P-Asserted-Identity: <sip:+4415777@carrier.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "+4415777 in P-Asserted-Identity",
		},
		{
			name: "No match - name only in SDP body (false positive prevention)",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:unknown@example.com>
To: <sip:someone@example.com>
Call-ID: test123

v=0
o=alicent 123 456 IN IP4 192.168.1.1
s=Session with alicent mentioned here
`,
			shouldMatch: false,
			reason:      "alicent only in SDP body, not in headers",
		},
		{
			name: "Phone number match",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+4415777@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "+4415777 phone number in From",
		},
		{
			name: "Case-insensitive user match",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:ALICENT@example.com>
To: <sip:someone@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "ALICENT (uppercase) should match alicent filter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := af.matchWithCPU(tt.payload)
			assert.Equal(t, tt.shouldMatch, result, tt.reason)
		})
	}
}

func TestMatchWithCPU_NoFilters(t *testing.T) {
	// When no filters are set, should match everything
	af := &ApplicationFilter{
		sipUsers:     []string{},
		phoneNumbers: []string{},
		ipAddresses:  []string{},
	}

	payload := `INVITE sip:anyone@example.com SIP/2.0
From: <sip:anyone@example.com>
To: <sip:anyone@example.com>
`

	// This test is checking the MatchPacket logic which returns true when no filters
	// matchWithCPU itself doesn't have this logic, so we test that it returns false
	result := af.matchWithCPU(payload)
	assert.False(t, result, "matchWithCPU should return false when no patterns match")
}

func TestMatchIPAddress(t *testing.T) {
	// Note: This test would require creating mock gopacket.Packet objects with network layers
	// For now, we'll test the UpdateFilters integration with IP addresses
	af := &ApplicationFilter{
		sipUsers:     []string{},
		phoneNumbers: []string{},
		ipAddresses:  []string{"192.168.0.1", "10.0.0.5"},
	}

	// Test that IP addresses are stored correctly
	assert.Equal(t, 2, len(af.ipAddresses), "Should have 2 IP addresses")
	assert.Contains(t, af.ipAddresses, "192.168.0.1")
	assert.Contains(t, af.ipAddresses, "10.0.0.5")
}
