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
			payload: `INVITE sip:bob@example.com SIP/2.0
From: Alice <sip:alice@example.com>;tag=123
To: Bob <sip:bob@example.com>
P-Asserted-Identity: <sip:+4415777@carrier.com>
Call-ID: abc123
`,
			wantFrom: `Alice <sip:alice@example.com>;tag=123`,
			wantTo:   `Bob <sip:bob@example.com>`,
			wantPAI:  `<sip:+4415777@carrier.com>`,
		},
		{
			name: "Compact form headers",
			payload: `INVITE sip:bob@example.com SIP/2.0
f: <sip:alice@example.com>
t: <sip:bob@example.com>
Call-ID: xyz789
`,
			wantFrom: `<sip:alice@example.com>`,
			wantTo:   `<sip:bob@example.com>`,
			wantPAI:  "",
		},
		{
			name: "Case-insensitive headers",
			payload: `INVITE sip:bob@example.com SIP/2.0
FROM: <sip:alice@example.com>
TO: <sip:bob@example.com>
p-asserted-identity: <sip:+1234567890@carrier.com>
`,
			wantFrom: `<sip:alice@example.com>`,
			wantTo:   `<sip:bob@example.com>`,
			wantPAI:  `<sip:+1234567890@carrier.com>`,
		},
		{
			name: "Headers with extra whitespace",
			payload: `INVITE sip:bob@example.com SIP/2.0
From:   Alice <sip:alice@example.com>
To:  Bob <sip:bob@example.com>
P-Asserted-Identity:  <sip:+44123@carrier.com>
`,
			wantFrom: `Alice <sip:alice@example.com>`,
			wantTo:   `Bob <sip:bob@example.com>`,
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
	vf := &VoIPFilter{
		sipUsers:     []string{"alice", "bob"},
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
			payload: `INVITE sip:bob@example.com SIP/2.0
From: Alice <sip:alice@example.com>
To: Bob <sip:bob@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "alice in From header",
		},
		{
			name: "Match in To header",
			payload: `INVITE sip:alice@example.com SIP/2.0
From: Charlie <sip:charlie@example.com>
To: Bob <sip:bob@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "bob in To header",
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
o=alice 123 456 IN IP4 192.168.1.1
s=Session with alice mentioned here
`,
			shouldMatch: false,
			reason:      "alice only in SDP body, not in headers",
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
From: <sip:ALICE@example.com>
To: <sip:someone@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "ALICE (uppercase) should match alice filter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vf.matchWithCPU(tt.payload)
			assert.Equal(t, tt.shouldMatch, result, tt.reason)
		})
	}
}

func TestMatchWithCPU_NoFilters(t *testing.T) {
	// When no filters are set, should match everything
	vf := &VoIPFilter{
		sipUsers:     []string{},
		phoneNumbers: []string{},
	}

	payload := `INVITE sip:anyone@example.com SIP/2.0
From: <sip:anyone@example.com>
To: <sip:anyone@example.com>
`

	// This test is checking the MatchPacket logic which returns true when no filters
	// matchWithCPU itself doesn't have this logic, so we test that it returns false
	result := vf.matchWithCPU(payload)
	assert.False(t, result, "matchWithCPU should return false when no patterns match")
}
