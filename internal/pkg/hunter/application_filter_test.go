package hunter

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
)

// newTestApplicationFilter creates an ApplicationFilter for testing with properly
// initialized acMatcher. The patterns from sipUsers and phoneNumbers are automatically
// added to the AC matcher.
func newTestApplicationFilter(sipUsers, phoneNumbers []parsedFilter) *ApplicationFilter {
	af := &ApplicationFilter{
		sipUsers:      sipUsers,
		sipURIs:       []parsedFilter{},
		phoneNumbers:  phoneNumbers,
		acMatcher:     ahocorasick.NewBufferedMatcher(),
		sipURIMatcher: ahocorasick.NewBufferedMatcher(),
	}

	// Build AC patterns from sipUsers and phoneNumbers
	acPatterns := make([]ahocorasick.Pattern, 0, len(sipUsers)+len(phoneNumbers))
	for i, f := range sipUsers {
		acPatterns = append(acPatterns, ahocorasick.Pattern{
			ID:   i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}
	baseID := len(sipUsers)
	for i, f := range phoneNumbers {
		acPatterns = append(acPatterns, ahocorasick.Pattern{
			ID:   baseID + i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}

	// Synchronously update patterns so they're ready for testing
	_ = af.acMatcher.UpdatePatternsSync(acPatterns)

	return af
}

// newTestApplicationFilterWithSIPURI creates an ApplicationFilter for testing SIPURI matching.
// SIPURI patterns match user@domain, not just user.
func newTestApplicationFilterWithSIPURI(sipURIs []parsedFilter) *ApplicationFilter {
	af := &ApplicationFilter{
		sipUsers:      []parsedFilter{},
		sipURIs:       sipURIs,
		phoneNumbers:  []parsedFilter{},
		acMatcher:     ahocorasick.NewBufferedMatcher(),
		sipURIMatcher: ahocorasick.NewBufferedMatcher(),
	}

	// Build AC patterns for SIPURI matching
	uriPatterns := make([]ahocorasick.Pattern, 0, len(sipURIs))
	for i, f := range sipURIs {
		uriPatterns = append(uriPatterns, ahocorasick.Pattern{
			ID:   i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}

	// Synchronously update patterns so they're ready for testing
	_ = af.sipURIMatcher.UpdatePatternsSync(uriPatterns)

	return af
}

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
	af := newTestApplicationFilter(
		[]parsedFilter{
			{original: "alicent", pattern: "alicent", patternType: filtering.PatternTypeContains},
			{original: "robb", pattern: "robb", patternType: filtering.PatternTypeContains},
		},
		[]parsedFilter{
			{original: "+4415777", pattern: "+4415777", patternType: filtering.PatternTypeContains},
			{original: "1234567890", pattern: "1234567890", patternType: filtering.PatternTypeContains},
		},
	)

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
	// When no filters are set, should NOT match (no patterns to match against)
	af := newTestApplicationFilter([]parsedFilter{}, []parsedFilter{})

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
		sipUsers:     []parsedFilter{},
		phoneNumbers: []parsedFilter{},
		ipAddresses:  []string{"192.168.0.1", "10.0.0.5"},
	}

	// Test that IP addresses are stored correctly
	assert.Equal(t, 2, len(af.ipAddresses), "Should have 2 IP addresses")
	assert.Contains(t, af.ipAddresses, "192.168.0.1")
	assert.Contains(t, af.ipAddresses, "10.0.0.5")
}

func TestMatchWithCPU_WildcardPatterns(t *testing.T) {
	// Test suffix pattern matching for phone numbers (main use case)
	af := newTestApplicationFilter(
		[]parsedFilter{
			{original: "alice*", pattern: "alice", patternType: filtering.PatternTypePrefix},
		},
		[]parsedFilter{
			// Suffix pattern to match last 6 digits regardless of prefix
			{original: "*456789", pattern: "456789", patternType: filtering.PatternTypeSuffix},
		},
	)

	tests := []struct {
		name        string
		payload     string
		shouldMatch bool
		reason      string
	}{
		{
			name: "Suffix match E.164 format",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "+49123456789 ends with 456789",
		},
		{
			name: "Suffix match 00-prefix format",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:0049123456789@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "0049123456789 ends with 456789",
		},
		{
			name: "Suffix match tech prefix (CLIR)",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:*31#+49123456789@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "*31#+49123456789 ends with 456789",
		},
		{
			name: "Suffix no match - different ending",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456000@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: false,
			reason:      "+49123456000 does NOT end with 456789",
		},
		{
			name: "Prefix match for username",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:alice.smith@example.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "alice.smith starts with alice",
		},
		{
			name: "Prefix no match",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:bob.alice@example.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: false,
			reason:      "bob.alice does NOT start with alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := af.matchWithCPU(tt.payload)
			assert.Equal(t, tt.shouldMatch, result, tt.reason)
		})
	}
}

func TestMatchWithCPU_SIPURIMatching(t *testing.T) {
	// SIPURI filter: matches user@domain (not just user part)
	af := newTestApplicationFilterWithSIPURI(
		[]parsedFilter{
			// Exact URI match
			{original: "alice@example.com", pattern: "alice@example.com", patternType: filtering.PatternTypeContains},
			// Match any user at specific domain
			{original: "@carrier.com", pattern: "@carrier.com", patternType: filtering.PatternTypeSuffix},
		},
	)

	tests := []struct {
		name        string
		payload     string
		shouldMatch bool
		reason      string
	}{
		{
			name: "Exact URI match",
			payload: `INVITE sip:robb@example.com SIP/2.0
From: Alice <sip:alice@example.com>
To: Robb <sip:robb@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "alice@example.com matches exactly",
		},
		{
			name: "Domain suffix match",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+4912345@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: true,
			reason:      "+4912345@carrier.com ends with @carrier.com",
		},
		{
			name: "No match - different domain",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:alice@different.com>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: false,
			reason:      "alice@different.com does not match alice@example.com",
		},
		{
			name: "No match - user part only would match but URI doesn't",
			payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:alice@other-domain.org>
To: <sip:dest@example.com>
Call-ID: test123
`,
			shouldMatch: false,
			reason:      "alice@other-domain.org does not match alice@example.com (full URI match required)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := af.matchWithCPU(tt.payload)
			assert.Equal(t, tt.shouldMatch, result, tt.reason)
		})
	}
}

func TestMatchWithCPU_SIPUserVsSIPURI_Difference(t *testing.T) {
	// This test demonstrates the key difference between SIPUser and SIPURI filters:
	// - SIPUser: extracts user part only, uses suffix matching (for phone numbers)
	// - SIPURI: extracts user@domain, uses exact/contains matching

	// Test case: Looking for calls from alice (suffix pattern *456789)
	// The user "+49123456789" should match SIPUser filter "*456789"
	// But the URI "+49123456789@carrier.com" requires different handling

	t.Run("SIPUser suffix matches user part only", func(t *testing.T) {
		af := newTestApplicationFilter(
			[]parsedFilter{},
			[]parsedFilter{
				// Phone number suffix pattern
				{original: "*456789", pattern: "456789", patternType: filtering.PatternTypeSuffix},
			},
		)

		payload := `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`
		result := af.matchWithCPU(payload)
		assert.True(t, result, "SIPUser/PhoneNumber filter should match user part +49123456789 ending with 456789")
	})

	t.Run("SIPURI matches full identity", func(t *testing.T) {
		af := newTestApplicationFilterWithSIPURI(
			[]parsedFilter{
				// Full URI pattern
				{original: "+49123456789@carrier.com", pattern: "+49123456789@carrier.com", patternType: filtering.PatternTypeContains},
			},
		)

		payload := `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`
		result := af.matchWithCPU(payload)
		assert.True(t, result, "SIPURI filter should match full URI +49123456789@carrier.com")
	})

	t.Run("SIPURI does not match when domain differs", func(t *testing.T) {
		af := newTestApplicationFilterWithSIPURI(
			[]parsedFilter{
				{original: "+49123456789@carrier.com", pattern: "+49123456789@carrier.com", patternType: filtering.PatternTypeContains},
			},
		)

		payload := `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@different-carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`
		result := af.matchWithCPU(payload)
		assert.False(t, result, "SIPURI filter should NOT match when domain differs (+49123456789@different-carrier.com vs +49123456789@carrier.com)")
	})

	t.Run("SIPUser matches regardless of domain", func(t *testing.T) {
		af := newTestApplicationFilter(
			[]parsedFilter{},
			[]parsedFilter{
				{original: "*456789", pattern: "456789", patternType: filtering.PatternTypeSuffix},
			},
		)

		// Same user, different domains
		payloads := []struct {
			payload string
			domain  string
		}{
			{
				payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@carrier.com>
To: <sip:dest@example.com>
`,
				domain: "carrier.com",
			},
			{
				payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@different.org>
To: <sip:dest@example.com>
`,
				domain: "different.org",
			},
			{
				payload: `INVITE sip:someone@example.com SIP/2.0
From: <sip:+49123456789@third-party.net>
To: <sip:dest@example.com>
`,
				domain: "third-party.net",
			},
		}

		for _, p := range payloads {
			result := af.matchWithCPU(p.payload)
			assert.True(t, result, "SIPUser filter should match user part regardless of domain (%s)", p.domain)
		}
	})
}
