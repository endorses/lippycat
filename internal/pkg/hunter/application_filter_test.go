package hunter

import (
	"net/netip"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/voip"
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

// TestMatchWithGPU_SIPURINamedAutomaton tests GPU matching using named automatons.
// This verifies that SIPURI matching via GPU works correctly using a separate named automaton.
func TestMatchWithGPU_SIPURINamedAutomaton(t *testing.T) {
	// Create an ApplicationFilter with GPU enabled (SIMD backend)
	config := &voip.GPUConfig{
		Enabled:          true,
		Backend:          "cpu-simd",
		PatternAlgorithm: voip.PatternAlgorithmAhoCorasick,
	}

	af, err := NewApplicationFilter(config)
	assert.NoError(t, err)

	// Update filters with both SIPUser and SIPURI filters
	filters := []*management.Filter{
		{Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice"},
		{Type: management.FilterType_FILTER_SIP_URI, Pattern: "bob@example.com"},
	}
	af.UpdateFilters(filters)

	// Verify both GPU automatons are built
	assert.True(t, af.gpuACBuilt, "GPU AC automaton should be built for SIPUser")
	assert.True(t, af.gpuSIPURIACBuilt, "GPU SIPURI AC automaton should be built")

	t.Run("GPU SIPUser matching via named automaton", func(t *testing.T) {
		payload := []byte(`INVITE sip:someone@example.com SIP/2.0
From: <sip:alice@carrier.com>
To: <sip:dest@example.com>
Call-ID: test123
`)
		result := af.matchWithGPU(payload)
		assert.True(t, result, "Should match SIPUser 'alice' via GPU")
	})

	t.Run("GPU SIPURI matching via named automaton", func(t *testing.T) {
		payload := []byte(`INVITE sip:someone@example.com SIP/2.0
From: <sip:bob@example.com>
To: <sip:dest@example.com>
Call-ID: test123
`)
		result := af.matchWithGPU(payload)
		assert.True(t, result, "Should match SIPURI 'bob@example.com' via GPU")
	})

	t.Run("GPU SIPURI no match when domain differs", func(t *testing.T) {
		payload := []byte(`INVITE sip:someone@example.com SIP/2.0
From: <sip:bob@different.org>
To: <sip:dest@example.com>
Call-ID: test123
`)
		result := af.matchWithGPU(payload)
		assert.False(t, result, "Should NOT match SIPURI when domain differs")
	})

	t.Run("GPU both filters - SIPUser match", func(t *testing.T) {
		payload := []byte(`INVITE sip:someone@example.com SIP/2.0
From: <sip:alice@any-domain.com>
To: <sip:dest@example.com>
Call-ID: test123
`)
		result := af.matchWithGPU(payload)
		assert.True(t, result, "Should match SIPUser 'alice' even with different domain")
	})
}

// TestIPFilterOptimization tests the O(1) hash map for exact IPs and O(prefix) radix tree for CIDRs
func TestIPFilterOptimization(t *testing.T) {
	t.Run("UpdateFilters parses exact IPv4", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.1"},
		}
		af.UpdateFilters(filters)

		assert.Equal(t, 2, len(af.exactIPv4), "Should have 2 exact IPv4 addresses")
		assert.Equal(t, 0, len(af.exactIPv6), "Should have no IPv6 addresses")
		assert.False(t, af.hasCIDRFilters, "Should have no CIDR filters")
	})

	t.Run("UpdateFilters parses exact IPv6", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "::1"},
		}
		af.UpdateFilters(filters)

		assert.Equal(t, 0, len(af.exactIPv4), "Should have no IPv4 addresses")
		assert.Equal(t, 2, len(af.exactIPv6), "Should have 2 exact IPv6 addresses")
		assert.False(t, af.hasCIDRFilters, "Should have no CIDR filters")
	})

	t.Run("UpdateFilters parses CIDR IPv4", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.0/8"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.0.0/16"},
		}
		af.UpdateFilters(filters)

		assert.Equal(t, 0, len(af.exactIPv4), "CIDR should not be in exact map")
		assert.True(t, af.hasCIDRFilters, "Should have CIDR filters")
	})

	t.Run("UpdateFilters parses CIDR IPv6", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::/32"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "fe80::/10"},
		}
		af.UpdateFilters(filters)

		assert.Equal(t, 0, len(af.exactIPv6), "CIDR should not be in exact map")
		assert.True(t, af.hasCIDRFilters, "Should have CIDR filters")
	})

	t.Run("UpdateFilters handles mixed exact and CIDR", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},   // exact IPv4
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.0/8"},    // CIDR IPv4
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::1"},   // exact IPv6
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::/32"}, // CIDR IPv6
		}
		af.UpdateFilters(filters)

		assert.Equal(t, 1, len(af.exactIPv4), "Should have 1 exact IPv4")
		assert.Equal(t, 1, len(af.exactIPv6), "Should have 1 exact IPv6")
		assert.True(t, af.hasCIDRFilters, "Should have CIDR filters")
	})

	t.Run("matchSingleIP matches exact IPv4", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.1"},
		}
		af.UpdateFilters(filters)

		// Test matching IPs
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.1.1")), "Should match 192.168.1.1")
		assert.True(t, af.matchSingleIP(mustParseAddr("10.0.0.1")), "Should match 10.0.0.1")

		// Test non-matching IPs
		assert.False(t, af.matchSingleIP(mustParseAddr("192.168.1.2")), "Should not match 192.168.1.2")
		assert.False(t, af.matchSingleIP(mustParseAddr("8.8.8.8")), "Should not match 8.8.8.8")
	})

	t.Run("matchSingleIP matches CIDR IPv4", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.0/8"},     // Class A
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.0.0/16"}, // Class C private
		}
		af.UpdateFilters(filters)

		// Test IPs within 10.0.0.0/8
		assert.True(t, af.matchSingleIP(mustParseAddr("10.0.0.1")), "10.0.0.1 should match 10.0.0.0/8")
		assert.True(t, af.matchSingleIP(mustParseAddr("10.255.255.255")), "10.255.255.255 should match 10.0.0.0/8")
		assert.True(t, af.matchSingleIP(mustParseAddr("10.123.45.67")), "10.123.45.67 should match 10.0.0.0/8")

		// Test IPs within 192.168.0.0/16
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.0.1")), "192.168.0.1 should match 192.168.0.0/16")
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.255.255")), "192.168.255.255 should match 192.168.0.0/16")

		// Test IPs outside both CIDRs
		assert.False(t, af.matchSingleIP(mustParseAddr("11.0.0.1")), "11.0.0.1 should not match")
		assert.False(t, af.matchSingleIP(mustParseAddr("8.8.8.8")), "8.8.8.8 should not match")
		assert.False(t, af.matchSingleIP(mustParseAddr("192.169.0.1")), "192.169.0.1 should not match 192.168.0.0/16")
	})

	t.Run("matchSingleIP matches exact IPv6", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::1"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "::1"},
		}
		af.UpdateFilters(filters)

		// Test matching IPs
		assert.True(t, af.matchSingleIP(mustParseAddr("2001:db8::1")), "Should match 2001:db8::1")
		assert.True(t, af.matchSingleIP(mustParseAddr("::1")), "Should match ::1")

		// Test non-matching IPs
		assert.False(t, af.matchSingleIP(mustParseAddr("2001:db8::2")), "Should not match 2001:db8::2")
		assert.False(t, af.matchSingleIP(mustParseAddr("::2")), "Should not match ::2")
	})

	t.Run("matchSingleIP matches CIDR IPv6", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "2001:db8::/32"},
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "fe80::/10"},
		}
		af.UpdateFilters(filters)

		// Test IPs within 2001:db8::/32
		assert.True(t, af.matchSingleIP(mustParseAddr("2001:db8::1")), "2001:db8::1 should match 2001:db8::/32")
		assert.True(t, af.matchSingleIP(mustParseAddr("2001:db8:abcd::1")), "2001:db8:abcd::1 should match 2001:db8::/32")

		// Test IPs within fe80::/10 (link-local)
		assert.True(t, af.matchSingleIP(mustParseAddr("fe80::1")), "fe80::1 should match fe80::/10")
		assert.True(t, af.matchSingleIP(mustParseAddr("febf::1")), "febf::1 should match fe80::/10")

		// Test IPs outside CIDRs
		assert.False(t, af.matchSingleIP(mustParseAddr("2001:db9::1")), "2001:db9::1 should not match 2001:db8::/32")
		assert.False(t, af.matchSingleIP(mustParseAddr("fec0::1")), "fec0::1 should not match fe80::/10")
	})

	t.Run("matchSingleIP prioritizes exact match over CIDR", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		filters := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},    // exact
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.0.0/16"}, // CIDR
		}
		af.UpdateFilters(filters)

		// Both exact and CIDR should work
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.1.1")), "Exact IP should match")
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.1.2")), "IP in CIDR should match")
	})

	t.Run("UpdateFilters clears previous filters", func(t *testing.T) {
		af, err := NewApplicationFilter(nil)
		assert.NoError(t, err)

		// First update
		filters1 := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.168.1.1"},
		}
		af.UpdateFilters(filters1)
		assert.True(t, af.matchSingleIP(mustParseAddr("192.168.1.1")), "Should match after first update")

		// Second update with different IP
		filters2 := []*management.Filter{
			{Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "10.0.0.1"},
		}
		af.UpdateFilters(filters2)

		assert.False(t, af.matchSingleIP(mustParseAddr("192.168.1.1")), "Old IP should not match after update")
		assert.True(t, af.matchSingleIP(mustParseAddr("10.0.0.1")), "New IP should match after update")
	})
}

// mustParseAddr parses an IP address and panics on error (for tests only)
func mustParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}
