package sipusers

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	username   string
	newSipUser *SipUser
}

var (
	sipUser1 = SipUser{ExpirationDate: time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)}
	sipUser2 = SipUser{ExpirationDate: time.Date(2035, 1, 1, 1, 1, 1, 1, time.UTC)}
	test     = make(map[string]*SipUser)
)

func TestAddSipUser(t *testing.T) {
	t.Run("user add checking", func(t *testing.T) {
		tests := []testCase{
			{username: "testuser1", newSipUser: &sipUser1},
			{username: "testuser2", newSipUser: &sipUser2},
		}
		for _, test := range tests {
			AddSipUser(test.username, test.newSipUser)
			assert.Equal(t, test.newSipUser.ExpirationDate, sipUserMap[test.username].ExpirationDate)
		}
	})
}

func TestAddMultipleSipUsers(t *testing.T) {
	t.Run("multi user add", func(t *testing.T) {
		test["testuser3"] = &sipUser1
		test["testuser4"] = &sipUser2
		AddMultipleSipUsers(test)
		assert.Equal(t, test["testuser3"], sipUserMap["testuser3"])
		assert.Equal(t, test["testuser4"], sipUserMap["testuser4"])
	})
}

func TestDeleteSipUser(t *testing.T) {
	t.Run("delete sip user", func(t *testing.T) {
		sipUserMap["testuser5"] = &sipUser2
		DeleteSipUser("testuser5")
		assert.Equal(t, (*SipUser)(nil), sipUserMap["testuser5"])
	})
}

func TestDeleteMultipleSipUsers(t *testing.T) {
	t.Run("delete multiple sip users", func(t *testing.T) {
		sipUserMap["testuser6"] = &sipUser2
		sipUserMap["testuser7"] = &sipUser2
		DeleteMultipleSipUsers([]string{"testuser6", "testuser7"})
		assert.Equal(t, (*SipUser)(nil), sipUserMap["testuser6"])
		assert.Equal(t, (*SipUser)(nil), sipUserMap["testuser7"])
	})
}

func TestIsSurveiled(t *testing.T) {
	// Clear existing users
	ClearAll()

	// Add test users
	testUsers := map[string]*SipUser{
		"alicent": {ExpirationDate: time.Now().Add(1 * time.Hour)},
		"robb":    {ExpirationDate: time.Now().Add(2 * time.Hour)},
		"charlie": {ExpirationDate: time.Now().Add(3 * time.Hour)},
	}
	AddMultipleSipUsers(testUsers)

	tests := []struct {
		name      string
		sipHeader string
		expected  bool
	}{
		{
			name:      "Header contains alicent",
			sipHeader: "<sip:alicent@example.com>;tag=123",
			expected:  true,
		},
		{
			name:      "Header contains robb",
			sipHeader: "<sip:robb@company.org>",
			expected:  true,
		},
		{
			name:      "Header contains charlie in URI",
			sipHeader: "<sip:charlie@192.168.1.100:5060>",
			expected:  true,
		},
		{
			name:      "Header contains alicent in display name only (no match - we extract username)",
			sipHeader: "Alicent Smith <sip:asmith@example.com>",
			expected:  false, // Now we extract username "asmith", not display name
		},
		{
			name:      "Header with multiple URIs - first matches",
			sipHeader: "<sip:alicent@proxy1.example.com>, <sip:proxy2.example.com>",
			expected:  true,
		},
		{
			name:      "Header with no surveiled users",
			sipHeader: "<sip:eve@external.com>;tag=456",
			expected:  false,
		},
		{
			name:      "Empty header",
			sipHeader: "",
			expected:  false,
		},
		{
			name:      "Header with partial match (should match with contains pattern)",
			sipHeader: "<sip:alicent-backup@example.com>", // Contains "alicent"
			expected:  true,
		},
		{
			name:      "Header with case sensitivity",
			sipHeader: "<sip:ALICENT@example.com>",
			expected:  true,
		},
		{
			name:      "Header with username as substring",
			sipHeader: "<sip:robby@example.com>",
			expected:  true, // Contains "robb"
		},
		{
			name:      "SIPS URI",
			sipHeader: "<sips:alicent@secure.example.com>",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSurveiled(tt.sipHeader)
			assert.Equal(t, tt.expected, result, "IsSurveiled should return %t for header: %s", tt.expected, tt.sipHeader)
		})
	}
}

func TestIsSurveiled_WildcardPatterns(t *testing.T) {
	// Test wildcard pattern matching for international phone number formats

	tests := []struct {
		name      string
		patterns  []string // Patterns to add as sipusers
		sipHeader string   // SIP header value to check
		expected  bool
	}{
		// Suffix matching (*456789)
		{
			name:      "Suffix pattern matches E.164 format",
			patterns:  []string{"*456789"},
			sipHeader: "<sip:+49123456789@domain.com>",
			expected:  true,
		},
		{
			name:      "Suffix pattern matches 00-prefix format",
			patterns:  []string{"*456789"},
			sipHeader: "<sip:0049123456789@domain.com>",
			expected:  true,
		},
		{
			name:      "Suffix pattern matches tech prefix format",
			patterns:  []string{"*456789"},
			sipHeader: "<sip:*31#+49123456789@domain.com>",
			expected:  true,
		},
		{
			name:      "Suffix pattern no match",
			patterns:  []string{"*456789"},
			sipHeader: "<sip:+49123456000@domain.com>",
			expected:  false,
		},

		// Prefix matching (alice*)
		{
			name:      "Prefix pattern matches exact",
			patterns:  []string{"alice*"},
			sipHeader: "<sip:alice@domain.com>",
			expected:  true,
		},
		{
			name:      "Prefix pattern matches with suffix",
			patterns:  []string{"alice*"},
			sipHeader: "<sip:alicent@domain.com>",
			expected:  true,
		},
		{
			name:      "Prefix pattern no match",
			patterns:  []string{"alice*"},
			sipHeader: "<sip:bob@domain.com>",
			expected:  false,
		},
		{
			name:      "Prefix pattern is case-insensitive",
			patterns:  []string{"alice*"},
			sipHeader: "<sip:ALICENT@domain.com>",
			expected:  true,
		},

		// Contains matching (default, backward compatible)
		{
			name:      "Contains pattern matches substring",
			patterns:  []string{"admin"},
			sipHeader: "<sip:sysadmin@domain.com>",
			expected:  true,
		},
		{
			name:      "Contains pattern matches at start",
			patterns:  []string{"admin"},
			sipHeader: "<sip:admin@domain.com>",
			expected:  true,
		},
		{
			name:      "Contains pattern matches at end",
			patterns:  []string{"admin"},
			sipHeader: "<sip:superadmin@domain.com>",
			expected:  true,
		},

		// Explicit contains (*pattern*)
		{
			name:      "Explicit contains matches",
			patterns:  []string{"*admin*"},
			sipHeader: "<sip:sysadmin123@domain.com>",
			expected:  true,
		},

		// Multiple patterns (any match)
		{
			name:      "Multiple patterns - first matches",
			patterns:  []string{"*456789", "*999000"},
			sipHeader: "<sip:+49123456789@domain.com>",
			expected:  true,
		},
		{
			name:      "Multiple patterns - second matches",
			patterns:  []string{"*456789", "*999000"},
			sipHeader: "<sip:+49123999000@domain.com>",
			expected:  true,
		},
		{
			name:      "Multiple patterns - none matches",
			patterns:  []string{"*456789", "*999000"},
			sipHeader: "<sip:+49123111222@domain.com>",
			expected:  false,
		},

		// Edge cases
		{
			name:      "Empty pattern matches everything",
			patterns:  []string{""},
			sipHeader: "<sip:anyuser@domain.com>",
			expected:  true,
		},
		{
			name:      "Escaped asterisk as literal",
			patterns:  []string{"\\*31#"},
			sipHeader: "<sip:*31#123456789@domain.com>",
			expected:  true,
		},
		{
			name:      "P-Asserted-Identity header value",
			patterns:  []string{"*456789"},
			sipHeader: "<sip:+49123456789@domain.com>",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and add patterns
			ClearAll()
			for _, pattern := range tt.patterns {
				AddSipUser(pattern, &SipUser{ExpirationDate: time.Now().Add(1 * time.Hour)})
			}

			result := IsSurveiled(tt.sipHeader)
			assert.Equal(t, tt.expected, result,
				"IsSurveiled with patterns %v should return %t for header: %s",
				tt.patterns, tt.expected, tt.sipHeader)
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
			name:     "Simple SIP URI",
			uri:      "<sip:alice@domain.com>",
			expected: "alice",
		},
		{
			name:     "SIP URI with display name",
			uri:      "Alice Smith <sip:alice@domain.com>",
			expected: "alice",
		},
		{
			name:     "SIP URI with tag",
			uri:      "<sip:alice@domain.com>;tag=123",
			expected: "alice",
		},
		{
			name:     "SIPS URI",
			uri:      "<sips:alice@secure.domain.com>",
			expected: "alice",
		},
		{
			name:     "Phone number in URI",
			uri:      "<sip:+49123456789@domain.com>",
			expected: "+49123456789",
		},
		{
			name:     "Phone number with tech prefix",
			uri:      "<sip:*31#+49123456789@domain.com>",
			expected: "*31#+49123456789",
		},
		{
			name:     "No @ symbol",
			uri:      "<sip:alice>",
			expected: "",
		},
		{
			name:     "No SIP prefix - returns as-is",
			uri:      "alice",
			expected: "alice",
		},
		{
			name:     "Empty string",
			uri:      "",
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

func TestIsSurveiled_Concurrency(t *testing.T) {
	// Test concurrent access to IsSurveiled
	ClearAll()
	AddSipUser("testuser", &SipUser{ExpirationDate: time.Now().Add(1 * time.Hour)})

	const numGoroutines = 50
	const checksPerGoroutine = 100

	var wg sync.WaitGroup
	results := make(chan bool, numGoroutines*checksPerGoroutine)

	// Start multiple goroutines checking surveillance concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < checksPerGoroutine; j++ {
				// Alternate between headers that should match and shouldn't match
				var header string
				var expected bool
				if j%2 == 0 {
					header = fmt.Sprintf("<sip:testuser@example%d.com>", id)
					expected = true
				} else {
					header = fmt.Sprintf("<sip:other%d@example.com>", id)
					expected = false
				}

				result := IsSurveiled(header)
				results <- (result == expected)
			}
		}(i)
	}

	wg.Wait()
	close(results)

	// Check that all results are correct
	successCount := 0
	totalCount := 0
	for success := range results {
		if success {
			successCount++
		}
		totalCount++
	}

	assert.Equal(t, numGoroutines*checksPerGoroutine, totalCount, "Should have processed all checks")
	assert.Equal(t, totalCount, successCount, "All concurrent checks should have returned correct results")
}

func TestIsSurveiled_EmptyUserMap(t *testing.T) {
	// Test with empty user map
	ClearAll()

	tests := []string{
		"<sip:anyone@example.com>",
		"<sip:user@company.org>",
		"<sip:test@192.168.1.100:5060>",
		"",
	}

	for _, header := range tests {
		t.Run(fmt.Sprintf("Empty map with header: %s", header), func(t *testing.T) {
			result := IsSurveiled(header)
			assert.False(t, result, "IsSurveiled should return false when no users are being surveiled")
		})
	}
}
