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
	muSu.Lock()
	sipUserMap = make(map[string]*SipUser)
	muSu.Unlock()

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
			sipHeader: "From: <sip:alicent@example.com>;tag=123",
			expected:  true,
		},
		{
			name:      "Header contains robb",
			sipHeader: "To: <sip:robb@company.org>",
			expected:  true,
		},
		{
			name:      "Header contains charlie in URI",
			sipHeader: "Contact: <sip:charlie@192.168.1.100:5060>",
			expected:  true,
		},
		{
			name:      "Header contains alicent in display name",
			sipHeader: "From: Alicent Smith <sip:asmith@example.com>",
			expected:  true, // Case-insensitive matching finds "Alicent" when checking for "alicent"
		},
		{
			name:      "Header with multiple users - alicent",
			sipHeader: "Route: <sip:alicent@proxy1.example.com>, <sip:proxy2.example.com>",
			expected:  true,
		},
		{
			name:      "Header with no surveiled users",
			sipHeader: "From: <sip:eve@external.com>;tag=456",
			expected:  false,
		},
		{
			name:      "Empty header",
			sipHeader: "",
			expected:  false,
		},
		{
			name:      "Header with partial match (should match)",
			sipHeader: "From: <sip:alicent-backup@example.com>", // Contains "alicent"
			expected:  true,
		},
		{
			name:      "Header with case sensitivity",
			sipHeader: "From: <sip:ALICENT@example.com>",
			expected:  true,
		},
		{
			name: "Complex SIP header with robb",
			sipHeader: `Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhds
From: "Robb Jones" <sip:robb@bigcompany.com>;tag=1928301774
To: "Alicent Smith" <sip:alicent@atlanta.com>
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE`,
			expected: true, // Contains both "robb" and "alicent"
		},
		{
			name:      "Header with username as substring",
			sipHeader: "From: <sip:robby@example.com>",
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

func TestIsSurveiled_Concurrency(t *testing.T) {
	// Test concurrent access to IsSurveiled
	muSu.Lock()
	sipUserMap = make(map[string]*SipUser)
	sipUserMap["testuser"] = &SipUser{ExpirationDate: time.Now().Add(1 * time.Hour)}
	muSu.Unlock()

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
					header = fmt.Sprintf("From: <sip:testuser@example%d.com>", id)
					expected = true
				} else {
					header = fmt.Sprintf("From: <sip:other%d@example.com>", id)
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
	muSu.Lock()
	sipUserMap = make(map[string]*SipUser)
	muSu.Unlock()

	tests := []string{
		"From: <sip:anyone@example.com>",
		"To: <sip:user@company.org>",
		"Contact: <sip:test@192.168.1.100:5060>",
		"",
	}

	for _, header := range tests {
		t.Run(fmt.Sprintf("Empty map with header: %s", header), func(t *testing.T) {
			result := IsSurveiled(header)
			assert.False(t, result, "IsSurveiled should return false when no users are being surveiled")
		})
	}
}
