package phonematcher

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcher_Basic(t *testing.T) {
	m := New()

	// Empty matcher should not match anything
	matched, ok := m.Match("+49123456789")
	assert.False(t, ok)
	assert.Empty(t, matched)

	// Add patterns
	m.UpdatePatterns([]string{
		"49123456789",
		"49987654321",
		"1234567890",
	})

	assert.Equal(t, 3, m.Size())

	// Test exact suffix match
	matched, ok = m.Match("+49123456789")
	assert.True(t, ok)
	assert.Equal(t, "49123456789", matched)

	// Test with prefix (suffix matching)
	matched, ok = m.Match("0049123456789")
	assert.True(t, ok)
	assert.Equal(t, "49123456789", matched)

	// Test non-match
	matched, ok = m.Match("+49111111111")
	assert.False(t, ok)
	assert.Empty(t, matched)
}

func TestMatcher_SuffixMatching(t *testing.T) {
	m := New()
	m.UpdatePatterns([]string{
		"123456789",  // 9 digits - below default min length, won't match
		"1234567890", // 10 digits
	})

	tests := []struct {
		name     string
		observed string
		wantOK   bool
		want     string
	}{
		// Exact match
		{"exact match", "1234567890", true, "1234567890"},

		// Suffix match with various prefixes
		{"with +", "+1234567890", true, "1234567890"},
		{"with 00", "001234567890", true, "1234567890"},
		{"with routing prefix", "7581234567890", true, "1234567890"},

		// SIP URI format
		{"sip URI", "sip:+1234567890@domain.com", true, "1234567890"},
		{"tel URI", "tel:+1234567890", true, "1234567890"},

		// Non-matches
		{"too short", "12345678", false, ""},
		{"different number", "9876543210", false, ""},
		{"partial overlap", "1234567899", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, ok := m.Match(tt.observed)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.want, matched)
			}
		})
	}
}

func TestMatcher_LongestMatchWins(t *testing.T) {
	m := NewWithMinLength(8)
	m.UpdatePatterns([]string{
		"12345678",   // 8 digits
		"9912345678", // 10 digits (longer, same suffix)
		"4499123456", // 10 digits (different)
	})

	// When observed ends with both patterns, longest should win
	matched, ok := m.Match("009912345678")
	assert.True(t, ok)
	assert.Equal(t, "9912345678", matched, "should match longer pattern")

	// Shorter pattern still works when longer doesn't match
	matched, ok = m.Match("+12345678")
	assert.True(t, ok)
	assert.Equal(t, "12345678", matched)
}

func TestMatcher_MinLength(t *testing.T) {
	// Test with custom min length
	m := NewWithMinLength(8)
	m.UpdatePatterns([]string{
		"12345",    // 5 digits - below min
		"12345678", // 8 digits - at min
	})

	// Short pattern is in watchlist but observed is too short
	_, ok := m.Match("12345")
	assert.False(t, ok, "should not match when observed is below min length")

	// Pattern at min length should match
	matched, ok := m.Match("+12345678")
	assert.True(t, ok)
	assert.Equal(t, "12345678", matched)
}

func TestMatcher_UpdatePatterns(t *testing.T) {
	m := New()

	// Initial patterns
	m.UpdatePatterns([]string{"49123456789"})
	_, ok := m.Match("+49123456789")
	assert.True(t, ok)

	// Update with different patterns
	m.UpdatePatterns([]string{"49987654321"})
	_, ok = m.Match("+49123456789")
	assert.False(t, ok, "old pattern should not match after update")
	_, ok = m.Match("+49987654321")
	assert.True(t, ok, "new pattern should match")

	// Clear patterns
	m.UpdatePatterns(nil)
	assert.Equal(t, 0, m.Size())
	_, ok = m.Match("+49987654321")
	assert.False(t, ok, "should not match with empty watchlist")
}

func TestMatcher_MatchWithDetails(t *testing.T) {
	m := New()
	m.UpdatePatterns([]string{"49123456789"})

	result, ok := m.MatchWithDetails("sip:+49123456789@gateway.com")
	require.True(t, ok)
	assert.Equal(t, "49123456789", result.Matched)
	assert.Equal(t, "49123456789", result.Observed)

	// With prefix
	result, ok = m.MatchWithDetails("00749123456789")
	require.True(t, ok)
	assert.Equal(t, "49123456789", result.Matched)
	assert.Equal(t, "00749123456789", result.Observed)
}

func TestMatcher_MatchBatch(t *testing.T) {
	m := New()
	m.UpdatePatterns([]string{
		"49123456789",
		"49111111111",
	})

	observed := []string{
		"+49123456789",
		"+49999999999",
		"sip:+49111111111@domain.com",
		"+49222222222",
	}

	results := m.MatchBatch(observed)

	assert.Equal(t, []bool{true, false, true, false}, results)
}

func TestMatcher_Lengths(t *testing.T) {
	m := New()
	m.UpdatePatterns([]string{
		"1234567890",   // 10 digits
		"12345678901",  // 11 digits
		"123456789012", // 12 digits
		"9876543210",   // 10 digits (duplicate length)
	})

	lengths := m.Lengths()
	assert.Equal(t, []int{12, 11, 10}, lengths, "lengths should be sorted descending")
}

func TestMatcher_ConcurrentAccess(t *testing.T) {
	m := New()
	m.UpdatePatterns([]string{"49123456789"})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			m.Match("+49123456789")
		}
		close(done)
	}()

	// Update patterns while matching
	for i := 0; i < 100; i++ {
		m.UpdatePatterns([]string{fmt.Sprintf("4912345678%d", i%10)})
	}

	<-done
}

// Benchmarks

func BenchmarkMatcher_Match_NoMatch(b *testing.B) {
	m := New()
	patterns := generatePhoneNumbers(10000)
	m.UpdatePatterns(patterns)

	// Use a number that definitely doesn't match
	observed := "+11111111111"

	b.ResetTimer()
	for b.Loop() {
		m.Match(observed)
	}
}

func BenchmarkMatcher_Match_Hit(b *testing.B) {
	m := New()
	patterns := generatePhoneNumbers(10000)
	m.UpdatePatterns(patterns)

	// Use a number that matches (last pattern)
	observed := "+" + patterns[len(patterns)-1]

	b.ResetTimer()
	for b.Loop() {
		m.Match(observed)
	}
}

func BenchmarkMatcher_Match_SIPUri(b *testing.B) {
	m := New()
	patterns := generatePhoneNumbers(10000)
	m.UpdatePatterns(patterns)

	observed := "sip:+" + patterns[5000] + "@gateway.example.com"

	b.ResetTimer()
	for b.Loop() {
		m.Match(observed)
	}
}

func BenchmarkMatcher_MatchBatch(b *testing.B) {
	m := New()
	patterns := generatePhoneNumbers(10000)
	m.UpdatePatterns(patterns)

	// Mix of matching and non-matching
	observed := make([]string, 100)
	for i := range observed {
		if i%10 == 0 {
			observed[i] = "+" + patterns[i*100]
		} else {
			observed[i] = "+1111111111" + fmt.Sprint(i)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		m.MatchBatch(observed)
	}
}

func BenchmarkMatcher_UpdatePatterns(b *testing.B) {
	m := New()

	for _, size := range []int{100, 1000, 10000} {
		patterns := generatePhoneNumbers(size)
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			for b.Loop() {
				m.UpdatePatterns(patterns)
			}
		})
	}
}

// Comparative benchmarks at different watchlist sizes
func BenchmarkMatcher_ScaleNoMatch(b *testing.B) {
	for _, size := range []int{100, 1000, 10000, 50000} {
		b.Run(fmt.Sprintf("watchlist_%d", size), func(b *testing.B) {
			m := New()
			patterns := generatePhoneNumbers(size)
			m.UpdatePatterns(patterns)

			observed := "+11111111111" // Non-matching

			b.ResetTimer()
			for b.Loop() {
				m.Match(observed)
			}
		})
	}
}

func BenchmarkMatcher_ScaleMatch(b *testing.B) {
	for _, size := range []int{100, 1000, 10000, 50000} {
		b.Run(fmt.Sprintf("watchlist_%d", size), func(b *testing.B) {
			m := New()
			patterns := generatePhoneNumbers(size)
			m.UpdatePatterns(patterns)

			observed := "+" + patterns[size/2] // Matching

			b.ResetTimer()
			for b.Loop() {
				m.Match(observed)
			}
		})
	}
}

// Helper to generate realistic phone numbers
func generatePhoneNumbers(count int) []string {
	rng := rand.New(rand.NewSource(42))
	countryCodes := []string{"49", "44", "1", "33", "39", "34"}

	patterns := make([]string, count)
	seen := make(map[string]struct{})

	for i := 0; i < count; {
		cc := countryCodes[rng.Intn(len(countryCodes))]
		// Generate 8-10 digit subscriber number
		subLen := 8 + rng.Intn(3)
		sub := ""
		for j := 0; j < subLen; j++ {
			sub += fmt.Sprint(rng.Intn(10))
		}
		num := cc + sub
		if _, exists := seen[num]; !exists {
			seen[num] = struct{}{}
			patterns[i] = num
			i++
		}
	}

	return patterns
}
