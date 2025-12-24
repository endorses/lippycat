package phonematcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeToDigits(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases
		{"empty", "", ""},
		{"digits only", "49123456789", "49123456789"},
		{"with plus", "+49123456789", "49123456789"},

		// TEL URI
		{"tel URI", "tel:+49123456789", "49123456789"},
		{"tel URI no plus", "tel:49123456789", "49123456789"},

		// SIP URI
		{"sip URI", "sip:+49123456789@domain.com", "49123456789"},
		{"sips URI", "sips:+49123456789@domain.com", "49123456789"},
		{"sip with params", "sip:+49123456789@domain.com;tag=abc123", "49123456789"},

		// Various formats
		{"with spaces", "+49 123 456 789", "49123456789"},
		{"with dashes", "+49-123-456-789", "49123456789"},
		{"with dots", "+49.123.456.789", "49123456789"},
		{"with parens", "(049) 123-456-789", "049123456789"},
		{"international prefix", "0049123456789", "0049123456789"},

		// Edge cases
		{"only separators", "+-.()", ""},
		{"letters mixed", "abc123def456", "123456"},
		{"URI in angle brackets", "<sip:+49123456789@domain.com>", "49123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeToDigits(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsDigitsOnly(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", false},
		{"123", true},
		{"0", true},
		{"49123456789", true},
		{"+49123456789", false},
		{"123abc", false},
		{" 123", false},
		{"123 ", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsDigitsOnly(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractUserPart(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple user", "alice", "alice"},
		{"user@domain", "alice@domain.com", "alice"},
		{"sip URI", "sip:alice@domain.com", "alice"},
		{"sips URI", "sips:alice@domain.com", "alice"},
		{"tel URI", "tel:+49123456789", "+49123456789"},
		{"with params", "sip:alice@domain.com;tag=xyz", "alice"},
		{"phone in sip", "sip:+49123456789@gateway.com", "+49123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractUserPart(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkNormalizeToDigits(b *testing.B) {
	inputs := []string{
		"+49123456789",
		"sip:+49123456789@domain.com",
		"tel:+49123456789",
		"0049-123-456-789",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, input := range inputs {
			NormalizeToDigits(input)
		}
	}
}
