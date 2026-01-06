package filtering

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedPattern string
		expectedType    PatternType
	}{
		// Contains patterns (no wildcards - backward compatible)
		{
			name:            "plain string is contains",
			input:           "alice",
			expectedPattern: "alice",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "phone number is contains",
			input:           "456789",
			expectedPattern: "456789",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "empty string",
			input:           "",
			expectedPattern: "",
			expectedType:    PatternTypeContains,
		},

		// Suffix patterns (*pattern)
		{
			name:            "leading wildcard is suffix",
			input:           "*456789",
			expectedPattern: "456789",
			expectedType:    PatternTypeSuffix,
		},
		{
			name:            "suffix with E.164 plus",
			input:           "*+49123456",
			expectedPattern: "+49123456",
			expectedType:    PatternTypeSuffix,
		},

		// Prefix patterns (pattern*)
		{
			name:            "trailing wildcard is prefix",
			input:           "alice*",
			expectedPattern: "alice",
			expectedType:    PatternTypePrefix,
		},
		{
			name:            "prefix with numbers",
			input:           "+4912*",
			expectedPattern: "+4912",
			expectedType:    PatternTypePrefix,
		},

		// Explicit contains (*pattern*)
		{
			name:            "both wildcards is contains",
			input:           "*alice*",
			expectedPattern: "alice",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "both wildcards with numbers",
			input:           "*456*",
			expectedPattern: "456",
			expectedType:    PatternTypeContains,
		},

		// Escaped asterisks
		{
			name:            "escaped leading asterisk",
			input:           `\*alice`,
			expectedPattern: "*alice",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "escaped trailing asterisk",
			input:           `alice\*`,
			expectedPattern: "alice*",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "escaped asterisk in middle",
			input:           `al\*ice`,
			expectedPattern: "al*ice",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "escaped with unescaped prefix wildcard",
			input:           `*\*31#`,
			expectedPattern: "*31#",
			expectedType:    PatternTypeSuffix,
		},
		{
			name:            "multiple escaped asterisks",
			input:           `\*31\*`,
			expectedPattern: "*31*",
			expectedType:    PatternTypeContains,
		},
		{
			name:            "escaped leading with unescaped trailing",
			input:           `\*alice*`,
			expectedPattern: "*alice",
			expectedType:    PatternTypePrefix,
		},
		{
			name:            "unescaped leading with escaped trailing",
			input:           `*alice\*`,
			expectedPattern: "alice*",
			expectedType:    PatternTypeSuffix,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, patternType := ParsePattern(tt.input)
			assert.Equal(t, tt.expectedPattern, pattern, "pattern mismatch")
			assert.Equal(t, tt.expectedType, patternType, "pattern type mismatch")
		})
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		pattern     string
		patternType PatternType
		expected    bool
	}{
		// Contains matching
		{
			name:        "contains match",
			value:       "sip:alice@example.com",
			pattern:     "alice",
			patternType: PatternTypeContains,
			expected:    true,
		},
		{
			name:        "contains no match",
			value:       "sip:bob@example.com",
			pattern:     "alice",
			patternType: PatternTypeContains,
			expected:    false,
		},
		{
			name:        "contains case insensitive",
			value:       "sip:ALICE@example.com",
			pattern:     "alice",
			patternType: PatternTypeContains,
			expected:    true,
		},

		// Prefix matching
		{
			name:        "prefix match",
			value:       "alice123",
			pattern:     "alice",
			patternType: PatternTypePrefix,
			expected:    true,
		},
		{
			name:        "prefix exact match",
			value:       "alice",
			pattern:     "alice",
			patternType: PatternTypePrefix,
			expected:    true,
		},
		{
			name:        "prefix no match",
			value:       "bobalice",
			pattern:     "alice",
			patternType: PatternTypePrefix,
			expected:    false,
		},
		{
			name:        "prefix case insensitive",
			value:       "ALICE123",
			pattern:     "alice",
			patternType: PatternTypePrefix,
			expected:    true,
		},

		// Suffix matching
		{
			name:        "suffix match E.164",
			value:       "+49123456789",
			pattern:     "456789",
			patternType: PatternTypeSuffix,
			expected:    true,
		},
		{
			name:        "suffix match 00-prefix",
			value:       "0049123456789",
			pattern:     "456789",
			patternType: PatternTypeSuffix,
			expected:    true,
		},
		{
			name:        "suffix match tech prefix",
			value:       "*31#+49123456789",
			pattern:     "456789",
			patternType: PatternTypeSuffix,
			expected:    true,
		},
		{
			name:        "suffix exact match",
			value:       "456789",
			pattern:     "456789",
			patternType: PatternTypeSuffix,
			expected:    true,
		},
		{
			name:        "suffix no match",
			value:       "456789123",
			pattern:     "456789",
			patternType: PatternTypeSuffix,
			expected:    false,
		},

		// Empty pattern
		{
			name:        "empty pattern matches anything",
			value:       "anything",
			pattern:     "",
			patternType: PatternTypeContains,
			expected:    true,
		},
		{
			name:        "empty pattern matches empty",
			value:       "",
			pattern:     "",
			patternType: PatternTypeContains,
			expected:    true,
		},

		// Empty value
		{
			name:        "empty value no match",
			value:       "",
			pattern:     "alice",
			patternType: PatternTypeContains,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Match(tt.value, tt.pattern, tt.patternType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePhonePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Empty and basic
		{"empty string", "", ""},
		{"already normalized", "49123456789", "49123456789"},

		// Plus prefix
		{"E.164 with plus", "+49123456789", "49123456789"},
		{"plus with spaces", "+49 123 456 789", "49123456789"},
		{"plus with dashes", "+49-123-456-789", "49123456789"},

		// European international prefix (00)
		{"00 prefix", "0049123456789", "49123456789"},
		{"00 prefix with spaces", "00 49 123 456 789", "49123456789"},
		{"00 prefix with dashes", "00-49-123-456-789", "49123456789"},

		// North American international prefix (011)
		{"011 prefix to Germany", "01149123456789", "49123456789"},
		{"011 prefix to UK", "011441234567890", "441234567890"},
		{"011 prefix clean", "0111234567890", "1234567890"},

		// URI formats
		{"tel URI with plus", "tel:+49123456789", "49123456789"},
		{"tel URI with 00", "tel:0049123456789", "49123456789"},
		{"sip URI", "sip:+49123456789@domain.com", "49123456789"},
		{"sip URI with 00", "sip:0049123456789@domain.com", "49123456789"},
		{"sips URI", "sips:+49123456789@domain.com;tag=xyz", "49123456789"},

		// Wildcards preserved
		{"suffix wildcard", "*456789", "*456789"},
		{"prefix wildcard with 00", "0049*", "49*"},
		{"prefix wildcard with plus", "+49*", "49*"},
		{"both wildcards", "*456*", "*456*"},
		{"suffix wildcard 00 prefix", "*0049123456789", "*49123456789"}, // normalizes after *

		// Non-phone patterns (usernames) - returned as-is
		{"username", "alice", "alice"},
		{"username with domain", "alice@domain.com", "alice@domain.com"},
		{"sip username", "sip:alice@domain.com", "sip:alice@domain.com"},
		{"username wildcard", "alice*", "alice*"},
		{"username suffix", "*alice", "*alice"},

		// Edge cases
		{"only plus", "+", "+"}, // No digits, returned as-is (might be a pattern)
		{"only 00", "00", ""},   // Digits only, prefix stripped
		{"only 011", "011", ""}, // Digits only, prefix stripped
		{"short number after 00", "001", "1"},
		{"mixed format", "(+49) 123-456 789", "49123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePhonePattern(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePhonePatternUserInputScenarios(t *testing.T) {
	// Test the specific user scenario: non-standardized phone numbers
	// User has: 0049123456789, 49123456789, +49123456789
	// All should normalize to: 49123456789

	inputs := []string{
		"0049123456789",     // European format
		"49123456789",       // Already normalized
		"+49123456789",      // E.164 format
		"+49 123 456 789",   // E.164 with spaces
		"00 49 123 456 789", // European with spaces
		"tel:+49123456789",  // tel: URI
	}

	expected := "49123456789"

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result := NormalizePhonePattern(input)
			assert.Equal(t, expected, result, "input %q should normalize to %q", input, expected)
		})
	}
}

func TestParsePatternAndMatch(t *testing.T) {
	// Integration tests: parse pattern then match
	tests := []struct {
		name     string
		input    string // raw pattern input from user
		value    string // value to match against
		expected bool
	}{
		// Backward compatible contains
		{
			name:     "plain substring match",
			input:    "alice",
			value:    "sip:alice@example.com",
			expected: true,
		},

		// Suffix matching for phone numbers
		{
			name:     "suffix match E.164 number",
			input:    "*456789",
			value:    "+49123456789",
			expected: true,
		},
		{
			name:     "suffix match 00-prefix number",
			input:    "*456789",
			value:    "0049123456789",
			expected: true,
		},
		{
			name:     "suffix match tech prefix number",
			input:    "*456789",
			value:    "*31#+49123456789",
			expected: true,
		},
		{
			name:     "suffix no match different ending",
			input:    "*456789",
			value:    "+49123456000",
			expected: false,
		},

		// Prefix matching
		{
			name:     "prefix match username",
			input:    "alice*",
			value:    "alice.smith",
			expected: true,
		},
		{
			name:     "prefix no match",
			input:    "alice*",
			value:    "bob.alice",
			expected: false,
		},

		// Escaped asterisk
		{
			name:     "prefix match with escaped asterisk (tech prefix)",
			input:    `\*31#*`,
			value:    "*31#+49123456",
			expected: true,
		},
		{
			name:     "suffix match ending with tech prefix",
			input:    `*\*31#`,
			value:    "suppress*31#",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, patternType := ParsePattern(tt.input)
			require.NotEmpty(t, pattern, "pattern should not be empty for non-empty input")
			result := Match(tt.value, pattern, patternType)
			assert.Equal(t, tt.expected, result)
		})
	}
}
