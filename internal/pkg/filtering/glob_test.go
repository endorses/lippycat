package filtering

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		// Empty patterns
		{"empty pattern with empty value", "", "", true},
		{"empty pattern with non-empty value", "", "example.com", false},

		// Exact match
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "EXAMPLE.COM", "example.com", true},
		{"exact no match", "example.com", "example.org", false},

		// Suffix match (*suffix)
		{"suffix match", "*.example.com", "www.example.com", true},
		{"suffix match exact", "*.example.com", ".example.com", true},
		{"suffix no match", "*.example.com", "example.com", false},
		{"suffix case insensitive", "*.EXAMPLE.COM", "www.example.com", true},

		// Prefix match (prefix*)
		{"prefix match", "admin.*", "admin.example.com", true},
		{"prefix match exact", "admin.*", "admin.", true},
		{"prefix no match", "admin.*", "user.example.com", false},
		{"prefix case insensitive", "ADMIN.*", "admin.example.com", true},

		// Contains match (*substr*)
		{"contains match", "*malware*", "this.has.malware.in.it", true},
		{"contains match start", "*malware*", "malware.domain.com", true},
		{"contains match end", "*malware*", "domain.malware", true},
		{"contains no match", "*malware*", "clean.domain.com", false},
		{"contains case insensitive", "*MALWARE*", "this.malware.com", true},

		// Middle wildcard (prefix*suffix)
		{"middle wildcard match", "foo*bar", "foobar", true},
		{"middle wildcard with content", "foo*bar", "fooXXXbar", true},
		{"middle wildcard no match prefix", "foo*bar", "bazXXXbar", false},
		{"middle wildcard no match suffix", "foo*bar", "fooXXXbaz", false},
		{"middle wildcard case insensitive", "FOO*BAR", "fooxxxbar", true},

		// DNS domain patterns
		{"dns wildcard subdomain", "*.example.com", "mail.example.com", true},
		{"dns wildcard subdomain nested", "*.example.com", "smtp.mail.example.com", true},
		{"dns exact domain no match wild", "*.example.com", "example.com", false},

		// Multiple wildcards
		{"multi wildcard", "*foo*bar*", "XXXfooYYYbarZZZ", true},
		{"multi wildcard tight", "*foo*bar*", "foobar", true},
		{"multi wildcard no match", "*foo*bar*", "fooXXX", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchGlob(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result,
				"MatchGlob(%q, %q) = %v, want %v",
				tt.pattern, tt.value, result, tt.expected)
		})
	}
}

func TestMatchAnyGlob(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		value    string
		expected bool
	}{
		{"no patterns", []string{}, "example.com", false},
		{"single pattern match", []string{"*.example.com"}, "www.example.com", true},
		{"single pattern no match", []string{"*.example.com"}, "example.org", false},
		{"multiple patterns first match", []string{"*.example.com", "*.example.org"}, "www.example.com", true},
		{"multiple patterns second match", []string{"*.example.com", "*.example.org"}, "www.example.org", true},
		{"multiple patterns no match", []string{"*.example.com", "*.example.org"}, "www.example.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchAnyGlob(tt.patterns, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGlobMatcher(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		value    string
		expected bool
	}{
		// Empty matcher
		{"no patterns", []string{}, "example.com", false},

		// Exact match (O(1) hash lookup)
		{"exact match", []string{"example.com"}, "example.com", true},
		{"exact match case insensitive", []string{"EXAMPLE.COM"}, "example.com", true},
		{"exact no match", []string{"example.com"}, "example.org", false},

		// Wildcard patterns
		{"suffix match", []string{"*.example.com"}, "www.example.com", true},
		{"prefix match", []string{"admin.*"}, "admin.example.com", true},
		{"contains match", []string{"*malware*"}, "has.malware.in.it", true},

		// Mixed patterns
		{"mixed exact and wildcard", []string{"example.com", "*.example.org"}, "www.example.org", true},
		{"mixed no match", []string{"example.com", "*.example.org"}, "www.example.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewGlobMatcher(tt.patterns)
			result := matcher.Match(tt.value)
			assert.Equal(t, tt.expected, result,
				"GlobMatcher.Match(%q) with patterns %v = %v, want %v",
				tt.value, tt.patterns, result, tt.expected)
		})
	}
}

func TestParseGlobPattern(t *testing.T) {
	tests := []struct {
		pattern      string
		expectedText string
		expectedType PatternType
	}{
		{"example.com", "example.com", patternTypeExact},
		{"*.example.com", ".example.com", PatternTypeSuffix},
		{"admin.*", "admin.", PatternTypePrefix},
		{"*malware*", "malware", PatternTypeContains},
		{"foo*bar", "foo*bar", PatternTypeContains}, // Complex pattern - middle wildcard kept
		{"", "", patternTypeExact},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			text, pType := parseGlobPattern(tt.pattern)
			assert.Equal(t, tt.expectedText, text, "text mismatch for %q", tt.pattern)
			assert.Equal(t, tt.expectedType, pType, "type mismatch for %q", tt.pattern)
		})
	}
}
