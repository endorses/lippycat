package phonematcher

import "strings"

// NormalizeToDigits extracts only digit characters from a phone number string.
// It handles various formats:
//   - tel:+49123456789 → 49123456789
//   - sip:+49123456789@domain.com → 49123456789
//   - +49 123 456 789 → 49123456789
//   - 0049-123-456-789 → 0049123456789
//   - (049) 123.456.789 → 049123456789
//
// The '+' prefix is stripped as it provides no matching value
// (we match suffixes, and + is always at the start).
func NormalizeToDigits(input string) string {
	if input == "" {
		return ""
	}

	// Pre-allocate for typical phone number length
	var result strings.Builder
	result.Grow(20)

	// Strip common URI prefixes
	s := input
	if idx := strings.Index(s, "tel:"); idx != -1 {
		s = s[idx+4:]
	} else if idx := strings.Index(s, "sip:"); idx != -1 {
		s = s[idx+4:]
	} else if idx := strings.Index(s, "sips:"); idx != -1 {
		s = s[idx+5:]
	}

	// Strip domain part (everything after @)
	if atIdx := strings.IndexByte(s, '@'); atIdx != -1 {
		s = s[:atIdx]
	}

	// Strip URI parameters (everything after ; or ?)
	if semiIdx := strings.IndexByte(s, ';'); semiIdx != -1 {
		s = s[:semiIdx]
	}
	if qIdx := strings.IndexByte(s, '?'); qIdx != -1 {
		s = s[:qIdx]
	}

	// Extract only digits
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			result.WriteByte(c)
		}
	}

	return result.String()
}

// IsDigitsOnly returns true if the string contains only ASCII digits.
func IsDigitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ExtractUserPart extracts the user part from a SIP URI.
// Examples:
//   - sip:alice@domain.com → alice
//   - sips:+49123456789@domain.com;tag=xyz → +49123456789
//   - tel:+49123456789 → +49123456789
//   - alice@domain.com → alice
//   - alice → alice
func ExtractUserPart(uri string) string {
	s := uri

	// Strip URI scheme
	if idx := strings.Index(s, "tel:"); idx != -1 {
		s = s[idx+4:]
	} else if idx := strings.Index(s, "sip:"); idx != -1 {
		s = s[idx+4:]
	} else if idx := strings.Index(s, "sips:"); idx != -1 {
		s = s[idx+5:]
	}

	// Strip domain part
	if atIdx := strings.IndexByte(s, '@'); atIdx != -1 {
		s = s[:atIdx]
	}

	// Strip URI parameters
	if semiIdx := strings.IndexByte(s, ';'); semiIdx != -1 {
		s = s[:semiIdx]
	}
	if qIdx := strings.IndexByte(s, '?'); qIdx != -1 {
		s = s[:qIdx]
	}

	return s
}
