// Package filtering provides pattern matching utilities for SIP user and phone number filters.
package filtering

import "strings"

// PatternType represents the type of pattern matching to perform.
type PatternType int

const (
	// PatternTypeContains matches if the pattern is found anywhere in the string.
	// This is the default for patterns without wildcards (backward compatible).
	PatternTypeContains PatternType = iota
	// PatternTypePrefix matches if the string starts with the pattern.
	PatternTypePrefix
	// PatternTypeSuffix matches if the string ends with the pattern.
	PatternTypeSuffix
)

// ParsePattern parses a pattern string and returns the pattern with wildcards
// stripped and the detected pattern type.
//
// Pattern syntax:
//   - "alice"    -> PatternTypeContains (substring match, backward compatible)
//   - "*456789"  -> PatternTypeSuffix (matches any prefix + 456789)
//   - "alice*"   -> PatternTypePrefix (matches alice + any suffix)
//   - "*alice*"  -> PatternTypeContains (explicit contains)
//   - "\\*alice" -> PatternTypeContains with literal "*" (escaped asterisk)
//
// Escape sequences:
//   - "\\*" is unescaped to a literal "*" character
func ParsePattern(input string) (pattern string, patternType PatternType) {
	if input == "" {
		return "", PatternTypeContains
	}

	// First, handle escape sequences by replacing \* with a placeholder,
	// then process wildcards, then restore the placeholder as literal *
	const placeholder = "\x00" // NUL byte as placeholder (won't appear in user input)

	// Replace escaped asterisks with placeholder
	working := strings.ReplaceAll(input, `\*`, placeholder)

	// Detect pattern type based on unescaped asterisks
	hasLeadingWildcard := strings.HasPrefix(working, "*")
	hasTrailingWildcard := strings.HasSuffix(working, "*")

	switch {
	case hasLeadingWildcard && hasTrailingWildcard:
		// *pattern* -> contains (strip both)
		patternType = PatternTypeContains
		working = strings.TrimPrefix(working, "*")
		working = strings.TrimSuffix(working, "*")
	case hasLeadingWildcard:
		// *pattern -> suffix match
		patternType = PatternTypeSuffix
		working = strings.TrimPrefix(working, "*")
	case hasTrailingWildcard:
		// pattern* -> prefix match
		patternType = PatternTypePrefix
		working = strings.TrimSuffix(working, "*")
	default:
		// no wildcards -> contains (backward compatible)
		patternType = PatternTypeContains
	}

	// Restore escaped asterisks as literal *
	pattern = strings.ReplaceAll(working, placeholder, "*")

	return pattern, patternType
}

// NormalizePhonePattern normalizes a phone number pattern by:
//  1. Extracting only digits (stripping +, spaces, dashes, URI prefixes)
//  2. Stripping common international dialing prefixes (00, 011)
//
// This allows users to input phone numbers in various formats:
//   - +49123456789   → 49123456789
//   - 0049123456789  → 49123456789
//   - 011149123456   → 149123456  (US international prefix to country code 1)
//   - tel:+49123456  → 49123456
//
// Wildcards are preserved:
//   - *456789       → *456789 (suffix match)
//   - 0049*         → 49* (prefix match with normalized digits)
//
// The function returns the original pattern unchanged if it doesn't look
// like a phone number (e.g., contains letters).
func NormalizePhonePattern(pattern string) string {
	if pattern == "" {
		return ""
	}

	// Parse wildcards first
	hasLeadingWildcard := strings.HasPrefix(pattern, "*")
	hasTrailingWildcard := strings.HasSuffix(pattern, "*")

	// Strip wildcards for processing
	working := pattern
	if hasLeadingWildcard {
		working = strings.TrimPrefix(working, "*")
	}
	if hasTrailingWildcard {
		working = strings.TrimSuffix(working, "*")
	}

	// Extract digits from the pattern (handles tel:, sip:, +, spaces, etc.)
	digits := extractDigits(working)

	// If no digits extracted or pattern has non-digit/non-wildcard chars that matter,
	// return original (might be a username like "alice")
	if digits == "" && working != "" {
		return pattern
	}

	// Strip common international dialing prefixes
	// Order matters: check longer prefixes first
	switch {
	case strings.HasPrefix(digits, "011"):
		// North American international prefix (011 + country code)
		digits = strings.TrimPrefix(digits, "011")
	case strings.HasPrefix(digits, "00"):
		// European/ITU international prefix (00 + country code)
		digits = strings.TrimPrefix(digits, "00")
	}

	// Reconstruct with wildcards
	if hasLeadingWildcard {
		digits = "*" + digits
	}
	if hasTrailingWildcard {
		digits = digits + "*"
	}

	return digits
}

// extractDigits extracts only digit characters from a string.
// Handles common phone number formats:
//   - tel:+49123456789 → 49123456789
//   - sip:+49123456789@domain.com → 49123456789
//   - +49 123 456 789 → 49123456789
func extractDigits(input string) string {
	if input == "" {
		return ""
	}

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
	var result strings.Builder
	result.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			result.WriteByte(c)
		}
	}

	return result.String()
}

// Match checks if the given value matches the pattern according to the pattern type.
// Matching is case-insensitive.
func Match(value, pattern string, patternType PatternType) bool {
	if pattern == "" {
		return true // Empty pattern matches everything
	}

	valueLower := strings.ToLower(value)
	patternLower := strings.ToLower(pattern)

	switch patternType {
	case PatternTypePrefix:
		return strings.HasPrefix(valueLower, patternLower)
	case PatternTypeSuffix:
		return strings.HasSuffix(valueLower, patternLower)
	case PatternTypeContains:
		return strings.Contains(valueLower, patternLower)
	default:
		return strings.Contains(valueLower, patternLower)
	}
}
