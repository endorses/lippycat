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
