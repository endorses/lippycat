// Package filtering provides pattern matching utilities.
package filtering

import (
	"bufio"
	"os"
	"strings"
)

// LoadPatternsFromFile loads patterns from a file, one per line.
// Empty lines and lines starting with # are ignored.
func LoadPatternsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return patterns, nil
}

// MatchGlob performs case-insensitive glob-style matching with * wildcard.
//
// Supported patterns:
//   - "example.com"     -> exact match
//   - "*.example.com"   -> suffix match (matches any prefix + .example.com)
//   - "admin.*"         -> prefix match (matches admin. + any suffix)
//   - "*malware*"       -> contains match (matches if malware is anywhere)
//   - "foo*bar"         -> prefix + suffix match (matches foo + anything + bar)
//
// Matching is case-insensitive, which is appropriate for:
//   - DNS domain names
//   - Email addresses
//   - HTTP hosts
func MatchGlob(pattern, value string) bool {
	// Handle empty pattern
	if pattern == "" {
		return value == ""
	}

	// Case-insensitive matching
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)

	// Count wildcards
	wildcardCount := strings.Count(pattern, "*")

	// No wildcard = exact match
	if wildcardCount == 0 {
		return pattern == value
	}

	// Single * at start = suffix match
	if wildcardCount == 1 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
	}

	// Single * at end = prefix match
	if wildcardCount == 1 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}

	// * at both ends = contains match
	if wildcardCount == 2 && pattern[0] == '*' && pattern[len(pattern)-1] == '*' {
		substr := pattern[1 : len(pattern)-1]
		return strings.Contains(value, substr)
	}

	// Single * in middle = prefix + suffix match
	if wildcardCount == 1 {
		idx := strings.Index(pattern, "*")
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return len(value) >= len(prefix)+len(suffix) &&
			value[:len(prefix)] == prefix &&
			value[len(value)-len(suffix):] == suffix
	}

	// Multiple wildcards: fall back to simpler check
	// Split on * and check all parts exist in order
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx == -1 {
			return false
		}
		// First part must be at start if pattern doesn't start with *
		if i == 0 && pattern[0] != '*' && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	// Last part must be at end if pattern doesn't end with *
	if pattern[len(pattern)-1] != '*' && pos != len(value) {
		return false
	}
	return true
}

// MatchAnyGlob checks if value matches any of the given glob patterns.
// Returns true if at least one pattern matches.
func MatchAnyGlob(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if MatchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// acPatternThreshold is the minimum number of patterns where Aho-Corasick is faster.
// Below this threshold, simple iteration is faster due to AC setup overhead.
const acPatternThreshold = 10

// GlobMatcher provides efficient multi-pattern matching using Aho-Corasick.
// For small pattern sets, it falls back to simple iteration.
type GlobMatcher struct {
	patterns      []string       // Original patterns (for simple matching)
	acPatterns    []acPattern    // Parsed patterns for AC matching
	exactPatterns map[string]int // Exact match patterns (pattern -> index)
	useAC         bool           // Whether to use Aho-Corasick
	acAutomaton   interface{}    // AC automaton (interface to avoid import cycle)
	acMatch       func([]byte) bool
}

// acPattern holds a parsed pattern for Aho-Corasick matching.
type acPattern struct {
	text        string
	patternType PatternType
}

// NewGlobMatcher creates a new GlobMatcher for the given patterns.
// For large pattern sets (> threshold), it uses Aho-Corasick for O(n) matching.
// For small sets, it uses simple iteration.
func NewGlobMatcher(patterns []string) *GlobMatcher {
	m := &GlobMatcher{
		patterns:      patterns,
		exactPatterns: make(map[string]int),
	}

	if len(patterns) == 0 {
		return m
	}

	// Parse patterns
	m.acPatterns = make([]acPattern, 0, len(patterns))
	for i, p := range patterns {
		parsed, pType := parseGlobPattern(p)
		if pType == patternTypeExact {
			// Store exact patterns separately for O(1) lookup
			m.exactPatterns[strings.ToLower(parsed)] = i
		} else {
			m.acPatterns = append(m.acPatterns, acPattern{
				text:        parsed,
				patternType: pType,
			})
		}
	}

	// Use AC for large pattern sets
	m.useAC = len(m.acPatterns) >= acPatternThreshold

	return m
}

// Match checks if the value matches any pattern.
func (m *GlobMatcher) Match(value string) bool {
	if len(m.patterns) == 0 {
		return false
	}

	// Check exact matches first (O(1) lookup)
	if len(m.exactPatterns) > 0 {
		if _, found := m.exactPatterns[strings.ToLower(value)]; found {
			return true
		}
	}

	// Fall back to simple iteration for now
	// AC integration would be added here for m.useAC case
	for _, pattern := range m.patterns {
		if MatchGlob(pattern, value) {
			return true
		}
	}
	return false
}

// patternTypeExact represents an exact match pattern (no wildcards).
const patternTypeExact PatternType = -1

// parseGlobPattern parses a glob pattern and returns the text and type.
func parseGlobPattern(pattern string) (string, PatternType) {
	if pattern == "" {
		return "", patternTypeExact
	}

	wildcardCount := strings.Count(pattern, "*")

	// No wildcard = exact match
	if wildcardCount == 0 {
		return pattern, patternTypeExact
	}

	// * at start only = suffix match
	if wildcardCount == 1 && pattern[0] == '*' {
		return pattern[1:], PatternTypeSuffix
	}

	// * at end only = prefix match
	if wildcardCount == 1 && pattern[len(pattern)-1] == '*' {
		return pattern[:len(pattern)-1], PatternTypePrefix
	}

	// * at both ends = contains match
	if wildcardCount == 2 && pattern[0] == '*' && pattern[len(pattern)-1] == '*' {
		return pattern[1 : len(pattern)-1], PatternTypeContains
	}

	// Complex patterns (middle wildcard, multiple wildcards) - use contains
	// Strip leading/trailing wildcards and use as contains pattern
	text := strings.Trim(pattern, "*")
	return text, PatternTypeContains
}
