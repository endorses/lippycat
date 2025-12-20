package ahocorasick

import (
	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// MultiModeAC provides optimized pattern matching using separate automata
// for different pattern types (contains, prefix, suffix).
//
// The key optimization is for suffix matching: instead of scanning the entire
// input and checking if matches end at the input length, we reverse both
// patterns and inputs. This transforms suffix matching into prefix matching,
// which is naturally efficient for AC automata (match at offset 0).
//
// Example:
//   - Suffix pattern "*456789" matches "+49123456789"
//   - Reversed: "987654" matches "987654321094+" at offset 0
type MultiModeAC struct {
	// containsAC matches patterns that can appear anywhere in the input.
	containsAC *AhoCorasick

	// prefixAC matches patterns that must appear at the start of the input.
	prefixAC *AhoCorasick

	// suffixAC matches REVERSED patterns against REVERSED inputs.
	// A suffix match becomes a prefix match when both are reversed.
	suffixAC *AhoCorasick

	// patterns stores all original patterns for ID lookup.
	patterns []Pattern

	// containsPatterns stores indices of contains patterns.
	containsPatterns []int

	// prefixPatterns stores indices of prefix patterns.
	prefixPatterns []int

	// suffixPatterns stores indices of suffix patterns.
	suffixPatterns []int
}

// NewMultiModeAC creates a new MultiModeAC matcher.
func NewMultiModeAC() *MultiModeAC {
	return &MultiModeAC{}
}

// Build constructs the multi-mode automata from patterns.
// Patterns are partitioned by type and built into separate automata.
func (m *MultiModeAC) Build(patterns []Pattern) error {
	m.patterns = make([]Pattern, len(patterns))
	copy(m.patterns, patterns)

	// Partition patterns by type
	var containsPatterns, prefixPatterns, suffixPatterns []Pattern
	m.containsPatterns = nil
	m.prefixPatterns = nil
	m.suffixPatterns = nil

	for i, p := range patterns {
		switch p.Type {
		case filtering.PatternTypeContains:
			// For contains, we need to track the original pattern index
			containsPatterns = append(containsPatterns, Pattern{
				ID:   p.ID,
				Text: p.Text,
				Type: filtering.PatternTypeContains,
			})
			m.containsPatterns = append(m.containsPatterns, i)

		case filtering.PatternTypePrefix:
			prefixPatterns = append(prefixPatterns, Pattern{
				ID:   p.ID,
				Text: p.Text,
				Type: filtering.PatternTypeContains, // AC will match anywhere, we check offset=0
			})
			m.prefixPatterns = append(m.prefixPatterns, i)

		case filtering.PatternTypeSuffix:
			// Reverse the pattern for suffix matching
			suffixPatterns = append(suffixPatterns, Pattern{
				ID:   p.ID,
				Text: reverseString(p.Text),
				Type: filtering.PatternTypeContains, // AC will match anywhere, we check offset=0
			})
			m.suffixPatterns = append(m.suffixPatterns, i)
		}
	}

	// Build separate automata
	m.containsAC = &AhoCorasick{}
	if len(containsPatterns) > 0 {
		if err := m.containsAC.Build(containsPatterns); err != nil {
			return err
		}
	}

	m.prefixAC = &AhoCorasick{}
	if len(prefixPatterns) > 0 {
		if err := m.prefixAC.Build(prefixPatterns); err != nil {
			return err
		}
	}

	m.suffixAC = &AhoCorasick{}
	if len(suffixPatterns) > 0 {
		if err := m.suffixAC.Build(suffixPatterns); err != nil {
			return err
		}
	}

	return nil
}

// Match finds all patterns that match the input.
func (m *MultiModeAC) Match(input []byte) []MatchResult {
	if len(m.patterns) == 0 {
		return nil
	}

	var results []MatchResult

	// Contains matches - any position is valid
	if m.containsAC.PatternCount() > 0 {
		for _, match := range m.containsAC.Match(input) {
			originalIdx := m.containsPatterns[match.PatternIndex]
			results = append(results, MatchResult{
				PatternID:    m.patterns[originalIdx].ID,
				PatternIndex: originalIdx,
				Offset:       match.Offset,
			})
		}
	}

	// Prefix matches - must start at position 0
	if m.prefixAC.PatternCount() > 0 {
		for _, match := range m.prefixAC.Match(input) {
			originalIdx := m.prefixPatterns[match.PatternIndex]
			patternLen := len(m.patterns[originalIdx].Text)
			// Prefix must start at position 0
			if match.Offset == patternLen {
				results = append(results, MatchResult{
					PatternID:    m.patterns[originalIdx].ID,
					PatternIndex: originalIdx,
					Offset:       match.Offset,
				})
			}
		}
	}

	// Suffix matches - reverse input, match reversed patterns
	if m.suffixAC.PatternCount() > 0 {
		reversedInput := reverseBytes(input)
		for _, match := range m.suffixAC.Match(reversedInput) {
			originalIdx := m.suffixPatterns[match.PatternIndex]
			patternLen := len(m.patterns[originalIdx].Text)
			// Suffix in reversed input = prefix at position 0
			if match.Offset == patternLen {
				results = append(results, MatchResult{
					PatternID:    m.patterns[originalIdx].ID,
					PatternIndex: originalIdx,
					Offset:       len(input), // Original offset is at end
				})
			}
		}
	}

	return results
}

// MatchBatch matches multiple inputs against the patterns.
func (m *MultiModeAC) MatchBatch(inputs [][]byte) [][]MatchResult {
	results := make([][]MatchResult, len(inputs))
	for i, input := range inputs {
		results[i] = m.Match(input)
	}
	return results
}

// PatternCount returns the total number of patterns.
func (m *MultiModeAC) PatternCount() int {
	return len(m.patterns)
}

// reverseBytes returns a reversed copy of the byte slice.
func reverseBytes(b []byte) []byte {
	n := len(b)
	reversed := make([]byte, n)
	for i := 0; i < n; i++ {
		reversed[n-1-i] = b[i]
	}
	return reversed
}

// reverseString returns a reversed copy of the string.
func reverseString(s string) string {
	return string(reverseBytes([]byte(s)))
}
