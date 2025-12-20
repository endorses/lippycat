package ahocorasick

import (
	"bytes"

	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// Pattern type aliases for convenience.
const (
	PatternTypeContains = filtering.PatternTypeContains
	PatternTypePrefix   = filtering.PatternTypePrefix
	PatternTypeSuffix   = filtering.PatternTypeSuffix
)

// state represents a node in the Aho-Corasick automaton.
type state struct {
	// transitions maps input bytes to next states.
	// Using a map for sparse alphabets (common in username matching).
	transitions map[byte]int

	// failure is the state to transition to when no match is found.
	// This is the key insight of Aho-Corasick: instead of restarting,
	// jump to the longest proper suffix that is also a prefix.
	failure int

	// output contains the indices of patterns that match at this state.
	// Multiple patterns can match at the same position (e.g., "he" and "she").
	output []int
}

// AhoCorasick is an Aho-Corasick automaton for multi-pattern string matching.
// It supports O(n + m + z) matching where n is input length, m is total pattern
// length, and z is number of matches.
type AhoCorasick struct {
	// states is the automaton's state table.
	// State 0 is the root state.
	states []state

	// patterns stores the original patterns for result reporting.
	patterns []Pattern

	// patternLengths stores the length of each pattern for offset calculation.
	patternLengths []int
}

// newState creates a new state with initialized fields.
func newState() state {
	return state{
		transitions: make(map[byte]int),
		failure:     0,
		output:      nil,
	}
}

// Match finds all patterns that match in the input.
// Matching is performed case-insensitively.
func (ac *AhoCorasick) Match(input []byte) []MatchResult {
	if len(ac.states) == 0 {
		return nil
	}

	// Convert input to lowercase for case-insensitive matching.
	// We use bytes.ToLower which handles ASCII efficiently.
	inputLower := bytes.ToLower(input)

	var results []MatchResult
	currentState := 0

	for i, b := range inputLower {
		// Follow failure links until we find a transition or reach root
		for currentState != 0 && ac.states[currentState].transitions[b] == 0 {
			// Check if transition exists (0 could be valid root transition)
			if _, exists := ac.states[currentState].transitions[b]; exists {
				break
			}
			currentState = ac.states[currentState].failure
		}

		// Try to transition
		if nextState, exists := ac.states[currentState].transitions[b]; exists {
			currentState = nextState
		}
		// If no transition from root, stay at root (currentState remains 0)

		// Collect all outputs at this state.
		// Outputs from suffix links are already merged during build phase,
		// so we only need to check the current state.
		for _, patternIdx := range ac.states[currentState].output {
			// Calculate the offset where the match ends (position after last char)
			matchEnd := i + 1
			matchStart := matchEnd - ac.patternLengths[patternIdx]

			// Validate based on pattern type
			pattern := ac.patterns[patternIdx]
			switch pattern.Type {
			case PatternTypePrefix:
				// Prefix must start at position 0
				if matchStart != 0 {
					continue
				}
			case PatternTypeSuffix:
				// Suffix must end at the end of input
				if matchEnd != len(inputLower) {
					continue
				}
			case PatternTypeContains:
				// Contains matches anywhere - no additional validation
			}

			results = append(results, MatchResult{
				PatternID:    pattern.ID,
				PatternIndex: patternIdx,
				Offset:       matchEnd,
			})
		}
	}

	return results
}

// MatchBatch matches multiple inputs against the patterns.
// This is useful for batch processing and is more efficient for some backends.
func (ac *AhoCorasick) MatchBatch(inputs [][]byte) [][]MatchResult {
	results := make([][]MatchResult, len(inputs))
	for i, input := range inputs {
		results[i] = ac.Match(input)
	}
	return results
}

// PatternCount returns the number of patterns in the automaton.
func (ac *AhoCorasick) PatternCount() int {
	return len(ac.patterns)
}

// Build constructs the automaton from patterns.
// This delegates to the Builder for actual construction.
func (ac *AhoCorasick) Build(patterns []Pattern) error {
	builder := NewBuilder()
	built, err := builder.Build(patterns)
	if err != nil {
		return err
	}

	// Copy the built automaton
	ac.states = built.states
	ac.patterns = built.patterns
	ac.patternLengths = built.patternLengths

	return nil
}
