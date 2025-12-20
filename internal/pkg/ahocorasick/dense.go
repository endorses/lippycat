package ahocorasick

import "github.com/endorses/lippycat/internal/pkg/filtering"

// DenseState represents a node in the Aho-Corasick automaton with a dense transition table.
// Using a fixed-size array for transitions provides O(1) lookup and better cache locality
// compared to the map-based sparse representation.
//
// Memory: 256*4 + 4 + 16 (slice header) ≈ 1044 bytes per state.
// For 10K patterns averaging 10 chars, expect ~100K states = ~100MB.
type DenseState struct {
	// transitions is a dense lookup table indexed by input byte.
	// -1 indicates no transition (must follow failure link).
	// Valid state indices are >= 0.
	transitions [256]int32

	// failure is the state to transition to when no match is found.
	failure int32

	// output contains the indices of patterns that match at this state.
	output []int
}

// DenseAhoCorasick is an Aho-Corasick automaton optimized for fast matching.
// It uses a dense state table representation for O(1) transitions and
// is designed for SIMD-accelerated matching.
type DenseAhoCorasick struct {
	// states is the automaton's dense state table.
	// State 0 is the root state.
	states []DenseState

	// patterns stores the original patterns for result reporting.
	patterns []Pattern

	// patternLengths stores the length of each pattern for offset calculation.
	patternLengths []int
}

// NewDenseAhoCorasick creates a new empty dense Aho-Corasick automaton.
func NewDenseAhoCorasick() *DenseAhoCorasick {
	return &DenseAhoCorasick{}
}

// newDenseState creates a new dense state with all transitions set to -1.
func newDenseState() DenseState {
	var s DenseState
	for i := range s.transitions {
		s.transitions[i] = -1
	}
	s.failure = 0
	return s
}

// Build constructs the dense automaton from patterns.
func (d *DenseAhoCorasick) Build(patterns []Pattern) error {
	d.patterns = make([]Pattern, len(patterns))
	copy(d.patterns, patterns)
	d.patternLengths = make([]int, len(patterns))
	for i, p := range patterns {
		d.patternLengths[i] = len(p.Text)
	}

	// Start with root state
	d.states = []DenseState{newDenseState()}

	// Phase 1: Build trie
	d.buildTrie()

	// Phase 2: Compute failure links
	d.computeFailureLinks()

	return nil
}

// buildTrie inserts all patterns into the trie.
func (d *DenseAhoCorasick) buildTrie() {
	for patternIdx, pattern := range d.patterns {
		if pattern.Text == "" {
			continue
		}

		currentState := int32(0)
		textBytes := []byte(pattern.Text)

		for _, char := range textBytes {
			// Convert to lowercase inline for case-insensitive matching
			if char >= 'A' && char <= 'Z' {
				char = char + 32
			}

			nextState := d.states[currentState].transitions[char]
			if nextState >= 0 {
				currentState = nextState
			} else {
				// Create new state
				newStateIdx := int32(len(d.states))
				d.states = append(d.states, newDenseState())
				d.states[currentState].transitions[char] = newStateIdx
				currentState = newStateIdx
			}
		}

		// Mark this state as an output state
		d.states[currentState].output = append(d.states[currentState].output, patternIdx)
	}
}

// computeFailureLinks uses BFS to compute failure links for all states.
func (d *DenseAhoCorasick) computeFailureLinks() {
	// BFS queue
	queue := make([]int32, 0, len(d.states))

	// Initialize: states at depth 1 have failure link to root
	for c := 0; c < 256; c++ {
		nextState := d.states[0].transitions[c]
		if nextState > 0 {
			d.states[nextState].failure = 0
			queue = append(queue, nextState)
		}
	}

	// BFS to compute failure links
	for len(queue) > 0 {
		currentState := queue[0]
		queue = queue[1:]

		for c := 0; c < 256; c++ {
			nextState := d.states[currentState].transitions[c]
			if nextState < 0 {
				continue
			}

			queue = append(queue, nextState)

			// Find failure state
			failState := d.states[currentState].failure
			for failState != 0 {
				if d.states[failState].transitions[c] >= 0 {
					break
				}
				failState = d.states[failState].failure
			}

			// Set failure link
			target := d.states[failState].transitions[c]
			if target >= 0 && target != nextState {
				d.states[nextState].failure = target
			} else {
				d.states[nextState].failure = 0
			}

			// Merge outputs from failure state
			failureState := d.states[nextState].failure
			if len(d.states[failureState].output) > 0 {
				d.states[nextState].output = append(
					d.states[nextState].output,
					d.states[failureState].output...,
				)
			}
		}
	}
}

// Match finds all patterns that match in the input.
// This uses the platform-optimized matchDense implementation.
func (d *DenseAhoCorasick) Match(input []byte) []MatchResult {
	return matchDense(d, input)
}

// MatchBatch matches multiple inputs against the patterns.
func (d *DenseAhoCorasick) MatchBatch(inputs [][]byte) [][]MatchResult {
	results := make([][]MatchResult, len(inputs))
	for i, input := range inputs {
		results[i] = d.Match(input)
	}
	return results
}

// PatternCount returns the number of patterns in the automaton.
func (d *DenseAhoCorasick) PatternCount() int {
	return len(d.patterns)
}

// validateMatch checks if a match result is valid based on pattern type.
func validateMatch(pattern Pattern, matchStart, matchEnd, inputLen int) bool {
	switch pattern.Type {
	case filtering.PatternTypePrefix:
		return matchStart == 0
	case filtering.PatternTypeSuffix:
		return matchEnd == inputLen
	case filtering.PatternTypeContains:
		return true
	}
	return false
}
