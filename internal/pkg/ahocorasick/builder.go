package ahocorasick

import (
	"strings"
)

// Builder constructs Aho-Corasick automata from patterns.
type Builder struct{}

// NewBuilder creates a new Builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// Build constructs an Aho-Corasick automaton from the given patterns.
// The build process has two phases:
//  1. Trie construction: Insert all patterns into a trie
//  2. Failure link computation: Use BFS to compute failure links for each state
//
// Time complexity: O(m) where m is the total length of all patterns.
// Space complexity: O(m) for the automaton states.
func (b *Builder) Build(patterns []Pattern) (*AhoCorasick, error) {
	ac := &AhoCorasick{
		states:         []state{newState()}, // Start with root state
		patterns:       make([]Pattern, len(patterns)),
		patternLengths: make([]int, len(patterns)),
	}

	// Copy patterns and record lengths
	copy(ac.patterns, patterns)
	for i, p := range patterns {
		ac.patternLengths[i] = len(p.Text)
	}

	// Phase 1: Build trie
	b.buildTrie(ac)

	// Phase 2: Compute failure links using BFS
	b.computeFailureLinks(ac)

	return ac, nil
}

// buildTrie inserts all patterns into the trie.
// Each pattern's text is converted to lowercase for case-insensitive matching.
func (b *Builder) buildTrie(ac *AhoCorasick) {
	for patternIdx, pattern := range ac.patterns {
		// Skip empty patterns - they would match at every position
		if pattern.Text == "" {
			continue
		}

		currentState := 0

		// Convert pattern to lowercase for case-insensitive matching
		textLower := strings.ToLower(pattern.Text)

		// Follow/create path for this pattern
		for _, char := range []byte(textLower) {
			// Check if transition exists
			if nextState, exists := ac.states[currentState].transitions[char]; exists {
				currentState = nextState
			} else {
				// Create new state
				newStateIdx := len(ac.states)
				ac.states = append(ac.states, newState())
				ac.states[currentState].transitions[char] = newStateIdx
				currentState = newStateIdx
			}
		}

		// Mark this state as an output state for this pattern
		ac.states[currentState].output = append(ac.states[currentState].output, patternIdx)
	}
}

// computeFailureLinks uses BFS to compute failure links for all states.
// The failure link for a state S points to the longest proper suffix of the
// path to S that is also a prefix of some pattern.
//
// This is the key insight of the Aho-Corasick algorithm: when a character
// doesn't match, instead of restarting from the root, we can jump to a
// state that represents the longest suffix that might still lead to a match.
func (b *Builder) computeFailureLinks(ac *AhoCorasick) {
	// BFS queue - start with all states directly reachable from root
	queue := make([]int, 0, len(ac.states))

	// Initialize: states at depth 1 have failure link to root
	for _, nextState := range ac.states[0].transitions {
		ac.states[nextState].failure = 0
		queue = append(queue, nextState)
	}

	// BFS to compute failure links for remaining states
	for len(queue) > 0 {
		currentState := queue[0]
		queue = queue[1:]

		// Process all transitions from current state
		for char, nextState := range ac.states[currentState].transitions {
			queue = append(queue, nextState)

			// Find failure state: follow failure links until we find a state
			// that has a transition for 'char', or reach root
			failState := ac.states[currentState].failure
			for failState != 0 {
				if _, exists := ac.states[failState].transitions[char]; exists {
					break
				}
				failState = ac.states[failState].failure
			}

			// Set failure link
			if target, exists := ac.states[failState].transitions[char]; exists && target != nextState {
				ac.states[nextState].failure = target
			} else {
				ac.states[nextState].failure = 0
			}

			// Merge outputs from failure state (suffix matches)
			// This ensures we report all patterns that end at this position
			failureState := ac.states[nextState].failure
			if len(ac.states[failureState].output) > 0 {
				ac.states[nextState].output = append(
					ac.states[nextState].output,
					ac.states[failureState].output...,
				)
			}
		}
	}
}
