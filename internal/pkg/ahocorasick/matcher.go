// Package ahocorasick provides an implementation of the Aho-Corasick string matching algorithm.
// The Aho-Corasick algorithm allows matching multiple patterns simultaneously against an input
// string in O(n + m + z) time, where n is the input length, m is the total pattern length,
// and z is the number of matches.
//
// This implementation is designed for high-performance pattern matching in network traffic
// analysis, supporting thousands to hundreds of thousands of patterns efficiently.
package ahocorasick

import "github.com/endorses/lippycat/internal/pkg/filtering"

// Pattern represents a pattern to be matched by the Aho-Corasick automaton.
type Pattern struct {
	// ID is a unique identifier for this pattern, returned in match results.
	ID int

	// Text is the pattern text to match (without wildcards).
	Text string

	// Type specifies how the pattern should be matched (prefix, suffix, contains).
	Type filtering.PatternType
}

// MatchResult represents a match found by the automaton.
type MatchResult struct {
	// PatternID is the ID of the matched pattern.
	PatternID int

	// PatternIndex is the index of the pattern in the original pattern slice.
	PatternIndex int

	// Offset is the byte offset in the input where the match ends.
	// For prefix patterns, this is validated to be equal to the pattern length.
	// For suffix patterns, this is validated to be at the end of the input.
	Offset int
}

// Matcher is the interface for pattern matching implementations.
// Both linear scan and Aho-Corasick implementations satisfy this interface.
type Matcher interface {
	// Build constructs the matcher from a set of patterns.
	// For Aho-Corasick, this builds the trie and computes failure links.
	// Returns an error if building fails.
	Build(patterns []Pattern) error

	// Match finds all patterns that match the input.
	// The input is matched case-insensitively.
	// Returns a slice of MatchResults, one for each matching pattern.
	Match(input []byte) []MatchResult

	// MatchBatch matches multiple inputs against the patterns.
	// This is more efficient for GPU implementations that benefit from batching.
	// Returns a slice of MatchResult slices, one per input.
	MatchBatch(inputs [][]byte) [][]MatchResult

	// PatternCount returns the number of patterns in the matcher.
	PatternCount() int
}
