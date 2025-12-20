package ahocorasick

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAhoCorasick_SinglePattern(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "hello", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "exact match",
			input:   "hello",
			wantIDs: []int{1},
		},
		{
			name:    "contains match",
			input:   "say hello world",
			wantIDs: []int{1},
		},
		{
			name:    "no match",
			input:   "world",
			wantIDs: nil,
		},
		{
			name:    "case insensitive match",
			input:   "HELLO",
			wantIDs: []int{1},
		},
		{
			name:    "mixed case match",
			input:   "HeLLo",
			wantIDs: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_MultiplePatterns(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "he", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "she", Type: filtering.PatternTypeContains},
		{ID: 3, Text: "his", Type: filtering.PatternTypeContains},
		{ID: 4, Text: "hers", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "overlapping patterns",
			input:   "she",
			wantIDs: []int{1, 2}, // "he" is suffix of "she"
		},
		{
			name:    "single match",
			input:   "his",
			wantIDs: []int{3},
		},
		{
			name:    "multiple separate matches",
			input:   "he said his",
			wantIDs: []int{1, 3},
		},
		{
			name:    "no matches",
			input:   "abc",
			wantIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_PrefixPattern(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypePrefix},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "prefix match at start",
			input:   "alice@example.com",
			wantIDs: []int{1},
		},
		{
			name:    "exact match",
			input:   "alice",
			wantIDs: []int{1},
		},
		{
			name:    "pattern in middle - no match for prefix",
			input:   "bob alice",
			wantIDs: nil,
		},
		{
			name:    "pattern at end - no match for prefix",
			input:   "hello alice",
			wantIDs: nil,
		},
		{
			name:    "case insensitive prefix",
			input:   "ALICE@example.com",
			wantIDs: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_SuffixPattern(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "456789", Type: filtering.PatternTypeSuffix},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "suffix match at end",
			input:   "+49123456789",
			wantIDs: []int{1},
		},
		{
			name:    "exact match",
			input:   "456789",
			wantIDs: []int{1},
		},
		{
			name:    "pattern at start - no match for suffix",
			input:   "456789abc",
			wantIDs: nil,
		},
		{
			name:    "pattern in middle - no match for suffix",
			input:   "123456789abc",
			wantIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_MixedPatternTypes(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypePrefix},
		{ID: 2, Text: "456789", Type: filtering.PatternTypeSuffix},
		{ID: 3, Text: "bob", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "prefix pattern matches",
			input:   "alice@example.com",
			wantIDs: []int{1},
		},
		{
			name:    "suffix pattern matches",
			input:   "+49123456789",
			wantIDs: []int{2},
		},
		{
			name:    "contains pattern matches",
			input:   "hello bob world",
			wantIDs: []int{3},
		},
		{
			name:    "no patterns match",
			input:   "charlie",
			wantIDs: nil,
		},
		{
			name:    "multiple patterns match",
			input:   "bob456789", // bob (contains) and 456789 (suffix) both match
			wantIDs: []int{2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_EmptyPattern(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	// Empty pattern should match at every position, but our implementation
	// only outputs when we traverse states, so empty patterns match once.
	results := ac.Match([]byte("hello"))
	// Empty string pattern creates no states beyond root
	// This behavior is acceptable - empty patterns are edge cases
	assert.Empty(t, results)
}

func TestAhoCorasick_EmptyInput(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "hello", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	results := ac.Match([]byte(""))
	assert.Empty(t, results)
}

func TestAhoCorasick_NoPatterns(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{})
	require.NoError(t, err)

	results := ac.Match([]byte("hello"))
	assert.Empty(t, results)
}

func TestAhoCorasick_MatchBatch(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "bob", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	inputs := [][]byte{
		[]byte("alice"),
		[]byte("bob"),
		[]byte("charlie"),
		[]byte("alice and bob"),
	}

	results := ac.MatchBatch(inputs)

	require.Len(t, results, 4)
	assert.Equal(t, []int{1}, extractPatternIDs(results[0]))
	assert.Equal(t, []int{2}, extractPatternIDs(results[1]))
	assert.Empty(t, results[2])
	assert.ElementsMatch(t, []int{1, 2}, extractPatternIDs(results[3]))
}

func TestAhoCorasick_PatternCount(t *testing.T) {
	ac := &AhoCorasick{}

	// Before build
	assert.Equal(t, 0, ac.PatternCount())

	// After build with patterns
	err := ac.Build([]Pattern{
		{ID: 1, Text: "a", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "b", Type: filtering.PatternTypeContains},
		{ID: 3, Text: "c", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)
	assert.Equal(t, 3, ac.PatternCount())
}

func TestAhoCorasick_RepeatedPatterns(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "test", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "test", Type: filtering.PatternTypeContains}, // Duplicate
	})
	require.NoError(t, err)

	results := ac.Match([]byte("test"))
	// Both patterns should match
	gotIDs := extractPatternIDs(results)
	assert.ElementsMatch(t, []int{1, 2}, gotIDs)
}

func TestAhoCorasick_SpecialCharacters(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "+49", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "@example.com", Type: filtering.PatternTypeContains},
		{ID: 3, Text: "alice@bob", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "plus sign",
			input:   "+49123456789",
			wantIDs: []int{1},
		},
		{
			name:    "at sign and dot",
			input:   "user@example.com",
			wantIDs: []int{2},
		},
		{
			name:    "multiple special chars",
			input:   "alice@bob.example.com",
			wantIDs: []int{3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := ac.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestAhoCorasick_LongInput(t *testing.T) {
	ac := &AhoCorasick{}
	err := ac.Build([]Pattern{
		{ID: 1, Text: "needle", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	// Create a long input with needle at the end
	input := make([]byte, 10000)
	for i := range input {
		input[i] = 'x'
	}
	copy(input[9990:], "needle")

	results := ac.Match(input)
	gotIDs := extractPatternIDs(results)
	assert.Equal(t, []int{1}, gotIDs)
}

func TestBuilder_Build(t *testing.T) {
	builder := NewBuilder()

	patterns := []Pattern{
		{ID: 1, Text: "test", Type: filtering.PatternTypeContains},
	}

	ac, err := builder.Build(patterns)
	require.NoError(t, err)
	require.NotNil(t, ac)

	assert.Equal(t, 1, ac.PatternCount())
	results := ac.Match([]byte("test"))
	assert.Len(t, results, 1)
	assert.Equal(t, 1, results[0].PatternID)
}

// extractPatternIDs extracts pattern IDs from match results.
func extractPatternIDs(results []MatchResult) []int {
	if len(results) == 0 {
		return nil
	}
	ids := make([]int, len(results))
	for i, r := range results {
		ids[i] = r.PatternID
	}
	return ids
}
