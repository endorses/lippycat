package ahocorasick

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiModeAC_ContainsOnly(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
		{ID: 1, Text: "hello", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "world", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "single match",
			input:   "hello",
			wantIDs: []int{1},
		},
		{
			name:    "both match",
			input:   "hello world",
			wantIDs: []int{1, 2},
		},
		{
			name:    "no match",
			input:   "foo bar",
			wantIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestMultiModeAC_PrefixOnly(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypePrefix},
		{ID: 2, Text: "bob", Type: filtering.PatternTypePrefix},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "prefix match",
			input:   "alice@example.com",
			wantIDs: []int{1},
		},
		{
			name:    "exact match",
			input:   "alice",
			wantIDs: []int{1},
		},
		{
			name:    "not at start",
			input:   "hello alice",
			wantIDs: nil,
		},
		{
			name:    "case insensitive",
			input:   "ALICE@example.com",
			wantIDs: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestMultiModeAC_SuffixOnly(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
		{ID: 1, Text: "456789", Type: filtering.PatternTypeSuffix},
		{ID: 2, Text: ".com", Type: filtering.PatternTypeSuffix},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		wantIDs []int
	}{
		{
			name:    "suffix match phone",
			input:   "+49123456789",
			wantIDs: []int{1},
		},
		{
			name:    "suffix match domain",
			input:   "example.com",
			wantIDs: []int{2},
		},
		{
			name:    "exact match",
			input:   "456789",
			wantIDs: []int{1},
		},
		{
			name:    "not at end",
			input:   "456789abc",
			wantIDs: nil,
		},
		{
			name:    "case insensitive",
			input:   "EXAMPLE.COM",
			wantIDs: []int{2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestMultiModeAC_MixedTypes(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
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
			name:    "prefix matches",
			input:   "alice@example.com",
			wantIDs: []int{1},
		},
		{
			name:    "suffix matches",
			input:   "+49123456789",
			wantIDs: []int{2},
		},
		{
			name:    "contains matches",
			input:   "hello bob world",
			wantIDs: []int{3},
		},
		{
			name:    "multiple types match",
			input:   "bob456789", // bob (contains) at start, 456789 (suffix) at end
			wantIDs: []int{2, 3},
		},
		{
			name:    "no match",
			input:   "charlie",
			wantIDs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := m.Match([]byte(tt.input))
			gotIDs := extractPatternIDs(results)
			assert.ElementsMatch(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestMultiModeAC_EmptyPatterns(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{})
	require.NoError(t, err)

	results := m.Match([]byte("hello"))
	assert.Empty(t, results)
	assert.Equal(t, 0, m.PatternCount())
}

func TestMultiModeAC_MatchBatch(t *testing.T) {
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypePrefix},
		{ID: 2, Text: "456789", Type: filtering.PatternTypeSuffix},
		{ID: 3, Text: "bob", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	inputs := [][]byte{
		[]byte("alice@example.com"),
		[]byte("+49123456789"),
		[]byte("hello bob world"),
		[]byte("charlie"),
	}

	results := m.MatchBatch(inputs)

	require.Len(t, results, 4)
	assert.Equal(t, []int{1}, extractPatternIDs(results[0]))
	assert.Equal(t, []int{2}, extractPatternIDs(results[1]))
	assert.Equal(t, []int{3}, extractPatternIDs(results[2]))
	assert.Empty(t, results[3])
}

func TestMultiModeAC_PatternCount(t *testing.T) {
	m := NewMultiModeAC()

	assert.Equal(t, 0, m.PatternCount())

	err := m.Build([]Pattern{
		{ID: 1, Text: "a", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "b", Type: filtering.PatternTypePrefix},
		{ID: 3, Text: "c", Type: filtering.PatternTypeSuffix},
	})
	require.NoError(t, err)

	assert.Equal(t, 3, m.PatternCount())
}

func TestMultiModeAC_ReversedSuffixOptimization(t *testing.T) {
	// This test verifies that suffix matching works correctly with
	// the reversed pattern optimization
	m := NewMultiModeAC()
	err := m.Build([]Pattern{
		{ID: 1, Text: "456789", Type: filtering.PatternTypeSuffix},
	})
	require.NoError(t, err)

	// The suffix automaton should contain the reversed pattern "987654"
	// When we match "+49123456789", we reverse it to "987654321094+"
	// and match "987654" at position 0 (which is a prefix match)

	results := m.Match([]byte("+49123456789"))
	require.Len(t, results, 1)
	assert.Equal(t, 1, results[0].PatternID)
}

func TestReverseBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "a"},
		{"ab", "ba"},
		{"hello", "olleh"},
		{"12345", "54321"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := reverseBytes([]byte(tt.input))
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "a"},
		{"hello", "olleh"},
		{"456789", "987654"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := reverseString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
