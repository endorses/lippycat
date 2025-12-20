package ahocorasick

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDenseAhoCorasick_Build(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "hello", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "world", Type: filtering.PatternTypeContains},
		{ID: 3, Text: "he", Type: filtering.PatternTypeContains},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	assert.Equal(t, 3, d.PatternCount())
	assert.Greater(t, len(d.states), 1) // Should have more than just root
}

func TestDenseAhoCorasick_Match_Contains(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "hello", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "world", Type: filtering.PatternTypeContains},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected []int // Pattern IDs expected
	}{
		{"no match", "foobar", nil},
		{"hello match", "say hello there", []int{1}},
		{"world match", "the world is big", []int{2}},
		{"both match", "hello world", []int{1, 2}},
		{"case insensitive", "HELLO WORLD", []int{1, 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := d.Match([]byte(tt.input))

			if tt.expected == nil {
				assert.Empty(t, results)
				return
			}

			ids := make([]int, len(results))
			for i, r := range results {
				ids[i] = r.PatternID
			}
			assert.ElementsMatch(t, tt.expected, ids)
		})
	}
}

func TestDenseAhoCorasick_Match_Prefix(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "+49", Type: filtering.PatternTypePrefix},
		{ID: 2, Text: "+1", Type: filtering.PatternTypePrefix},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{"no match", "123456", nil},
		{"+49 prefix", "+491234567890", []int{1}},
		{"+1 prefix", "+15551234567", []int{2}},
		{"+49 not at start", "call +491234567890", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := d.Match([]byte(tt.input))

			if tt.expected == nil {
				assert.Empty(t, results)
				return
			}

			ids := make([]int, len(results))
			for i, r := range results {
				ids[i] = r.PatternID
			}
			assert.ElementsMatch(t, tt.expected, ids)
		})
	}
}

func TestDenseAhoCorasick_Match_Suffix(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "@example.com", Type: filtering.PatternTypeSuffix},
		{ID: 2, Text: "@test.org", Type: filtering.PatternTypeSuffix},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{"no match", "user@other.net", nil},
		{"example.com suffix", "user@example.com", []int{1}},
		{"test.org suffix", "admin@test.org", []int{2}},
		{"suffix not at end", "user@example.com extra", nil},
		{"case insensitive", "USER@EXAMPLE.COM", []int{1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := d.Match([]byte(tt.input))

			if tt.expected == nil {
				assert.Empty(t, results)
				return
			}

			ids := make([]int, len(results))
			for i, r := range results {
				ids[i] = r.PatternID
			}
			assert.ElementsMatch(t, tt.expected, ids)
		})
	}
}

func TestDenseAhoCorasick_Match_Overlapping(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "he", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "her", Type: filtering.PatternTypeContains},
		{ID: 3, Text: "hero", Type: filtering.PatternTypeContains},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	results := d.Match([]byte("a hero emerges"))

	ids := make([]int, len(results))
	for i, r := range results {
		ids[i] = r.PatternID
	}

	// Should find all three overlapping patterns in "hero"
	assert.ElementsMatch(t, []int{1, 2, 3}, ids)
}

func TestDenseAhoCorasick_MatchBatch(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 2, Text: "bob", Type: filtering.PatternTypeContains},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	inputs := [][]byte{
		[]byte("alice is here"),
		[]byte("bob was there"),
		[]byte("nobody"),
	}

	results := d.MatchBatch(inputs)

	require.Len(t, results, 3)
	assert.Len(t, results[0], 1) // alice
	assert.Len(t, results[1], 1) // bob
	assert.Len(t, results[2], 0) // nobody
}

func TestDenseAhoCorasick_EmptyInput(t *testing.T) {
	patterns := []Pattern{
		{ID: 1, Text: "test", Type: filtering.PatternTypeContains},
	}

	d := NewDenseAhoCorasick()
	err := d.Build(patterns)
	require.NoError(t, err)

	results := d.Match([]byte{})
	assert.Empty(t, results)

	results = d.Match(nil)
	assert.Empty(t, results)
}

func TestDenseAhoCorasick_EmptyPatterns(t *testing.T) {
	d := NewDenseAhoCorasick()
	err := d.Build([]Pattern{})
	require.NoError(t, err)

	results := d.Match([]byte("test"))
	assert.Empty(t, results)
}

// BenchmarkDense compares Dense (SIMD-friendly) vs Original (map-based) AC.
func BenchmarkDense(b *testing.B) {
	patternCounts := []int{100, 1000, 10000}
	input := []byte("+49123456789012345")

	for _, count := range patternCounts {
		patterns := generatePatterns(count, filtering.PatternTypeContains)

		// Build dense automaton
		dense := NewDenseAhoCorasick()
		if err := dense.Build(patterns); err != nil {
			b.Fatal(err)
		}

		// Build original automaton
		original := &AhoCorasick{}
		if err := original.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("Dense/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = dense.Match(input)
			}
		})

		b.Run(fmt.Sprintf("Original/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = original.Match(input)
			}
		})
	}
}

// BenchmarkDense_LongInput measures performance with longer inputs.
func BenchmarkDense_LongInput(b *testing.B) {
	patterns := generatePatterns(1000, filtering.PatternTypeContains)

	// Create a longer input (typical SIP message excerpt)
	input := []byte("sip:+491234567890@example.com;user=phone INVITE sip:+4955512345@voip.example.com SIP/2.0")

	dense := NewDenseAhoCorasick()
	if err := dense.Build(patterns); err != nil {
		b.Fatal(err)
	}

	original := &AhoCorasick{}
	if err := original.Build(patterns); err != nil {
		b.Fatal(err)
	}

	b.Run("Dense/longInput", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dense.Match(input)
		}
	})

	b.Run("Original/longInput", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = original.Match(input)
		}
	})
}

// BenchmarkDense_Build measures build time.
func BenchmarkDense_Build(b *testing.B) {
	sizes := []int{100, 1000, 10000}

	for _, size := range sizes {
		patterns := generatePatterns(size, filtering.PatternTypeContains)

		b.Run(fmt.Sprintf("Dense/patterns=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				d := NewDenseAhoCorasick()
				_ = d.Build(patterns)
			}
		})

		b.Run(fmt.Sprintf("Original/patterns=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ac := &AhoCorasick{}
				_ = ac.Build(patterns)
			}
		})
	}
}

// BenchmarkDense_BatchMatching compares batch matching performance.
func BenchmarkDense_BatchMatching(b *testing.B) {
	patterns := generatePatterns(1000, filtering.PatternTypeContains)
	inputs := generateInputs(100, 20)

	dense := NewDenseAhoCorasick()
	if err := dense.Build(patterns); err != nil {
		b.Fatal(err)
	}

	original := &AhoCorasick{}
	if err := original.Build(patterns); err != nil {
		b.Fatal(err)
	}

	b.Run("Dense/batch100", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dense.MatchBatch(inputs)
		}
	})

	b.Run("Original/batch100", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = original.MatchBatch(inputs)
		}
	})
}
