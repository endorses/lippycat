package ahocorasick

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferedMatcher_BasicMatch(t *testing.T) {
	// Force aho-corasick algorithm to test automaton path
	bm := NewBufferedMatcherWithAlgorithm(AlgorithmAhoCorasick)

	patterns := []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 1, Text: "bob", Type: filtering.PatternTypeContains},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	assert.True(t, bm.HasAutomaton())
	assert.Equal(t, AlgorithmAhoCorasick, bm.GetSelectedAlgorithm())
	assert.Equal(t, 2, bm.PatternCount())

	// Test matching
	results := bm.Match([]byte("alice@example.com"))
	assert.Len(t, results, 1)
	assert.Equal(t, 0, results[0].PatternID)

	results = bm.Match([]byte("bob@example.com"))
	assert.Len(t, results, 1)
	assert.Equal(t, 1, results[0].PatternID)

	results = bm.Match([]byte("charlie@example.com"))
	assert.Len(t, results, 0)
}

func TestBufferedMatcher_MatchUsernames(t *testing.T) {
	bm := NewBufferedMatcher()

	patterns := []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 1, Text: "12345", Type: filtering.PatternTypeSuffix},
		{ID: 2, Text: "+49", Type: filtering.PatternTypePrefix},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	tests := []struct {
		name      string
		usernames []string
		want      bool
	}{
		{
			name:      "contains match in first username",
			usernames: []string{"alice", "bob", "charlie"},
			want:      true,
		},
		{
			name:      "suffix match",
			usernames: []string{"user12345"},
			want:      true,
		},
		{
			name:      "prefix match",
			usernames: []string{"+49123456789"},
			want:      true,
		},
		{
			name:      "no match",
			usernames: []string{"charlie", "dave"},
			want:      false,
		},
		{
			name:      "empty usernames",
			usernames: []string{},
			want:      false,
		},
		{
			name:      "empty string in usernames",
			usernames: []string{"", "alice"},
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bm.MatchUsernames(tt.usernames)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBufferedMatcher_LinearScanFallback(t *testing.T) {
	bm := NewBufferedMatcher()

	// Set patterns without building automaton (simulating during-build state)
	bm.patternsMu.Lock()
	bm.patterns = []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 1, Text: "456789", Type: filtering.PatternTypeSuffix},
	}
	bm.patternsMu.Unlock()

	// No automaton available
	assert.False(t, bm.HasAutomaton())

	// Should still match via linear scan
	results := bm.Match([]byte("alice@example.com"))
	assert.Len(t, results, 1)

	// Test suffix matching in linear scan
	results = bm.Match([]byte("+49123456789"))
	assert.Len(t, results, 1)
	assert.Equal(t, 1, results[0].PatternID)

	// MatchUsernames should also work
	assert.True(t, bm.MatchUsernames([]string{"alice"}))
	assert.True(t, bm.MatchUsernames([]string{"+49123456789"}))
	assert.False(t, bm.MatchUsernames([]string{"charlie"}))
}

func TestBufferedMatcher_ConcurrentReads(t *testing.T) {
	bm := NewBufferedMatcher()

	patterns := []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 1, Text: "bob", Type: filtering.PatternTypeContains},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	// Run concurrent reads
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				bm.Match([]byte("alice@example.com"))
				bm.MatchUsernames([]string{"alice", "bob"})
			}
		}()
	}
	wg.Wait()
}

func TestBufferedMatcher_ConcurrentUpdates(t *testing.T) {
	bm := NewBufferedMatcher()

	// Initial patterns
	err := bm.UpdatePatternsSync([]Pattern{
		{ID: 0, Text: "initial", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	// Run concurrent updates and reads
	var wg sync.WaitGroup

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bm.Match([]byte("test"))
				bm.MatchUsernames([]string{"test"})
			}
		}()
	}

	// Writers (updates)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				bm.UpdatePatterns([]Pattern{
					{ID: id*10 + j, Text: "pattern", Type: filtering.PatternTypeContains},
				})
				time.Sleep(time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

func TestBufferedMatcher_EmptyPatterns(t *testing.T) {
	bm := NewBufferedMatcher()

	err := bm.UpdatePatternsSync([]Pattern{})
	require.NoError(t, err)

	assert.Equal(t, 0, bm.PatternCount())
	assert.False(t, bm.HasAutomaton())

	// Empty patterns should not match anything
	results := bm.Match([]byte("test"))
	assert.Len(t, results, 0)

	assert.False(t, bm.MatchUsernames([]string{"test"}))
}

func TestBufferedMatcher_PatternTypes(t *testing.T) {
	bm := NewBufferedMatcher()

	patterns := []Pattern{
		{ID: 0, Text: "prefix", Type: filtering.PatternTypePrefix},
		{ID: 1, Text: "suffix", Type: filtering.PatternTypeSuffix},
		{ID: 2, Text: "contains", Type: filtering.PatternTypeContains},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	tests := []struct {
		input    string
		expected []int // Expected pattern IDs
	}{
		{"prefix_test", []int{0}},
		{"test_suffix", []int{1}},
		{"test_contains_here", []int{2}},
		{"no_match", []int{}},
		{"prefix", []int{0}},             // "prefix" matches prefix pattern only
		{"contains_word", []int{2}},      // matches contains pattern
		{"prefix_contains", []int{0, 2}}, // matches both prefix and contains
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			results := bm.Match([]byte(tt.input))
			ids := make([]int, len(results))
			for i, r := range results {
				ids[i] = r.PatternID
			}
			assert.ElementsMatch(t, tt.expected, ids)
		})
	}
}

func TestBufferedMatcher_CaseInsensitive(t *testing.T) {
	bm := NewBufferedMatcher()

	patterns := []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	// All case variations should match
	assert.True(t, bm.MatchUsernames([]string{"alice"}))
	assert.True(t, bm.MatchUsernames([]string{"ALICE"}))
	assert.True(t, bm.MatchUsernames([]string{"Alice"}))
	assert.True(t, bm.MatchUsernames([]string{"aLiCe"}))
}

func TestBufferedMatcher_Stats(t *testing.T) {
	// Force aho-corasick algorithm to test automaton stats
	bm := NewBufferedMatcherWithAlgorithm(AlgorithmAhoCorasick)

	// Initial stats
	stats := bm.GetStats()
	assert.Equal(t, 0, stats.PatternCount)
	assert.False(t, stats.HasAutomaton)
	assert.False(t, stats.IsBuilding)
	assert.Equal(t, AlgorithmAhoCorasick, stats.Algorithm)

	// After building
	err := bm.UpdatePatternsSync([]Pattern{
		{ID: 0, Text: "test", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	stats = bm.GetStats()
	assert.Equal(t, 1, stats.PatternCount)
	assert.True(t, stats.HasAutomaton)
	assert.False(t, stats.IsBuilding)
	assert.Greater(t, stats.StateCount, 0)
	assert.False(t, stats.LastBuildTime.IsZero())
	assert.Greater(t, stats.LastBuildDuration, time.Duration(0))
	assert.Equal(t, AlgorithmAhoCorasick, stats.AlgorithmSelected)
}

func TestBufferedMatcher_MatchBatch(t *testing.T) {
	bm := NewBufferedMatcher()

	patterns := []Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 1, Text: "bob", Type: filtering.PatternTypeContains},
	}

	err := bm.UpdatePatternsSync(patterns)
	require.NoError(t, err)

	inputs := [][]byte{
		[]byte("alice@example.com"),
		[]byte("bob@example.com"),
		[]byte("charlie@example.com"),
	}

	results := bm.MatchBatch(inputs)
	require.Len(t, results, 3)
	assert.Len(t, results[0], 1) // alice matches
	assert.Len(t, results[1], 1) // bob matches
	assert.Len(t, results[2], 0) // charlie doesn't match
}

func TestBufferedMatcher_UpdateReplacesPatterns(t *testing.T) {
	bm := NewBufferedMatcher()

	// Initial patterns
	err := bm.UpdatePatternsSync([]Pattern{
		{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	assert.True(t, bm.MatchUsernames([]string{"alice"}))
	assert.False(t, bm.MatchUsernames([]string{"bob"}))

	// Update with new patterns
	err = bm.UpdatePatternsSync([]Pattern{
		{ID: 1, Text: "bob", Type: filtering.PatternTypeContains},
	})
	require.NoError(t, err)

	// Old pattern should no longer match
	assert.False(t, bm.MatchUsernames([]string{"alice"}))
	// New pattern should match
	assert.True(t, bm.MatchUsernames([]string{"bob"}))
}

func TestBufferedMatcher_AlgorithmSelection(t *testing.T) {
	t.Run("auto with few patterns uses linear", func(t *testing.T) {
		bm := NewBufferedMatcher() // Default is auto

		err := bm.UpdatePatternsSync([]Pattern{
			{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
			{ID: 1, Text: "bob", Type: filtering.PatternTypeContains},
		})
		require.NoError(t, err)

		assert.Equal(t, AlgorithmAuto, bm.GetAlgorithm())
		assert.Equal(t, AlgorithmLinear, bm.GetSelectedAlgorithm())
		assert.False(t, bm.HasAutomaton())

		// Should still match via linear scan
		assert.True(t, bm.MatchUsernames([]string{"alice"}))
	})

	t.Run("auto with many patterns uses aho-corasick", func(t *testing.T) {
		bm := NewBufferedMatcher()

		// Create 150 patterns (above threshold of 100)
		patterns := make([]Pattern, 150)
		for i := 0; i < 150; i++ {
			patterns[i] = Pattern{
				ID:   i,
				Text: "pattern" + string(rune('a'+i%26)),
				Type: filtering.PatternTypeContains,
			}
		}

		err := bm.UpdatePatternsSync(patterns)
		require.NoError(t, err)

		assert.Equal(t, AlgorithmAuto, bm.GetAlgorithm())
		assert.Equal(t, AlgorithmAhoCorasick, bm.GetSelectedAlgorithm())
		assert.True(t, bm.HasAutomaton())
	})

	t.Run("forced linear scan", func(t *testing.T) {
		bm := NewBufferedMatcherWithAlgorithm(AlgorithmLinear)

		// Even with many patterns, should use linear scan
		patterns := make([]Pattern, 150)
		for i := 0; i < 150; i++ {
			patterns[i] = Pattern{
				ID:   i,
				Text: "pattern" + string(rune('a'+i%26)),
				Type: filtering.PatternTypeContains,
			}
		}

		err := bm.UpdatePatternsSync(patterns)
		require.NoError(t, err)

		assert.Equal(t, AlgorithmLinear, bm.GetAlgorithm())
		assert.Equal(t, AlgorithmLinear, bm.GetSelectedAlgorithm())
		assert.False(t, bm.HasAutomaton())

		// Should still match via linear scan
		assert.True(t, bm.MatchUsernames([]string{"patterna"}))
	})

	t.Run("forced aho-corasick", func(t *testing.T) {
		bm := NewBufferedMatcherWithAlgorithm(AlgorithmAhoCorasick)

		// Even with few patterns, should use AC
		err := bm.UpdatePatternsSync([]Pattern{
			{ID: 0, Text: "alice", Type: filtering.PatternTypeContains},
		})
		require.NoError(t, err)

		assert.Equal(t, AlgorithmAhoCorasick, bm.GetAlgorithm())
		assert.Equal(t, AlgorithmAhoCorasick, bm.GetSelectedAlgorithm())
		assert.True(t, bm.HasAutomaton())
	})

	t.Run("set algorithm after creation", func(t *testing.T) {
		bm := NewBufferedMatcher()
		bm.SetAlgorithm(AlgorithmLinear)

		err := bm.UpdatePatternsSync([]Pattern{
			{ID: 0, Text: "test", Type: filtering.PatternTypeContains},
		})
		require.NoError(t, err)

		assert.Equal(t, AlgorithmLinear, bm.GetAlgorithm())
		assert.Equal(t, AlgorithmLinear, bm.GetSelectedAlgorithm())
	})
}

// Benchmark concurrent reads during updates
func BenchmarkBufferedMatcher_ConcurrentReads(b *testing.B) {
	bm := NewBufferedMatcher()

	patterns := make([]Pattern, 1000)
	for i := 0; i < 1000; i++ {
		patterns[i] = Pattern{
			ID:   i,
			Text: "pattern" + string(rune('a'+i%26)),
			Type: filtering.PatternTypeContains,
		}
	}
	_ = bm.UpdatePatternsSync(patterns)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bm.MatchUsernames([]string{"patterna", "patternb", "patternz"})
		}
	})
}
