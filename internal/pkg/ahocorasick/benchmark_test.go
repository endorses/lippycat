package ahocorasick

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// linearScanMatch is a simple linear scan matcher for comparison.
type linearScanMatch struct {
	patterns []Pattern
}

func (l *linearScanMatch) Build(patterns []Pattern) error {
	l.patterns = patterns
	return nil
}

func (l *linearScanMatch) Match(input []byte) []MatchResult {
	inputLower := strings.ToLower(string(input))
	var results []MatchResult

	for i, p := range l.patterns {
		patternLower := strings.ToLower(p.Text)
		var matched bool

		switch p.Type {
		case filtering.PatternTypePrefix:
			matched = strings.HasPrefix(inputLower, patternLower)
		case filtering.PatternTypeSuffix:
			matched = strings.HasSuffix(inputLower, patternLower)
		case filtering.PatternTypeContains:
			matched = strings.Contains(inputLower, patternLower)
		}

		if matched {
			results = append(results, MatchResult{
				PatternID:    p.ID,
				PatternIndex: i,
			})
		}
	}
	return results
}

func (l *linearScanMatch) MatchBatch(inputs [][]byte) [][]MatchResult {
	results := make([][]MatchResult, len(inputs))
	for i, input := range inputs {
		results[i] = l.Match(input)
	}
	return results
}

func (l *linearScanMatch) PatternCount() int {
	return len(l.patterns)
}

// generatePatterns creates n random patterns for benchmarking.
func generatePatterns(n int, patternType filtering.PatternType) []Pattern {
	patterns := make([]Pattern, n)
	for i := 0; i < n; i++ {
		// Generate random phone number-like patterns (7-15 digits)
		length := 7 + rand.Intn(9)
		digits := make([]byte, length)
		for j := 0; j < length; j++ {
			digits[j] = '0' + byte(rand.Intn(10))
		}
		patterns[i] = Pattern{
			ID:   i,
			Text: string(digits),
			Type: patternType,
		}
	}
	return patterns
}

// generateInputs creates n random inputs for benchmarking.
func generateInputs(n int, maxLength int) [][]byte {
	inputs := make([][]byte, n)
	for i := 0; i < n; i++ {
		// Generate random phone number-like input
		length := 10 + rand.Intn(maxLength-10)
		input := make([]byte, length)
		// Start with + for international format
		input[0] = '+'
		for j := 1; j < length; j++ {
			input[j] = '0' + byte(rand.Intn(10))
		}
		inputs[i] = input
	}
	return inputs
}

// BenchmarkAhoCorasick_Build measures automaton build time at various pattern counts.
func BenchmarkAhoCorasick_Build(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000}

	for _, size := range sizes {
		patterns := generatePatterns(size, filtering.PatternTypeContains)

		b.Run(fmt.Sprintf("patterns=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ac := &AhoCorasick{}
				_ = ac.Build(patterns)
			}
		})
	}
}

// BenchmarkMatch compares AC vs linear scan at various pattern counts.
func BenchmarkMatch(b *testing.B) {
	patternCounts := []int{10, 50, 100, 500, 1000, 5000, 10000}
	input := []byte("+49123456789012345")

	for _, count := range patternCounts {
		patterns := generatePatterns(count, filtering.PatternTypeContains)

		// Build AC automaton
		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		// Build linear scanner
		linear := &linearScanMatch{}
		if err := linear.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("AC/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ac.Match(input)
			}
		})

		b.Run(fmt.Sprintf("Linear/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = linear.Match(input)
			}
		})
	}
}

// BenchmarkMatchBatch measures batch matching performance.
func BenchmarkMatchBatch(b *testing.B) {
	patternCounts := []int{100, 1000, 10000}
	batchSizes := []int{10, 100, 1000}

	for _, patternCount := range patternCounts {
		patterns := generatePatterns(patternCount, filtering.PatternTypeContains)

		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		linear := &linearScanMatch{}
		if err := linear.Build(patterns); err != nil {
			b.Fatal(err)
		}

		for _, batchSize := range batchSizes {
			inputs := generateInputs(batchSize, 20)

			b.Run(fmt.Sprintf("AC/patterns=%d/batch=%d", patternCount, batchSize), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = ac.MatchBatch(inputs)
				}
			})

			b.Run(fmt.Sprintf("Linear/patterns=%d/batch=%d", patternCount, batchSize), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = linear.MatchBatch(inputs)
				}
			})
		}
	}
}

// BenchmarkMatchPatternTypes measures performance across different pattern types.
func BenchmarkMatchPatternTypes(b *testing.B) {
	patternCount := 1000
	input := []byte("+49123456789012345")

	types := []struct {
		name string
		typ  filtering.PatternType
	}{
		{"Contains", filtering.PatternTypeContains},
		{"Prefix", filtering.PatternTypePrefix},
		{"Suffix", filtering.PatternTypeSuffix},
	}

	for _, tt := range types {
		patterns := generatePatterns(patternCount, tt.typ)

		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		linear := &linearScanMatch{}
		if err := linear.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("AC/%s", tt.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ac.Match(input)
			}
		})

		b.Run(fmt.Sprintf("Linear/%s", tt.name), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = linear.Match(input)
			}
		})
	}
}

// BenchmarkMatchWithMatches measures performance when patterns actually match.
func BenchmarkMatchWithMatches(b *testing.B) {
	// Create patterns that will actually match our input
	patternCounts := []int{100, 1000, 10000}
	input := []byte("+49123456789012345")

	for _, count := range patternCounts {
		patterns := generatePatterns(count, filtering.PatternTypeContains)
		// Add a pattern that will match
		patterns = append(patterns, Pattern{
			ID:   count,
			Text: "456789",
			Type: filtering.PatternTypeContains,
		})

		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		linear := &linearScanMatch{}
		if err := linear.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("AC/patterns=%d/withMatch", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				results := ac.Match(input)
				if len(results) == 0 {
					b.Fatal("expected at least one match")
				}
			}
		})

		b.Run(fmt.Sprintf("Linear/patterns=%d/withMatch", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				results := linear.Match(input)
				if len(results) == 0 {
					b.Fatal("expected at least one match")
				}
			}
		})
	}
}

// generateMixedPatterns creates patterns with a mix of types.
func generateMixedPatterns(n int) []Pattern {
	patterns := make([]Pattern, n)
	types := []filtering.PatternType{
		filtering.PatternTypeContains,
		filtering.PatternTypePrefix,
		filtering.PatternTypeSuffix,
	}

	for i := 0; i < n; i++ {
		length := 7 + rand.Intn(9)
		digits := make([]byte, length)
		for j := 0; j < length; j++ {
			digits[j] = '0' + byte(rand.Intn(10))
		}
		patterns[i] = Pattern{
			ID:   i,
			Text: string(digits),
			Type: types[i%3], // Rotate through types
		}
	}
	return patterns
}

// BenchmarkMultiModeAC_Build measures build time for MultiModeAC.
func BenchmarkMultiModeAC_Build(b *testing.B) {
	sizes := []int{10, 100, 1000, 10000}

	for _, size := range sizes {
		patterns := generateMixedPatterns(size)

		b.Run(fmt.Sprintf("SingleAC/patterns=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ac := &AhoCorasick{}
				_ = ac.Build(patterns)
			}
		})

		b.Run(fmt.Sprintf("MultiModeAC/patterns=%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				m := NewMultiModeAC()
				_ = m.Build(patterns)
			}
		})
	}
}

// BenchmarkMultiModeAC_Match compares single AC vs MultiModeAC matching.
func BenchmarkMultiModeAC_Match(b *testing.B) {
	patternCounts := []int{100, 1000, 10000}
	input := []byte("+49123456789012345")

	for _, count := range patternCounts {
		patterns := generateMixedPatterns(count)

		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		multi := NewMultiModeAC()
		if err := multi.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("SingleAC/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ac.Match(input)
			}
		})

		b.Run(fmt.Sprintf("MultiModeAC/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = multi.Match(input)
			}
		})
	}
}

// BenchmarkMultiModeAC_SuffixOptimization specifically tests suffix matching
// to verify the reversed pattern optimization provides a benefit.
func BenchmarkMultiModeAC_SuffixOptimization(b *testing.B) {
	patternCounts := []int{100, 1000, 10000}
	input := []byte("+49123456789012345")

	for _, count := range patternCounts {
		// All suffix patterns
		patterns := generatePatterns(count, filtering.PatternTypeSuffix)

		ac := &AhoCorasick{}
		if err := ac.Build(patterns); err != nil {
			b.Fatal(err)
		}

		multi := NewMultiModeAC()
		if err := multi.Build(patterns); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("SingleAC_Suffix/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ac.Match(input)
			}
		})

		b.Run(fmt.Sprintf("MultiModeAC_Suffix/patterns=%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = multi.Match(input)
			}
		})
	}
}
