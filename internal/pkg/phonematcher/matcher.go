// Package phonematcher provides LI-optimized phone number matching using
// bloom filters and hash sets for high-performance suffix matching.
//
// This package is designed for lawful interception (LI) use cases where:
//   - Thousands of phone numbers need to be matched against observed traffic
//   - 99%+ of traffic doesn't match (bloom filter rejects quickly)
//   - Suffix matching handles varying prefixes (+49, 0049, routing codes)
//   - Phone numbers are structured data (digits only after normalization)
//
// Performance targets:
//   - Non-match (bloom reject): <15ns
//   - Match (bloom hit + hash confirm): <100ns
package phonematcher

import (
	"slices"
	"sort"
	"sync/atomic"

	"github.com/bits-and-blooms/bloom/v3"
)

// DefaultMinLength is the minimum suffix length to check (reduces false positives).
// Phone numbers shorter than this are too ambiguous for reliable matching.
const DefaultMinLength = 10

// DefaultBloomFPRate is the target false positive rate for the bloom filter.
// 0.001 = 0.1% false positive rate, good balance of size vs accuracy.
const DefaultBloomFPRate = 0.001

// Matcher performs high-performance phone number suffix matching.
// It uses a bloom filter for fast rejection of non-matches and a hash set
// for confirmation of potential matches.
//
// Thread-safe: reads are lock-free via atomic pointer swap.
// Updates rebuild the entire state and atomically swap it in.
type Matcher struct {
	state atomic.Pointer[matcherState]
}

// matcherState holds the immutable matching state.
// A new state is created on each UpdatePatterns call.
type matcherState struct {
	bloom     *bloom.BloomFilter  // Quick rejection filter
	watchlist map[string]struct{} // Exact lookup (normalized digits)
	lengths   []int               // Unique lengths, sorted descending
	minLength int                 // Minimum suffix length to check
}

// MatchResult contains information about a successful match.
type MatchResult struct {
	// Matched is the watchlist pattern that matched.
	Matched string
	// Observed is the normalized digits that were checked.
	Observed string
}

// New creates a new Matcher with default settings.
// Call UpdatePatterns to add watchlist numbers.
func New() *Matcher {
	m := &Matcher{}
	m.state.Store(&matcherState{
		bloom:     bloom.NewWithEstimates(1, DefaultBloomFPRate),
		watchlist: make(map[string]struct{}),
		lengths:   nil,
		minLength: DefaultMinLength,
	})
	return m
}

// NewWithMinLength creates a new Matcher with a custom minimum suffix length.
func NewWithMinLength(minLength int) *Matcher {
	m := &Matcher{}
	m.state.Store(&matcherState{
		bloom:     bloom.NewWithEstimates(1, DefaultBloomFPRate),
		watchlist: make(map[string]struct{}),
		lengths:   nil,
		minLength: minLength,
	})
	return m
}

// UpdatePatterns rebuilds the matcher with a new set of watchlist patterns.
// Patterns are normalized to digits-only before being added.
// This operation is atomic: readers see either the old or new state, never partial.
func (m *Matcher) UpdatePatterns(patterns []string) {
	if len(patterns) == 0 {
		m.state.Store(&matcherState{
			bloom:     bloom.NewWithEstimates(1, DefaultBloomFPRate),
			watchlist: make(map[string]struct{}),
			lengths:   nil,
			minLength: m.state.Load().minLength,
		})
		return
	}

	// Normalize all patterns and collect unique lengths
	watchlist := make(map[string]struct{}, len(patterns))
	lengthSet := make(map[int]struct{})

	for _, p := range patterns {
		normalized := NormalizeToDigits(p)
		if normalized == "" {
			continue
		}
		watchlist[normalized] = struct{}{}
		lengthSet[len(normalized)] = struct{}{}
	}

	// Sort lengths descending (longest match first)
	lengths := make([]int, 0, len(lengthSet))
	for l := range lengthSet {
		lengths = append(lengths, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(lengths)))

	// Build bloom filter with all patterns
	// For suffix matching, we add all possible suffixes to the bloom filter
	bf := bloom.NewWithEstimates(uint(len(watchlist)*10), DefaultBloomFPRate)
	for pattern := range watchlist {
		bf.AddString(pattern)
	}

	m.state.Store(&matcherState{
		bloom:     bf,
		watchlist: watchlist,
		lengths:   lengths,
		minLength: m.state.Load().minLength,
	})
}

// Match checks if the observed string (phone number from SIP header) matches
// any pattern in the watchlist via suffix matching.
//
// Returns the matched pattern and true if found, or empty string and false otherwise.
// Matching uses "longest match wins" strategy.
func (m *Matcher) Match(observed string) (matched string, ok bool) {
	state := m.state.Load()
	if len(state.watchlist) == 0 {
		return "", false
	}

	digits := NormalizeToDigits(observed)
	if len(digits) < state.minLength {
		return "", false
	}

	// Check each candidate suffix length (longest first)
	for _, k := range state.lengths {
		if k > len(digits) {
			continue
		}
		if k < state.minLength {
			break // Stop checking shorter lengths
		}

		suffix := digits[len(digits)-k:]

		// Fast path: bloom filter rejects most non-matches
		if !state.bloom.TestString(suffix) {
			continue
		}

		// Slow path: confirm with hash set
		if _, exists := state.watchlist[suffix]; exists {
			return suffix, true
		}
	}

	return "", false
}

// MatchWithDetails returns detailed match information including the observed digits.
func (m *Matcher) MatchWithDetails(observed string) (MatchResult, bool) {
	state := m.state.Load()
	if len(state.watchlist) == 0 {
		return MatchResult{}, false
	}

	digits := NormalizeToDigits(observed)
	if len(digits) < state.minLength {
		return MatchResult{}, false
	}

	for _, k := range state.lengths {
		if k > len(digits) {
			continue
		}
		if k < state.minLength {
			break
		}

		suffix := digits[len(digits)-k:]

		if !state.bloom.TestString(suffix) {
			continue
		}

		if _, exists := state.watchlist[suffix]; exists {
			return MatchResult{
				Matched:  suffix,
				Observed: digits,
			}, true
		}
	}

	return MatchResult{}, false
}

// MatchBatch checks multiple observed strings and returns matches.
// This is optimized for batch processing of SIP packets.
func (m *Matcher) MatchBatch(observed []string) []bool {
	results := make([]bool, len(observed))
	state := m.state.Load()

	if len(state.watchlist) == 0 {
		return results
	}

	for i, obs := range observed {
		_, results[i] = m.matchWithState(state, obs)
	}

	return results
}

// matchWithState performs matching with a specific state (avoids repeated atomic loads).
func (m *Matcher) matchWithState(state *matcherState, observed string) (string, bool) {
	digits := NormalizeToDigits(observed)
	if len(digits) < state.minLength {
		return "", false
	}

	for _, k := range state.lengths {
		if k > len(digits) {
			continue
		}
		if k < state.minLength {
			break
		}

		suffix := digits[len(digits)-k:]

		if !state.bloom.TestString(suffix) {
			continue
		}

		if _, exists := state.watchlist[suffix]; exists {
			return suffix, true
		}
	}

	return "", false
}

// Size returns the number of patterns in the watchlist.
func (m *Matcher) Size() int {
	return len(m.state.Load().watchlist)
}

// Lengths returns the unique pattern lengths (sorted descending).
func (m *Matcher) Lengths() []int {
	return slices.Clone(m.state.Load().lengths)
}

// MinLength returns the minimum suffix length being checked.
func (m *Matcher) MinLength() int {
	return m.state.Load().minLength
}
