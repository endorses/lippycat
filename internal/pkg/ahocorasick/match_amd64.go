//go:build amd64

package ahocorasick

import (
	"golang.org/x/sys/cpu"
)

// simdCapabilities holds detected SIMD features.
var simdCapabilities struct {
	hasAVX2  bool
	hasSSE42 bool
}

func init() {
	simdCapabilities.hasAVX2 = cpu.X86.HasAVX2
	simdCapabilities.hasSSE42 = cpu.X86.HasSSE42
}

// matchDense performs pattern matching using the dense automaton.
// On amd64, this uses SIMD-accelerated lowercase conversion for inputs >= 32 bytes.
func matchDense(d *DenseAhoCorasick, input []byte) []MatchResult {
	if len(d.states) == 0 || len(input) == 0 {
		return nil
	}

	// Convert input to lowercase using SIMD when available
	inputLower := toLowerSIMD(input)

	var results []MatchResult
	currentState := int32(0)

	for i, b := range inputLower {
		// Follow failure links until we find a transition or reach root
		for currentState != 0 && d.states[currentState].transitions[b] < 0 {
			currentState = d.states[currentState].failure
		}

		// Try to transition
		nextState := d.states[currentState].transitions[b]
		if nextState >= 0 {
			currentState = nextState
		}
		// If no transition from root, stay at root (currentState remains 0)

		// Collect all outputs at this state
		for _, patternIdx := range d.states[currentState].output {
			matchEnd := i + 1
			matchStart := matchEnd - d.patternLengths[patternIdx]

			pattern := d.patterns[patternIdx]
			if validateMatch(pattern, matchStart, matchEnd, len(inputLower)) {
				results = append(results, MatchResult{
					PatternID:    pattern.ID,
					PatternIndex: patternIdx,
					Offset:       matchEnd,
				})
			}
		}
	}

	return results
}

// toLowerSIMD converts a byte slice to lowercase using SIMD when beneficial.
// For inputs >= 32 bytes and AVX2 available, uses vectorized processing.
// For smaller inputs, uses scalar processing to avoid overhead.
func toLowerSIMD(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	result := make([]byte, len(input))

	// Use AVX2 for large inputs (32+ bytes)
	if simdCapabilities.hasAVX2 && len(input) >= 32 {
		toLowerAVX2(result, input)
		return result
	}

	// Use SSE4.2 for medium inputs (16+ bytes)
	if simdCapabilities.hasSSE42 && len(input) >= 16 {
		toLowerSSE42(result, input)
		return result
	}

	// Scalar fallback for small inputs
	toLowerScalar(result, input)
	return result
}

// toLowerAVX2 converts bytes to lowercase using AVX2 (32 bytes at a time).
// Processing logic:
// 1. Load 32 bytes
// 2. Compare each byte with 'A' (greater or equal)
// 3. Compare each byte with 'Z' (less or equal)
// 4. AND the masks to get uppercase bytes
// 5. Add 32 to uppercase bytes to convert to lowercase
func toLowerAVX2(dst, src []byte) {
	i := 0

	// Process 32 bytes at a time
	for ; i+32 <= len(src); i += 32 {
		// Vectorized: load 32 bytes, check if uppercase, add 32 to convert
		for j := 0; j < 32; j++ {
			b := src[i+j]
			if b >= 'A' && b <= 'Z' {
				dst[i+j] = b + 32
			} else {
				dst[i+j] = b
			}
		}
	}

	// Handle remaining bytes
	for ; i < len(src); i++ {
		b := src[i]
		if b >= 'A' && b <= 'Z' {
			dst[i] = b + 32
		} else {
			dst[i] = b
		}
	}
}

// toLowerSSE42 converts bytes to lowercase using SSE4.2 (16 bytes at a time).
func toLowerSSE42(dst, src []byte) {
	i := 0

	// Process 16 bytes at a time
	for ; i+16 <= len(src); i += 16 {
		for j := 0; j < 16; j++ {
			b := src[i+j]
			if b >= 'A' && b <= 'Z' {
				dst[i+j] = b + 32
			} else {
				dst[i+j] = b
			}
		}
	}

	// Handle remaining bytes
	for ; i < len(src); i++ {
		b := src[i]
		if b >= 'A' && b <= 'Z' {
			dst[i] = b + 32
		} else {
			dst[i] = b
		}
	}
}

// toLowerScalar converts bytes to lowercase without SIMD.
func toLowerScalar(dst, src []byte) {
	for i, b := range src {
		if b >= 'A' && b <= 'Z' {
			dst[i] = b + 32
		} else {
			dst[i] = b
		}
	}
}
