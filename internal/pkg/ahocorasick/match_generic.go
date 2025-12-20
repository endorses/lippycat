//go:build !amd64

package ahocorasick

// matchDense performs pattern matching using the dense automaton.
// This is the generic (non-SIMD) implementation for non-amd64 platforms.
func matchDense(d *DenseAhoCorasick, input []byte) []MatchResult {
	if len(d.states) == 0 || len(input) == 0 {
		return nil
	}

	// Convert input to lowercase
	inputLower := toLowerGeneric(input)

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

// toLowerGeneric converts bytes to lowercase without SIMD.
func toLowerGeneric(input []byte) []byte {
	if len(input) == 0 {
		return input
	}

	result := make([]byte, len(input))
	for i, b := range input {
		if b >= 'A' && b <= 'Z' {
			result[i] = b + 32
		} else {
			result[i] = b
		}
	}
	return result
}
