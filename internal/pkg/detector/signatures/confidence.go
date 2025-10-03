package signatures

// Indicator represents a single piece of evidence for protocol detection
type Indicator struct {
	Name       string
	Weight     float64 // 0.0 - 1.0
	Confidence float64 // 0.0 - 1.0
}

// ScoreDetection calculates overall confidence from multiple indicators
// Uses weighted average of all indicators
func ScoreDetection(indicators []Indicator) float64 {
	if len(indicators) == 0 {
		return 0.0
	}

	totalWeight := 0.0
	weightedSum := 0.0

	for _, ind := range indicators {
		totalWeight += ind.Weight
		weightedSum += ind.Weight * ind.Confidence
	}

	if totalWeight == 0.0 {
		return 0.0
	}

	score := weightedSum / totalWeight

	// Clamp to [0.0, 1.0]
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	return score
}

// CombineConfidence combines multiple confidence scores using maximum
// This is useful when multiple detection methods all point to same protocol
func CombineConfidence(scores ...float64) float64 {
	max := 0.0
	for _, score := range scores {
		if score > max {
			max = score
		}
	}
	return max
}

// AdjustConfidenceByContext adjusts confidence based on contextual factors
func AdjustConfidenceByContext(baseConfidence float64, factors map[string]float64) float64 {
	confidence := baseConfidence

	// Apply each contextual factor as a multiplier
	for _, factor := range factors {
		confidence *= factor
	}

	// Clamp to [0.0, 1.0]
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// GetConfidenceLevel returns a human-readable confidence level
func GetConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= ConfidenceDefinite:
		return "Definite"
	case confidence >= ConfidenceVeryHigh:
		return "Very High"
	case confidence >= ConfidenceHigh:
		return "High"
	case confidence >= ConfidenceMedium:
		return "Medium"
	case confidence >= ConfidenceLow:
		return "Low"
	case confidence >= ConfidenceGuess:
		return "Guess"
	default:
		return "Unknown"
	}
}

// PortBasedConfidence returns confidence adjustment for port-based hints
// Standard ports get higher confidence, non-standard ports get lower
func PortBasedConfidence(port uint16, standardPorts []uint16) float64 {
	for _, standardPort := range standardPorts {
		if port == standardPort {
			return 1.2 // Boost confidence by 20% for standard port
		}
	}
	return 0.8 // Reduce confidence by 20% for non-standard port
}
