//go:build tui || all

package filters

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NumericComparisonFilter filters records by numeric field comparison
type NumericComparisonFilter struct {
	field    string  // field name (duration, mos, jitter, loss, packets, etc.)
	operator string  // comparison operator (>, <, >=, <=, =)
	value    float64 // comparison value
	rawExpr  string  // original expression for display
}

// Duration parsing regex: matches "30s", "5m", "1h", "1h30m", etc.
var durationRegex = regexp.MustCompile(`^(\d+h)?(\d+m)?(\d+s)?$`)

// NewNumericComparisonFilter creates a new numeric comparison filter
// expr format: "field:>value" or "field:>=value" etc.
// For duration fields, value can include time units: "30s", "5m", "1h", "1h30m"
func NewNumericComparisonFilter(field, operatorAndValue string) (*NumericComparisonFilter, error) {
	// Parse operator and value from the expression
	operator, valueStr := parseOperatorAndValue(operatorAndValue)
	if operator == "" {
		return nil, fmt.Errorf("invalid comparison: %s", operatorAndValue)
	}

	// Parse the value
	value, err := parseNumericValue(field, valueStr)
	if err != nil {
		return nil, fmt.Errorf("invalid value for %s: %v", field, err)
	}

	return &NumericComparisonFilter{
		field:    field,
		operator: operator,
		value:    value,
		rawExpr:  fmt.Sprintf("%s:%s%s", field, operator, valueStr),
	}, nil
}

// parseOperatorAndValue extracts the operator and value from a comparison string
func parseOperatorAndValue(s string) (operator, value string) {
	s = strings.TrimSpace(s)

	// Check for two-character operators first
	if strings.HasPrefix(s, ">=") {
		return ">=", strings.TrimSpace(s[2:])
	}
	if strings.HasPrefix(s, "<=") {
		return "<=", strings.TrimSpace(s[2:])
	}
	if strings.HasPrefix(s, "==") {
		return "=", strings.TrimSpace(s[2:])
	}

	// Check for single-character operators
	if strings.HasPrefix(s, ">") {
		return ">", strings.TrimSpace(s[1:])
	}
	if strings.HasPrefix(s, "<") {
		return "<", strings.TrimSpace(s[1:])
	}
	if strings.HasPrefix(s, "=") {
		return "=", strings.TrimSpace(s[1:])
	}

	return "", s
}

// parseNumericValue parses a numeric value, handling duration formats for duration fields
func parseNumericValue(field, valueStr string) (float64, error) {
	// For duration fields, parse duration format
	if field == "duration" {
		return parseDuration(valueStr)
	}

	// For other fields, parse as float
	return strconv.ParseFloat(valueStr, 64)
}

// parseDuration parses a duration string like "30s", "5m", "1h", "1h30m"
// Returns the duration in seconds
func parseDuration(s string) (float64, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	// Try standard Go duration parsing first
	if d, err := time.ParseDuration(s); err == nil {
		return d.Seconds(), nil
	}

	// Try parsing as a plain number (seconds)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}

	// Try custom duration format (e.g., "1h30m", "30s")
	if durationRegex.MatchString(s) {
		var total float64

		// Extract hours
		if idx := strings.Index(s, "h"); idx != -1 {
			hours, err := strconv.ParseFloat(s[:idx], 64)
			if err != nil {
				return 0, err
			}
			total += hours * 3600
			s = s[idx+1:]
		}

		// Extract minutes
		if idx := strings.Index(s, "m"); idx != -1 {
			minutes, err := strconv.ParseFloat(s[:idx], 64)
			if err != nil {
				return 0, err
			}
			total += minutes * 60
			s = s[idx+1:]
		}

		// Extract seconds
		if idx := strings.Index(s, "s"); idx != -1 {
			seconds, err := strconv.ParseFloat(s[:idx], 64)
			if err != nil {
				return 0, err
			}
			total += seconds
		}

		return total, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}

// Match checks if the record's numeric field matches the comparison
func (f *NumericComparisonFilter) Match(record Filterable) bool {
	fieldValue := record.GetNumericField(f.field)

	switch f.operator {
	case ">":
		return fieldValue > f.value
	case "<":
		return fieldValue < f.value
	case ">=":
		return fieldValue >= f.value
	case "<=":
		return fieldValue <= f.value
	case "=", "==":
		// For floating point comparison, use a small epsilon
		const epsilon = 0.0001
		diff := fieldValue - f.value
		if diff < 0 {
			diff = -diff
		}
		return diff < epsilon
	default:
		return false
	}
}

// String returns a human-readable representation
func (f *NumericComparisonFilter) String() string {
	return f.rawExpr
}

// Type returns the filter type
func (f *NumericComparisonFilter) Type() string {
	return "numeric"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Numeric comparisons are generally selective
func (f *NumericComparisonFilter) Selectivity() float64 {
	// Equality is most selective
	if f.operator == "=" || f.operator == "==" {
		return 0.9
	}
	// Range comparisons are moderately selective
	return 0.7
}

// SupportedRecordTypes returns nil as numeric filters can work on any record type
// (as long as the record has the specified numeric field)
func (f *NumericComparisonFilter) SupportedRecordTypes() []string {
	return nil // Generic filter - supports all record types with numeric fields
}
