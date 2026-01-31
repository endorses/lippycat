//go:build tui || all

package filters

import (
	"fmt"
	"strings"
)

// statePattern represents a parsed state filter pattern
type statePattern struct {
	pattern    string // original pattern (lowercase)
	isWildcard bool   // true if pattern ends with *
	prefix     string // for wildcards: prefix to match (without *)
}

// CallStateFilter filters calls by their state (ringing, active, ended, failed)
// Supports:
//   - Exact states: "active", "ringing", "ended"
//   - Error codes: "E:404", "E:503"
//   - Wildcards: "E:*" (any error), "E:4*" (4xx errors), "E:50*" (50x errors)
//   - "failed" is an alias for "E:*" (matches any error state)
type CallStateFilter struct {
	patterns []statePattern // patterns to match (case-insensitive)
}

// NewCallStateFilter creates a new call state filter
// states can be comma-separated: "active", "ringing,ended", "E:*", "E:4*", etc.
func NewCallStateFilter(statesStr string) *CallStateFilter {
	// Parse comma-separated states
	parts := strings.Split(statesStr, ",")
	patterns := make([]statePattern, 0, len(parts))
	for _, p := range parts {
		state := strings.TrimSpace(strings.ToLower(p))
		if state == "" {
			continue
		}

		// "failed" is an alias for "E:*" (any error state)
		if state == "failed" {
			patterns = append(patterns, statePattern{
				pattern:    "e:*",
				isWildcard: true,
				prefix:     "e:",
			})
			continue
		}

		// Check for wildcard pattern
		if strings.HasSuffix(state, "*") {
			patterns = append(patterns, statePattern{
				pattern:    state,
				isWildcard: true,
				prefix:     strings.TrimSuffix(state, "*"),
			})
		} else {
			patterns = append(patterns, statePattern{
				pattern:    state,
				isWildcard: false,
			})
		}
	}

	return &CallStateFilter{
		patterns: patterns,
	}
}

// Match checks if the record's state matches any of the filter patterns
func (f *CallStateFilter) Match(record Filterable) bool {
	// CallStateFilter only works on calls
	if record.RecordType() != "call" {
		return false
	}

	// Get the call state
	state := strings.ToLower(record.GetStringField("state"))

	// Check if state matches any of the filter patterns
	for _, p := range f.patterns {
		if p.isWildcard {
			// Wildcard: check prefix match
			if strings.HasPrefix(state, p.prefix) {
				return true
			}
		} else {
			// Exact match
			if state == p.pattern {
				return true
			}
		}
	}

	return false
}

// String returns a human-readable representation
func (f *CallStateFilter) String() string {
	patternStrs := make([]string, len(f.patterns))
	for i, p := range f.patterns {
		patternStrs[i] = p.pattern
	}
	return fmt.Sprintf("state:%s", strings.Join(patternStrs, ","))
}

// Type returns the filter type
func (f *CallStateFilter) Type() string {
	return "callstate"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Call state filters are moderately selective
func (f *CallStateFilter) Selectivity() float64 {
	// More patterns = less selective
	// Wildcards are less selective than exact matches
	if len(f.patterns) >= 3 {
		return 0.3
	} else if len(f.patterns) == 2 {
		return 0.5
	}
	// Single wildcard is less selective than single exact match
	if len(f.patterns) == 1 && f.patterns[0].isWildcard {
		return 0.5
	}
	return 0.7 // Single exact state is fairly selective
}

// SupportedRecordTypes returns ["call"] as this filter only works on calls
func (f *CallStateFilter) SupportedRecordTypes() []string {
	return []string{"call"}
}
