//go:build tui || all

package filters

import (
	"fmt"
	"strings"
)

// CallStateFilter filters calls by their state (ringing, active, ended, failed)
type CallStateFilter struct {
	states []string // states to match (case-insensitive)
}

// NewCallStateFilter creates a new call state filter
// states can be comma-separated: "active", "ringing,ended", etc.
func NewCallStateFilter(statesStr string) *CallStateFilter {
	// Parse comma-separated states
	parts := strings.Split(statesStr, ",")
	states := make([]string, 0, len(parts))
	for _, p := range parts {
		state := strings.TrimSpace(strings.ToLower(p))
		if state != "" {
			states = append(states, state)
		}
	}

	return &CallStateFilter{
		states: states,
	}
}

// Match checks if the record's state matches any of the filter states
func (f *CallStateFilter) Match(record Filterable) bool {
	// CallStateFilter only works on calls
	if record.RecordType() != "call" {
		return false
	}

	// Get the call state
	state := strings.ToLower(record.GetStringField("state"))

	// Check if state matches any of the filter states
	for _, s := range f.states {
		if state == s {
			return true
		}
	}

	return false
}

// String returns a human-readable representation
func (f *CallStateFilter) String() string {
	return fmt.Sprintf("state:%s", strings.Join(f.states, ","))
}

// Type returns the filter type
func (f *CallStateFilter) Type() string {
	return "callstate"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Call state filters are moderately selective
func (f *CallStateFilter) Selectivity() float64 {
	// More states = less selective
	if len(f.states) >= 3 {
		return 0.3
	} else if len(f.states) == 2 {
		return 0.5
	}
	return 0.7 // Single state is fairly selective
}

// SupportedRecordTypes returns ["call"] as this filter only works on calls
func (f *CallStateFilter) SupportedRecordTypes() []string {
	return []string{"call"}
}
