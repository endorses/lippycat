//go:build hunter || all

// Package filter provides protocol-specific content filtering for hunters.
// These matchers are used to filter packets based on application-layer content
// before forwarding to processors.
package filter

import (
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// ParsedPattern holds a parsed filter pattern for matching.
type ParsedPattern struct {
	ID          string                // Filter ID (for LI correlation)
	Original    string                // Original pattern from user
	Pattern     string                // Parsed pattern (wildcards stripped)
	PatternType filtering.PatternType // Type of matching
}

// ProtocolMatcher is the interface for protocol-specific content matchers.
type ProtocolMatcher interface {
	// UpdateFilters updates the matcher with new filters.
	UpdateFilters(filters []*management.Filter)

	// Match checks if the given data matches any filter.
	// Returns true if matched, and optionally the matched filter IDs.
	Match(data []byte) (matched bool, filterIDs []string)

	// MatchString checks if the given string matches any filter.
	MatchString(value string) (matched bool, filterIDs []string)

	// HasFilters returns true if there are any active filters.
	HasFilters() bool
}

// BaseProtocolMatcher provides common functionality for protocol matchers.
type BaseProtocolMatcher struct {
	mu       sync.RWMutex
	patterns []ParsedPattern
}

// HasFilters returns true if there are any active filters.
func (m *BaseProtocolMatcher) HasFilters() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.patterns) > 0
}

// GetPatterns returns a copy of the current patterns.
func (m *BaseProtocolMatcher) GetPatterns() []ParsedPattern {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]ParsedPattern, len(m.patterns))
	copy(result, m.patterns)
	return result
}

// SetPatterns replaces the current patterns.
func (m *BaseProtocolMatcher) SetPatterns(patterns []ParsedPattern) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.patterns = patterns
}

// MatchStringWithPatterns matches a value against the stored patterns.
// Uses glob-style matching with case-insensitive comparison.
func (m *BaseProtocolMatcher) MatchStringWithPatterns(value string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.patterns {
		if filtering.MatchGlob(p.Original, value) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}
