package filters

import (
	"github.com/endorses/lippycat/cmd/tui/components"
)

// Filter represents a packet filter
type Filter interface {
	// Match returns true if the packet matches the filter
	Match(packet components.PacketDisplay) bool
	// String returns a human-readable representation of the filter
	String() string
	// Type returns the filter type (bpf, voip, etc.)
	Type() string
}

// FilterChain combines multiple filters
type FilterChain struct {
	filters []Filter
}

// NewFilterChain creates a new filter chain
func NewFilterChain() *FilterChain {
	return &FilterChain{
		filters: make([]Filter, 0),
	}
}

// Add adds a filter to the chain
func (fc *FilterChain) Add(filter Filter) {
	fc.filters = append(fc.filters, filter)
}

// Clear removes all filters
func (fc *FilterChain) Clear() {
	fc.filters = make([]Filter, 0)
}

// Match checks if a packet matches all filters in the chain
func (fc *FilterChain) Match(packet components.PacketDisplay) bool {
	// If no filters, match everything
	if len(fc.filters) == 0 {
		return true
	}

	// All filters must match (AND logic)
	for _, filter := range fc.filters {
		if !filter.Match(packet) {
			return false
		}
	}
	return true
}

// GetFilters returns all active filters
func (fc *FilterChain) GetFilters() []Filter {
	return fc.filters
}

// IsEmpty returns true if there are no filters
func (fc *FilterChain) IsEmpty() bool {
	return len(fc.filters) == 0
}