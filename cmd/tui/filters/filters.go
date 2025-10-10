//go:build tui || all
// +build tui all

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
	// Selectivity returns how selective this filter is (0.0 = least selective, 1.0 = most selective)
	// More selective filters reject packets faster and should run first
	Selectivity() float64
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

// Add adds a filter to the chain and sorts by selectivity (most selective first)
func (fc *FilterChain) Add(filter Filter) {
	fc.filters = append(fc.filters, filter)
	fc.sortBySelectivity()
}

// sortBySelectivity sorts filters by selectivity (descending)
// Most selective filters run first to reject packets earlier
func (fc *FilterChain) sortBySelectivity() {
	// Simple insertion sort - filter chains are typically small (1-5 filters)
	for i := 1; i < len(fc.filters); i++ {
		j := i
		for j > 0 && fc.filters[j].Selectivity() > fc.filters[j-1].Selectivity() {
			fc.filters[j], fc.filters[j-1] = fc.filters[j-1], fc.filters[j]
			j--
		}
	}
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