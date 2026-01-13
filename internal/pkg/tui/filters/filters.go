//go:build tui || all

package filters

import (
	"github.com/endorses/lippycat/internal/pkg/tui/components"
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

// filterWithOrder wraps a filter with its insertion order
type filterWithOrder struct {
	filter         Filter
	insertionOrder int
}

// FilterChain combines multiple filters
type FilterChain struct {
	filters        []filterWithOrder
	nextOrderIndex int
}

// NewFilterChain creates a new filter chain
func NewFilterChain() *FilterChain {
	return &FilterChain{
		filters:        make([]filterWithOrder, 0),
		nextOrderIndex: 0,
	}
}

// Add adds a filter to the chain and sorts by selectivity (most selective first)
func (fc *FilterChain) Add(filter Filter) {
	fc.filters = append(fc.filters, filterWithOrder{
		filter:         filter,
		insertionOrder: fc.nextOrderIndex,
	})
	fc.nextOrderIndex++
	fc.sortBySelectivity()
}

// sortBySelectivity sorts filters by selectivity (descending)
// Most selective filters run first to reject packets earlier
func (fc *FilterChain) sortBySelectivity() {
	// Simple insertion sort - filter chains are typically small (1-5 filters)
	for i := 1; i < len(fc.filters); i++ {
		j := i
		for j > 0 && fc.filters[j].filter.Selectivity() > fc.filters[j-1].filter.Selectivity() {
			fc.filters[j], fc.filters[j-1] = fc.filters[j-1], fc.filters[j]
			j--
		}
	}
}

// Clear removes all filters
func (fc *FilterChain) Clear() {
	fc.filters = make([]filterWithOrder, 0)
	fc.nextOrderIndex = 0
}

// Match checks if a packet matches all filters in the chain
func (fc *FilterChain) Match(packet components.PacketDisplay) bool {
	// If no filters, match everything
	if len(fc.filters) == 0 {
		return true
	}

	// All filters must match (AND logic)
	for _, fwo := range fc.filters {
		if !fwo.filter.Match(packet) {
			return false
		}
	}
	return true
}

// GetFilters returns all active filters
func (fc *FilterChain) GetFilters() []Filter {
	filters := make([]Filter, len(fc.filters))
	for i, fwo := range fc.filters {
		filters[i] = fwo.filter
	}
	return filters
}

// IsEmpty returns true if there are no filters
func (fc *FilterChain) IsEmpty() bool {
	return len(fc.filters) == 0
}

// Count returns the number of filters in the chain
func (fc *FilterChain) Count() int {
	return len(fc.filters)
}

// RemoveLast removes the last filter from the chain (by insertion order)
// Returns true if a filter was removed, false if the chain was empty
func (fc *FilterChain) RemoveLast() bool {
	if len(fc.filters) == 0 {
		return false
	}

	// Find the filter with the highest insertion order
	maxOrderIdx := 0
	maxOrder := fc.filters[0].insertionOrder
	for i := 1; i < len(fc.filters); i++ {
		if fc.filters[i].insertionOrder > maxOrder {
			maxOrder = fc.filters[i].insertionOrder
			maxOrderIdx = i
		}
	}

	// Remove the filter with the highest insertion order
	fc.filters = append(fc.filters[:maxOrderIdx], fc.filters[maxOrderIdx+1:]...)
	return true
}

// GetFilterDescriptions returns human-readable descriptions of all filters
func (fc *FilterChain) GetFilterDescriptions() []string {
	descriptions := make([]string, len(fc.filters))
	for i, fwo := range fc.filters {
		descriptions[i] = fwo.filter.String()
	}
	return descriptions
}
