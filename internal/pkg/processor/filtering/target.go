package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
)

// FilterTarget abstracts how filters are applied to packet sources.
// Implementations include:
// - HunterTarget: distributes filters to remote hunters via gRPC
// - LocalTarget: applies filters locally as BPF on capture interfaces
type FilterTarget interface {
	// ApplyFilter adds or updates a filter.
	// Returns the number of targets that received the filter update.
	ApplyFilter(filter *management.Filter) (uint32, error)

	// RemoveFilter removes a filter by ID.
	// Returns the number of targets that received the removal.
	RemoveFilter(filterID string) (uint32, error)

	// GetActiveFilters returns all currently active filters.
	GetActiveFilters() []*management.Filter

	// SupportsFilterType returns true if this target can handle the given filter type.
	// For example, LocalTarget may not support FILTER_SIP_USER (requires DPI),
	// while HunterTarget with VoIP hunters would support it.
	SupportsFilterType(filterType management.FilterType) bool

	// FilterCount returns the number of active filters.
	FilterCount() int
}

// NoOpFilterTarget is a FilterTarget that does nothing.
// Used when no filtering is configured or needed.
type NoOpFilterTarget struct{}

// ApplyFilter implements FilterTarget but does nothing.
func (n *NoOpFilterTarget) ApplyFilter(_ *management.Filter) (uint32, error) {
	return 0, nil
}

// RemoveFilter implements FilterTarget but does nothing.
func (n *NoOpFilterTarget) RemoveFilter(_ string) (uint32, error) {
	return 0, nil
}

// GetActiveFilters implements FilterTarget, returning empty list.
func (n *NoOpFilterTarget) GetActiveFilters() []*management.Filter {
	return nil
}

// SupportsFilterType implements FilterTarget, returning false for all types.
func (n *NoOpFilterTarget) SupportsFilterType(_ management.FilterType) bool {
	return false
}

// FilterCount implements FilterTarget, returning 0.
func (n *NoOpFilterTarget) FilterCount() int {
	return 0
}

// Ensure NoOpFilterTarget implements FilterTarget.
var _ FilterTarget = (*NoOpFilterTarget)(nil)
