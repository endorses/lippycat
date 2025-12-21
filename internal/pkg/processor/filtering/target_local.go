// Package filtering - LocalTarget Implementation
//
// LocalTarget implements the FilterTarget interface for applying filters locally
// in standalone "tap" mode. It converts management filters to BPF expressions
// and routes application-layer filters (VoIP) to ApplicationFilter.
//
// Architecture:
//
//	Management Filter → LocalTarget → BPF (kernel) + ApplicationFilter (userspace)
//
// Filter routing:
//   - FILTER_BPF, FILTER_IP_ADDRESS → BPF (kernel-level)
//   - FILTER_SIP_USER, FILTER_PHONE_NUMBER, FILTER_CALL_ID, FILTER_CODEC → ApplicationFilter
package filtering

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// BPFUpdater is an interface for updating BPF filters on a capture source.
// LocalSource implements this interface via SetBPFFilter.
type BPFUpdater interface {
	SetBPFFilter(filter string) error
}

// AppFilterUpdater is an interface for updating application-layer filters.
// hunter.ApplicationFilter implements this interface.
type AppFilterUpdater interface {
	UpdateFilters(filters []*management.Filter)
}

// LocalTarget implements FilterTarget for local standalone capture mode.
// It applies BPF filters at the kernel level and routes VoIP filters
// to an ApplicationFilter for userspace matching.
type LocalTarget struct {
	mu sync.RWMutex

	// Active filters indexed by ID
	filters map[string]*management.Filter

	// Base BPF filter (from command line or config)
	baseBPF string

	// Dependencies (optional, set via Set* methods)
	bpfUpdater    BPFUpdater
	appFilterFunc AppFilterUpdater
}

// LocalTargetConfig contains configuration for LocalTarget.
type LocalTargetConfig struct {
	// BaseBPF is the initial BPF filter expression from CLI/config.
	// This filter is always applied in addition to any dynamic filters.
	BaseBPF string
}

// NewLocalTarget creates a new LocalTarget for local filtering.
func NewLocalTarget(cfg LocalTargetConfig) *LocalTarget {
	return &LocalTarget{
		filters: make(map[string]*management.Filter),
		baseBPF: cfg.BaseBPF,
	}
}

// SetBPFUpdater sets the BPF updater for applying kernel-level filters.
// The updater is typically a LocalSource instance.
func (t *LocalTarget) SetBPFUpdater(updater BPFUpdater) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bpfUpdater = updater
}

// SetApplicationFilter sets the application filter for VoIP filtering.
// The filter is typically a hunter.ApplicationFilter instance.
func (t *LocalTarget) SetApplicationFilter(filter AppFilterUpdater) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.appFilterFunc = filter
}

// ApplyFilter adds or updates a filter.
// Returns 1 if the filter was applied successfully, 0 otherwise.
func (t *LocalTarget) ApplyFilter(filter *management.Filter) (uint32, error) {
	if filter == nil || filter.Id == "" {
		return 0, nil
	}

	t.mu.Lock()
	// Store or update the filter
	_, exists := t.filters[filter.Id]
	t.filters[filter.Id] = filter

	// Get current state for logging
	bpfUpdater := t.bpfUpdater
	appFilter := t.appFilterFunc
	t.mu.Unlock()

	action := "added"
	if exists {
		action = "updated"
	}

	logger.Debug("LocalTarget filter "+action,
		"filter_id", filter.Id,
		"filter_type", filter.Type,
		"pattern", filter.Pattern)

	// Apply filters based on type
	if err := t.applyFilters(bpfUpdater, appFilter); err != nil {
		return 0, fmt.Errorf("failed to apply filter: %w", err)
	}

	return 1, nil
}

// RemoveFilter removes a filter by ID.
// Returns 1 if the filter was removed successfully, 0 if not found.
func (t *LocalTarget) RemoveFilter(filterID string) (uint32, error) {
	if filterID == "" {
		return 0, nil
	}

	t.mu.Lock()
	_, exists := t.filters[filterID]
	if !exists {
		t.mu.Unlock()
		return 0, nil
	}

	delete(t.filters, filterID)
	bpfUpdater := t.bpfUpdater
	appFilter := t.appFilterFunc
	t.mu.Unlock()

	logger.Debug("LocalTarget filter removed", "filter_id", filterID)

	// Re-apply remaining filters
	if err := t.applyFilters(bpfUpdater, appFilter); err != nil {
		return 0, fmt.Errorf("failed to reapply filters after removal: %w", err)
	}

	return 1, nil
}

// GetActiveFilters returns all currently active filters.
func (t *LocalTarget) GetActiveFilters() []*management.Filter {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filters := make([]*management.Filter, 0, len(t.filters))
	for _, f := range t.filters {
		filters = append(filters, f)
	}
	return filters
}

// SupportsFilterType returns true if this target can handle the given filter type.
// LocalTarget supports BPF and IP_ADDRESS at kernel level, and VoIP filters
// via ApplicationFilter.
func (t *LocalTarget) SupportsFilterType(filterType management.FilterType) bool {
	switch filterType {
	case management.FilterType_FILTER_BPF,
		management.FilterType_FILTER_IP_ADDRESS:
		// These are converted to BPF (kernel-level)
		return true
	case management.FilterType_FILTER_SIP_USER,
		management.FilterType_FILTER_PHONE_NUMBER,
		management.FilterType_FILTER_CALL_ID,
		management.FilterType_FILTER_CODEC:
		// These require ApplicationFilter (userspace)
		// Only supported if we have an app filter configured
		t.mu.RLock()
		hasAppFilter := t.appFilterFunc != nil
		t.mu.RUnlock()
		return hasAppFilter
	default:
		return false
	}
}

// FilterCount returns the number of active filters.
func (t *LocalTarget) FilterCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.filters)
}

// applyFilters applies all current filters to the capture source.
// BPF-convertible filters are combined into a single BPF expression.
// VoIP filters are passed to the ApplicationFilter.
func (t *LocalTarget) applyFilters(bpfUpdater BPFUpdater, appFilter AppFilterUpdater) error {
	t.mu.RLock()
	filters := make([]*management.Filter, 0, len(t.filters))
	for _, f := range t.filters {
		filters = append(filters, f)
	}
	baseBPF := t.baseBPF
	t.mu.RUnlock()

	// Separate filters by type
	var bpfFilters []*management.Filter
	var appFilters []*management.Filter

	for _, f := range filters {
		if !f.Enabled {
			continue
		}

		switch f.Type {
		case management.FilterType_FILTER_BPF,
			management.FilterType_FILTER_IP_ADDRESS:
			bpfFilters = append(bpfFilters, f)
		case management.FilterType_FILTER_SIP_USER,
			management.FilterType_FILTER_PHONE_NUMBER,
			management.FilterType_FILTER_CALL_ID,
			management.FilterType_FILTER_CODEC:
			appFilters = append(appFilters, f)
		}
	}

	// Build combined BPF expression
	bpfExpr := t.buildBPFExpression(baseBPF, bpfFilters)

	// Apply BPF filter if we have an updater
	if bpfUpdater != nil && bpfExpr != "" {
		logger.Debug("LocalTarget applying BPF filter", "expression", bpfExpr)
		if err := bpfUpdater.SetBPFFilter(bpfExpr); err != nil {
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	} else if bpfUpdater != nil && bpfExpr == "" && baseBPF == "" {
		// Clear any existing BPF filter
		if err := bpfUpdater.SetBPFFilter(""); err != nil {
			return fmt.Errorf("failed to clear BPF filter: %w", err)
		}
	}

	// Apply application-layer filters
	if appFilter != nil {
		logger.Debug("LocalTarget updating application filter",
			"filter_count", len(appFilters))
		appFilter.UpdateFilters(appFilters)
	}

	return nil
}

// buildBPFExpression builds a combined BPF expression from base BPF and filters.
// Multiple filters are combined with OR logic.
// The base BPF (if any) is ANDed with the combined filter expression.
func (t *LocalTarget) buildBPFExpression(baseBPF string, filters []*management.Filter) string {
	if len(filters) == 0 {
		return baseBPF
	}

	var expressions []string

	for _, f := range filters {
		expr := t.filterToBPF(f)
		if expr != "" {
			expressions = append(expressions, expr)
		}
	}

	if len(expressions) == 0 {
		return baseBPF
	}

	// Combine filter expressions with OR
	var filterExpr string
	if len(expressions) == 1 {
		filterExpr = expressions[0]
	} else {
		// Wrap each expression in parentheses and OR them
		wrapped := make([]string, len(expressions))
		for i, e := range expressions {
			wrapped[i] = "(" + e + ")"
		}
		filterExpr = strings.Join(wrapped, " or ")
	}

	// Combine with base BPF using AND
	if baseBPF != "" {
		return "(" + baseBPF + ") and (" + filterExpr + ")"
	}

	return filterExpr
}

// filterToBPF converts a management filter to a BPF expression.
// Returns empty string for filters that cannot be converted to BPF.
func (t *LocalTarget) filterToBPF(f *management.Filter) string {
	switch f.Type {
	case management.FilterType_FILTER_BPF:
		// BPF filters are already in BPF syntax
		return f.Pattern

	case management.FilterType_FILTER_IP_ADDRESS:
		// Convert IP address to BPF host expression
		return t.ipAddressToBPF(f.Pattern)

	default:
		// Other filter types cannot be converted to BPF
		return ""
	}
}

// ipAddressToBPF converts an IP address pattern to a BPF expression.
// Supports:
//   - Single IP: "192.168.1.1" -> "host 192.168.1.1"
//   - CIDR: "192.168.1.0/24" -> "net 192.168.1.0/24"
func (t *LocalTarget) ipAddressToBPF(pattern string) string {
	if pattern == "" {
		return ""
	}

	// Check if it's a CIDR notation
	if strings.Contains(pattern, "/") {
		// Validate CIDR
		_, _, err := net.ParseCIDR(pattern)
		if err != nil {
			logger.Warn("Invalid CIDR pattern for BPF filter",
				"pattern", pattern,
				"error", err)
			return ""
		}
		return "net " + pattern
	}

	// Single IP address
	ip := net.ParseIP(pattern)
	if ip == nil {
		logger.Warn("Invalid IP address pattern for BPF filter",
			"pattern", pattern)
		return ""
	}

	return "host " + pattern
}

// SetBaseBPF updates the base BPF filter.
// This triggers recompilation of the combined filter expression.
func (t *LocalTarget) SetBaseBPF(bpf string) error {
	t.mu.Lock()
	t.baseBPF = bpf
	bpfUpdater := t.bpfUpdater
	appFilter := t.appFilterFunc
	t.mu.Unlock()

	return t.applyFilters(bpfUpdater, appFilter)
}

// GetBaseBPF returns the current base BPF filter.
func (t *LocalTarget) GetBaseBPF() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.baseBPF
}

// Ensure LocalTarget implements FilterTarget.
var _ FilterTarget = (*LocalTarget)(nil)
