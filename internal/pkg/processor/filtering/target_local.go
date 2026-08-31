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
	"sort"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/protobuf/proto"
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

// LocalFilterPolicy is a detached snapshot of the effective local filtering
// policy. Slices and protobuf messages are cloned before a policy is handed to
// a coordinator, so coordinator-side mutation cannot alter LocalTarget state.
type LocalFilterPolicy struct {
	BaseBPF            string
	BPFExpression      string
	Filters            []*management.Filter
	ApplicationFilters []*management.Filter
}

// LocalFilterChange describes one effective local-policy transition.
type LocalFilterChange struct {
	Previous LocalFilterPolicy
	Next     LocalFilterPolicy
}

// LocalFilterCoordinator performs a local filter transition at a capture and
// producer-session boundary. LocalTarget commits its candidate state only when
// this method succeeds.
type LocalFilterCoordinator interface {
	ReconcileLocalFilterChange(change LocalFilterChange) error
}

// ApplyApplicationPolicy applies a prepared userspace policy while capture is quiesced.
func (t *LocalTarget) ApplyApplicationPolicy(policy LocalFilterPolicy) {
	t.mu.RLock()
	appFilter := t.appFilterFunc
	t.mu.RUnlock()
	if appFilter != nil {
		appFilter.UpdateFilters(cloneFilterSlice(policy.ApplicationFilters))
	}
}

// LocalTarget implements FilterTarget for local standalone capture mode.
// It applies BPF filters at the kernel level and routes VoIP filters
// to an ApplicationFilter for userspace matching.
type LocalTarget struct {
	mu         sync.RWMutex
	bpfApplyMu sync.Mutex
	mutationMu sync.Mutex

	// Active filters indexed by ID
	filters map[string]*management.Filter

	// Base BPF filter (from command line or config)
	baseBPF string

	// Dependencies (optional, set via Set* methods)
	bpfUpdater    BPFUpdater
	appFilterFunc AppFilterUpdater
	coordinator   LocalFilterCoordinator

	// lastAppliedBPF is only valid when hasAppliedBPF is true. Keeping the
	// boolean separate matters because an empty expression is a real applied
	// state (it clears the kernel filter).
	lastAppliedBPF string
	hasAppliedBPF  bool
}

// SetCoordinator installs the owner of capture/session filter boundaries.
func (t *LocalTarget) SetCoordinator(coordinator LocalFilterCoordinator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.coordinator = coordinator
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
	// A replacement updater has independent state and must receive the current
	// expression on the next reconciliation.
	t.hasAppliedBPF = false
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

	t.mutationMu.Lock()
	defer t.mutationMu.Unlock()

	previous, next := t.candidateState(func(filters map[string]*management.Filter) {
		filters[filter.Id] = cloneFilter(filter)
	})
	_, exists := previous.filters[filter.Id]

	action := "added"
	if exists {
		action = "updated"
	}

	logger.Debug("LocalTarget filter "+action,
		"filter_id", filter.Id,
		"filter_type", filter.Type,
		"pattern", filter.Pattern)

	if err := t.reconcileCandidate(previous, next); err != nil {
		return 0, fmt.Errorf("failed to apply filter: %w", err)
	}
	t.commitCandidate(next)

	return 1, nil
}

// ApplyFilterBatch adds or updates multiple filters in a single operation.
// This is more efficient than calling ApplyFilter repeatedly because it only
// rebuilds the Aho-Corasick automaton once at the end.
// Returns the number of filters applied successfully.
func (t *LocalTarget) ApplyFilterBatch(filters []*management.Filter) (uint32, error) {
	if len(filters) == 0 {
		return 0, nil
	}

	t.mutationMu.Lock()
	defer t.mutationMu.Unlock()

	var count uint32
	previous, next := t.candidateState(func(candidate map[string]*management.Filter) {
		for _, filter := range filters {
			if filter == nil || filter.Id == "" {
				continue
			}
			candidate[filter.Id] = cloneFilter(filter)
			count++
		}
	})

	// Count enabled filters by type
	var enabledApp, disabledCount int
	for _, f := range next.filters {
		if !f.Enabled {
			disabledCount++
			continue
		}
		switch f.Type {
		case management.FilterType_FILTER_SIP_USER,
			management.FilterType_FILTER_PHONE_NUMBER,
			management.FilterType_FILTER_CALL_ID,
			management.FilterType_FILTER_CODEC:
			enabledApp++
		}
	}
	logger.Info("LocalTarget batch filter update",
		"total_count", count,
		"enabled_app_filters", enabledApp,
		"disabled_count", disabledCount)

	// Apply all filters once
	if err := t.reconcileCandidate(previous, next); err != nil {
		return 0, fmt.Errorf("failed to apply filters: %w", err)
	}
	t.commitCandidate(next)

	return count, nil
}

// RemoveFilter removes a filter by ID.
// Returns 1 if the filter was removed successfully, 0 if not found.
func (t *LocalTarget) RemoveFilter(filterID string) (uint32, error) {
	if filterID == "" {
		return 0, nil
	}

	t.mutationMu.Lock()
	defer t.mutationMu.Unlock()

	previous, next := t.candidateState(func(filters map[string]*management.Filter) {
		delete(filters, filterID)
	})
	_, exists := previous.filters[filterID]
	if !exists {
		return 0, nil
	}

	logger.Debug("LocalTarget filter removed", "filter_id", filterID)

	// Re-apply remaining filters
	if err := t.reconcileCandidate(previous, next); err != nil {
		return 0, fmt.Errorf("failed to reapply filters after removal: %w", err)
	}
	t.commitCandidate(next)

	return 1, nil
}

// GetActiveFilters returns all currently active filters.
func (t *LocalTarget) GetActiveFilters() []*management.Filter {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filters := make([]*management.Filter, 0, len(t.filters))
	for _, f := range t.filters {
		filters = append(filters, cloneFilter(f))
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

func (t *LocalTarget) applyPolicy(policy LocalFilterPolicy, bpfUpdater BPFUpdater, appFilter AppFilterUpdater) error {
	filters := policy.Filters

	// Map iteration order is random. Stable ordering prevents an equivalent set
	// of BPF filters from looking changed merely because reconciliation visited
	// them in a different order.
	sort.Slice(filters, func(i, j int) bool {
		return filters[i].Id < filters[j].Id
	})

	bpfExpr := policy.BPFExpression
	appFilters := policy.ApplicationFilters

	// Apply BPF only when its effective expression changed. Phone-number, SIP
	// URI, Call-ID, and codec filters are userspace-only and must not restart
	// live capture when their reconciliation leaves BPF unchanged.
	t.bpfApplyMu.Lock()
	defer t.bpfApplyMu.Unlock()
	// Another reconciliation may have completed while this one was building its
	// expression, so refresh the applied state after entering the serial region.
	var lastAppliedBPF string
	var hasAppliedBPF bool
	t.mu.RLock()
	if t.bpfUpdater == bpfUpdater {
		lastAppliedBPF = t.lastAppliedBPF
		hasAppliedBPF = t.hasAppliedBPF
	} else {
		bpfUpdater = t.bpfUpdater
		hasAppliedBPF = false
	}
	t.mu.RUnlock()

	if bpfUpdater != nil && (!hasAppliedBPF || bpfExpr != lastAppliedBPF) {
		logger.Debug("LocalTarget applying BPF filter", "expression", bpfExpr)
		if err := bpfUpdater.SetBPFFilter(bpfExpr); err != nil {
			if bpfExpr == "" {
				return fmt.Errorf("failed to clear BPF filter: %w", err)
			}
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}

		t.mu.Lock()
		// Do not let a concurrent updater replacement inherit another updater's
		// applied state.
		if t.bpfUpdater == bpfUpdater {
			t.lastAppliedBPF = bpfExpr
			t.hasAppliedBPF = true
		}
		t.mu.Unlock()
	}
	// Apply application-layer filters
	if appFilter != nil {
		logger.Info("LocalTarget updating application filter",
			"filter_count", len(appFilters))
		appFilter.UpdateFilters(appFilters)
	} else {
		logger.Warn("LocalTarget has no application filter configured",
			"app_filter_count", len(appFilters))
	}

	return nil
}

type localTargetState struct {
	filters map[string]*management.Filter
	baseBPF string
	policy  LocalFilterPolicy
}

func (t *LocalTarget) candidateState(mutate func(map[string]*management.Filter)) (localTargetState, localTargetState) {
	t.mu.RLock()
	previous := localTargetState{filters: cloneFilterMap(t.filters), baseBPF: t.baseBPF}
	t.mu.RUnlock()
	next := localTargetState{filters: cloneFilterMap(previous.filters), baseBPF: previous.baseBPF}
	mutate(next.filters)
	previous.policy = t.buildPolicy(previous.baseBPF, previous.filters)
	next.policy = t.buildPolicy(next.baseBPF, next.filters)
	return previous, next
}

func (t *LocalTarget) reconcileCandidate(previous, next localTargetState) error {
	if effectivePoliciesEqual(previous.policy, next.policy) {
		return nil
	}
	t.mu.RLock()
	coordinator := t.coordinator
	bpfUpdater := t.bpfUpdater
	appFilter := t.appFilterFunc
	t.mu.RUnlock()
	if coordinator != nil {
		return coordinator.ReconcileLocalFilterChange(LocalFilterChange{
			Previous: clonePolicy(previous.policy),
			Next:     clonePolicy(next.policy),
		})
	}
	return t.applyPolicy(next.policy, bpfUpdater, appFilter)
}

func (t *LocalTarget) commitCandidate(next localTargetState) {
	t.mu.Lock()
	t.filters = cloneFilterMap(next.filters)
	t.baseBPF = next.baseBPF
	if t.coordinator != nil {
		t.lastAppliedBPF = next.policy.BPFExpression
		t.hasAppliedBPF = true
	}
	t.mu.Unlock()
}

func (t *LocalTarget) buildPolicy(baseBPF string, filters map[string]*management.Filter) LocalFilterPolicy {
	all := make([]*management.Filter, 0, len(filters))
	var bpfFilters, appFilters []*management.Filter
	for _, filter := range filters {
		f := cloneFilter(filter)
		all = append(all, f)
		if !f.Enabled {
			continue
		}
		switch f.Type {
		case management.FilterType_FILTER_BPF, management.FilterType_FILTER_IP_ADDRESS:
			bpfFilters = append(bpfFilters, f)
		case management.FilterType_FILTER_SIP_USER, management.FilterType_FILTER_PHONE_NUMBER,
			management.FilterType_FILTER_CALL_ID, management.FilterType_FILTER_CODEC:
			appFilters = append(appFilters, f)
		}
	}
	sortFilters(all)
	sortFilters(bpfFilters)
	sortFilters(appFilters)
	return LocalFilterPolicy{BaseBPF: baseBPF, BPFExpression: t.buildBPFExpression(baseBPF, bpfFilters), Filters: all, ApplicationFilters: appFilters}
}

func sortFilters(filters []*management.Filter) {
	sort.Slice(filters, func(i, j int) bool { return filters[i].Id < filters[j].Id })
}

func effectivePoliciesEqual(a, b LocalFilterPolicy) bool {
	if a.BPFExpression != b.BPFExpression || len(a.ApplicationFilters) != len(b.ApplicationFilters) {
		return false
	}
	for i := range a.ApplicationFilters {
		af, bf := a.ApplicationFilters[i], b.ApplicationFilters[i]
		if af.Id != bf.Id || af.Type != bf.Type || af.Pattern != bf.Pattern || af.Enabled != bf.Enabled {
			return false
		}
	}
	return true
}

func cloneFilter(filter *management.Filter) *management.Filter {
	if filter == nil {
		return nil
	}
	return proto.Clone(filter).(*management.Filter)
}

func cloneFilterMap(filters map[string]*management.Filter) map[string]*management.Filter {
	result := make(map[string]*management.Filter, len(filters))
	for id, filter := range filters {
		result[id] = cloneFilter(filter)
	}
	return result
}

func clonePolicy(policy LocalFilterPolicy) LocalFilterPolicy {
	return LocalFilterPolicy{BaseBPF: policy.BaseBPF, BPFExpression: policy.BPFExpression,
		Filters: cloneFilterSlice(policy.Filters), ApplicationFilters: cloneFilterSlice(policy.ApplicationFilters)}
}

func cloneFilterSlice(filters []*management.Filter) []*management.Filter {
	result := make([]*management.Filter, len(filters))
	for i, filter := range filters {
		result[i] = cloneFilter(filter)
	}
	return result
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
	t.mutationMu.Lock()
	defer t.mutationMu.Unlock()
	previous, next := t.candidateState(func(map[string]*management.Filter) {})
	next.baseBPF = bpf
	next.policy = t.buildPolicy(next.baseBPF, next.filters)
	if err := t.reconcileCandidate(previous, next); err != nil {
		return err
	}
	t.commitCandidate(next)
	return nil
}

// GetBaseBPF returns the current base BPF filter.
func (t *LocalTarget) GetBaseBPF() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.baseBPF
}

// Ensure LocalTarget implements FilterTarget.
var _ FilterTarget = (*LocalTarget)(nil)
