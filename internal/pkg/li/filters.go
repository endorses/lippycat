// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// FilterManager handles the mapping between LI intercept tasks and lippycat filters.
//
// It translates ETSI TS 103 280 target identities into the internal filter system:
//   - SIPURI (sip:user@domain) → FILTER_SIP_URI
//   - TELURI (tel:+number) → FILTER_PHONE_NUMBER
//   - NAI (user@realm) → FILTER_SIP_URI
//   - IPv4Address/IPv6Address → FILTER_IP_ADDRESS
//   - IPv4CIDR/IPv6CIDR → FILTER_IP_ADDRESS
//   - Username → FILTER_SIP_USER
//
// The manager maintains a bidirectional mapping between task XIDs and filter IDs
// to enable correlation when packets match filters.
type FilterManager struct {
	mu sync.RWMutex

	// xidToFilters maps task XID to its associated filter IDs.
	// A single task may have multiple targets, each becoming a filter.
	xidToFilters map[uuid.UUID][]string

	// filterToXID maps filter ID back to the task XID.
	// Used when a packet matches a filter to find the intercept task.
	filterToXID map[string]uuid.UUID

	// filterStore holds all LI-generated filters.
	// Key is filter ID, value is the filter proto.
	filterStore map[string]*management.Filter

	// filterPusher is called to push filter updates to hunters.
	// This integrates with the processor's filter management system.
	filterPusher FilterPusher
}

// FilterPusher is the interface for pushing filter updates to the filter management system.
type FilterPusher interface {
	// UpdateFilter adds or updates a filter and pushes it to affected hunters.
	UpdateFilter(filter *management.Filter) error
	// DeleteFilter removes a filter and notifies affected hunters.
	DeleteFilter(filterID string) error
}

// FilterLister is an optional FilterPusher capability reporting all installed
// filter IDs, including ones restored from disk that this process did not
// create. Startup reconciliation needs it: a persisted LI filter outlives the
// registry, so no local task refers to it after a restart.
type FilterLister interface {
	ListFilterIDs() []string
}

// FilterCleanupError means replacement filters were installed but superseded
// filters could not all be withdrawn. Residual IDs remain tracked for retry.
type FilterCleanupError struct{ Err error }

func (e *FilterCleanupError) Error() string { return e.Err.Error() }
func (e *FilterCleanupError) Unwrap() error { return e.Err }

// liFilterIDPrefix marks a filter as LI-owned: prefix + XID prefix + "-" + index.
const liFilterIDPrefix = "li-"

// liFilterXIDPrefix extracts the canonical XID from new filter IDs and the
// eight-character prefix from legacy IDs. False is returned for malformed IDs.
func liFilterXIDPrefix(filterID string) (string, bool) {
	if !strings.HasPrefix(filterID, liFilterIDPrefix) {
		return "", false
	}
	rest := filterID[len(liFilterIDPrefix):]
	sep := strings.LastIndex(rest, "-")
	if sep <= 0 || sep == len(rest)-1 {
		return "", false
	}
	owner := rest[:sep]
	if len(owner) == 8 {
		return owner, true
	}
	// A canonical UUID contains internal hyphens; validating it avoids treating
	// arbitrary operator filter names beginning with li- as task ownership.
	if xid, err := uuid.Parse(owner); err == nil && xid.String() == strings.ToLower(owner) {
		return xid.String(), true
	}
	return "", false
}

// NewFilterManager creates a new filter manager.
//
// The filterPusher is used to push filter updates to the processor's filter
// management system. Pass nil for testing without actual filter propagation.
func NewFilterManager(filterPusher FilterPusher) *FilterManager {
	return &FilterManager{
		xidToFilters: make(map[uuid.UUID][]string),
		filterToXID:  make(map[string]uuid.UUID),
		filterStore:  make(map[string]*management.Filter),
		filterPusher: filterPusher,
	}
}

// CreateFiltersForTask creates filters for all targets in an intercept task.
//
// Each target identity is mapped to the appropriate filter type and pushed
// to the filter management system. Returns the list of created filter IDs.
func (m *FilterManager) CreateFiltersForTask(task *InterceptTask) ([]string, error) {
	if task == nil {
		return nil, fmt.Errorf("task is nil")
	}
	if len(task.Targets) == 0 {
		return nil, fmt.Errorf("task has no targets")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if task already has filters
	if _, exists := m.xidToFilters[task.XID]; exists {
		return nil, fmt.Errorf("filters already exist for task %s", task.XID)
	}

	var filterIDs []string
	var createdFilters []*management.Filter

	// Create a filter for each target
	for i, target := range task.Targets {
		filter, err := m.targetToFilter(task.XID, i, target)
		if err != nil {
			// Rollback: remove any filters we've already created
			for _, f := range createdFilters {
				delete(m.filterStore, f.Id)
				delete(m.filterToXID, f.Id)
			}
			return nil, fmt.Errorf("failed to create filter for target %d: %w", i, err)
		}

		if owner, ok := m.filterToXID[filter.Id]; ok && owner != task.XID {
			return nil, fmt.Errorf("create filters for XID %s: filter ID %s is owned by XID %s", task.XID, filter.Id, owner)
		}
		if _, ok := m.filterStore[filter.Id]; ok {
			return nil, fmt.Errorf("create filters for XID %s: filter ID %s already exists", task.XID, filter.Id)
		}
		filterIDs = append(filterIDs, filter.Id)
		createdFilters = append(createdFilters, filter)
	}

	var pushed []string
	if m.filterPusher != nil {
		for _, filter := range createdFilters {
			if err := m.filterPusher.UpdateFilter(filter); err != nil {
				pushErr := fmt.Errorf("install filters for XID %s: update filter %s: %w", task.XID, filter.Id, err)
				rollbackErr := m.rollbackRemoteFiltersLocked(task.XID, pushed)
				if rollbackErr != nil {
					return nil, errors.Join(pushErr, rollbackErr)
				}
				return nil, fmt.Errorf("%w; rollback succeeded", pushErr)
			}
			pushed = append(pushed, filter.Id)
		}
	}

	for _, filter := range createdFilters {
		m.filterStore[filter.Id] = filter
		m.filterToXID[filter.Id] = task.XID
	}
	m.xidToFilters[task.XID] = filterIDs

	return filterIDs, nil
}

func (m *FilterManager) rollbackRemoteFiltersLocked(xid uuid.UUID, filterIDs []string) error {
	if m.filterPusher == nil {
		return nil
	}
	var errs []error
	var residual []string
	for i := len(filterIDs) - 1; i >= 0; i-- {
		id := filterIDs[i]
		if err := m.filterPusher.DeleteFilter(id); err != nil {
			residual = append(residual, id)
			errs = append(errs, fmt.Errorf("rollback XID %s delete filter %s: %w", xid, id, err))
		}
	}
	if len(errs) != 0 {
		logger.Error("LI filter rollback left remotely installed filters", "xid", xid, "residual_filter_ids", residual, "error", errors.Join(errs...))
	}
	return errors.Join(errs...)
}

// UpdateFiltersForTask atomically updates filters when a task is modified.
//
// This removes existing filters and creates new ones based on the updated targets.
// If any filter creation fails, the operation is rolled back.
func (m *FilterManager) UpdateFiltersForTask(task *InterceptTask) error {
	if task == nil {
		return fmt.Errorf("task is nil")
	}

	m.mu.Lock()

	// Get existing filter IDs
	existingIDs, exists := m.xidToFilters[task.XID]
	if !exists {
		// No existing filters, unlock and create new ones
		m.mu.Unlock()
		_, err := m.CreateFiltersForTask(task)
		return err
	}

	// From here on, we hold the lock until the end
	defer m.mu.Unlock()

	// Target position is part of the filter identity. Reusing these canonical IDs
	// keeps a target stable across modification and reactivation instead of
	// allocating an ever-increasing index.
	var newFilterIDs []string
	var newFilters []*management.Filter
	for i, target := range task.Targets {
		filter, err := m.targetToFilter(task.XID, i, target)
		if err != nil {
			return fmt.Errorf("construct replacement filters for XID %s target %d: %w", task.XID, i, err)
		}
		if owner, ok := m.filterToXID[filter.Id]; ok && owner != task.XID {
			return fmt.Errorf("replace filters for XID %s: filter ID %s is owned by XID %s", task.XID, filter.Id, owner)
		}
		newFilterIDs = append(newFilterIDs, filter.Id)
		newFilters = append(newFilters, filter)
	}

	// Update canonical IDs in place. If a push fails, restore every already
	// changed filter to its previous definition (or delete it if it was new).
	if m.filterPusher != nil {
		var pushed []*management.Filter
		for _, filter := range newFilters {
			if err := m.filterPusher.UpdateFilter(filter); err != nil {
				pushErr := fmt.Errorf("install replacement filters for XID %s: update filter %s: %w", task.XID, filter.Id, err)
				var rollbackErrs []error
				for i := len(pushed) - 1; i >= 0; i-- {
					applied := pushed[i]
					if previous, ok := m.filterStore[applied.Id]; ok {
						if restoreErr := m.filterPusher.UpdateFilter(previous); restoreErr != nil {
							rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback XID %s restore filter %s: %w", task.XID, applied.Id, restoreErr))
						}
					} else if deleteErr := m.filterPusher.DeleteFilter(applied.Id); deleteErr != nil {
						rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback XID %s delete filter %s: %w", task.XID, applied.Id, deleteErr))
					}
				}
				return errors.Join(pushErr, errors.Join(rollbackErrs...))
			}
			pushed = append(pushed, filter)
		}
	}

	// Commit replacements locally before deleting old filters. If deletion is
	// partial, residual IDs remain mapped so a later Remove/Update can retry.
	for _, filter := range newFilters {
		m.filterStore[filter.Id] = filter
		m.filterToXID[filter.Id] = task.XID
	}
	committedIDs := append([]string(nil), newFilterIDs...)
	newIDSet := make(map[string]bool, len(newFilterIDs))
	for _, id := range newFilterIDs {
		newIDSet[id] = true
	}
	var deleteErrs []error
	for _, id := range existingIDs {
		if newIDSet[id] {
			continue
		}
		if m.filterPusher != nil {
			if err := m.filterPusher.DeleteFilter(id); err != nil {
				committedIDs = append(committedIDs, id)
				deleteErrs = append(deleteErrs, fmt.Errorf("replace filters for XID %s: delete old filter %s: %w", task.XID, id, err))
				continue
			}
		}
		delete(m.filterStore, id)
		delete(m.filterToXID, id)
	}
	m.xidToFilters[task.XID] = committedIDs
	if len(deleteErrs) != 0 {
		logger.Error("LI filter replacement left old filters installed", "xid", task.XID, "filter_ids", committedIDs[len(newFilterIDs):], "error", errors.Join(deleteErrs...))
		return &FilterCleanupError{Err: errors.Join(deleteErrs...)}
	}

	return nil
}

// RemoveFiltersForTask removes all filters associated with a task.
//
// Called when a task is deactivated.
func (m *FilterManager) RemoveFiltersForTask(xid uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	filterIDs, exists := m.xidToFilters[xid]
	if !exists {
		return nil // No filters to remove
	}

	var deleteErrs []error
	var residual []string
	for _, id := range filterIDs {
		if m.filterPusher != nil {
			if err := m.filterPusher.DeleteFilter(id); err != nil {
				residual = append(residual, id)
				deleteErrs = append(deleteErrs, fmt.Errorf("remove filters for XID %s: delete filter %s: %w", xid, id, err))
				continue
			}
		}
		delete(m.filterStore, id)
		delete(m.filterToXID, id)
	}
	if len(residual) == 0 {
		delete(m.xidToFilters, xid)
	} else {
		m.xidToFilters[xid] = residual
		logger.Error("LI task filter removal incomplete", "xid", xid, "residual_filter_ids", residual, "error", errors.Join(deleteErrs...))
	}
	return errors.Join(deleteErrs...)
}

// GetXIDForFilter returns the task XID associated with a filter.
//
// Used when a packet matches a filter to find the intercept task
// for X2/X3 delivery.
func (m *FilterManager) GetXIDForFilter(filterID string) (uuid.UUID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	xid, exists := m.filterToXID[filterID]
	return xid, exists
}

// GetFiltersForXID returns all filter IDs associated with a task.
func (m *FilterManager) GetFiltersForXID(xid uuid.UUID) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids, exists := m.xidToFilters[xid]
	if !exists {
		return nil
	}

	// Return a copy
	result := make([]string, len(ids))
	copy(result, ids)
	return result
}

// GetFilter returns a filter by ID.
func (m *FilterManager) GetFilter(filterID string) (*management.Filter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, exists := m.filterStore[filterID]
	if !exists {
		return nil, false
	}

	// Return a copy (proto.Clone handles the protobuf message correctly)
	return proto.Clone(f).(*management.Filter), true
}

// FilterCount returns the total number of filters.
func (m *FilterManager) FilterCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.filterStore)
}

// TaskCount returns the number of tasks with filters.
func (m *FilterManager) TaskCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.xidToFilters)
}

// targetToFilter converts an ETSI target identity to a lippycat filter.
func (m *FilterManager) targetToFilter(xid uuid.UUID, index int, target TargetIdentity) (*management.Filter, error) {
	filterType, pattern, err := m.mapTargetToFilterType(target)
	if err != nil {
		return nil, err
	}

	// Generate a unique filter ID that includes the XID for traceability
	filterID := fmt.Sprintf(liFilterIDPrefix+"%s-%d", xid.String(), index)

	return &management.Filter{
		Id:          filterID,
		Type:        filterType,
		Pattern:     pattern,
		Enabled:     true,
		Description: fmt.Sprintf("LI task %s target %d: %s", xid.String(), index, target.Type),
	}, nil
}

// mapTargetToFilterType maps an ETSI target type to lippycat filter type and pattern.
func (m *FilterManager) mapTargetToFilterType(target TargetIdentity) (management.FilterType, string, error) {
	switch target.Type {
	case TargetTypeSIPURI:
		// sip:user@domain → extract user@domain for SIP URI filter
		pattern := extractSIPURIPattern(target.Value)
		return management.FilterType_FILTER_SIP_URI, pattern, nil

	case TargetTypeTELURI:
		// tel:+15551234567 → extract phone number for phone number filter
		pattern := extractPhonePattern(target.Value)
		return management.FilterType_FILTER_PHONE_NUMBER, pattern, nil

	case TargetTypeNAI:
		// user@realm has same format as SIP URI (user@domain)
		return management.FilterType_FILTER_SIP_URI, target.Value, nil

	case TargetTypeIPv4Address, TargetTypeIPv6Address:
		// Direct IP address
		return management.FilterType_FILTER_IP_ADDRESS, target.Value, nil

	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		// CIDR notation (e.g., 10.0.0.0/8)
		return management.FilterType_FILTER_IP_ADDRESS, target.Value, nil

	case TargetTypeUsername:
		// SIP user part only (existing SIP_USER filter)
		return management.FilterType_FILTER_SIP_USER, target.Value, nil

	case TargetTypeIMSI:
		// IMSI (15 digits) from Authorization or P-Asserted-Identity
		pattern := normalizeIMSI(target.Value)
		if pattern == "" {
			return 0, "", fmt.Errorf("invalid IMSI format: %s", target.Value)
		}
		return management.FilterType_FILTER_IMSI, pattern, nil

	case TargetTypeIMEI:
		// IMEI (15 digits) from Contact +sip.instance
		pattern := normalizeIMEI(target.Value)
		if pattern == "" {
			return 0, "", fmt.Errorf("invalid IMEI format: %s", target.Value)
		}
		return management.FilterType_FILTER_IMEI, pattern, nil

	default:
		return 0, "", fmt.Errorf("unsupported target type: %s", target.Type)
	}
}

// extractSIPURIPattern extracts the user@domain from a SIP URI.
// Input: "sip:alice@example.com" or "sip:alice@example.com;transport=tcp"
// Output: "alice@example.com"
func extractSIPURIPattern(uri string) string {
	// Remove sip: or sips: prefix
	pattern := uri
	if strings.HasPrefix(strings.ToLower(pattern), "sips:") {
		pattern = pattern[5:]
	} else if strings.HasPrefix(strings.ToLower(pattern), "sip:") {
		pattern = pattern[4:]
	}

	// Remove URI parameters (after ';')
	if idx := strings.Index(pattern, ";"); idx != -1 {
		pattern = pattern[:idx]
	}

	// Remove port if present
	if idx := strings.LastIndex(pattern, ":"); idx != -1 {
		// Check if this is IPv6 (has more than one colon) or a port
		if strings.Count(pattern, ":") == 1 {
			// Simple host:port case
			atIdx := strings.Index(pattern, "@")
			if atIdx != -1 && idx > atIdx {
				// Port is after the @, so strip it
				pattern = pattern[:idx]
			}
		}
	}

	return pattern
}

// normalizeIMSI validates and normalizes an IMSI to 15 digits.
// Returns empty string if the IMSI is invalid.
func normalizeIMSI(imsi string) string {
	// Extract only digits
	var digits strings.Builder
	for _, r := range imsi {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}

	result := digits.String()

	// IMSI must be exactly 15 digits
	if len(result) != 15 {
		return ""
	}

	return result
}

// normalizeIMEI validates and normalizes an IMEI.
// Accepts various formats:
//   - Plain digits: "353456789012345"
//   - URN format: "urn:gsma:imei:35345678-9012345-0"
//   - With dashes: "35-345678-9012345-0"
//
// Returns empty string if the IMEI is invalid.
func normalizeIMEI(imei string) string {
	// Remove urn:gsma:imei: prefix if present
	lower := strings.ToLower(imei)
	if strings.HasPrefix(lower, "urn:gsma:imei:") {
		imei = imei[14:]
	} else if strings.HasPrefix(lower, "urn:urn-7:3gpp-imei:") {
		imei = imei[20:]
	}

	// Extract only digits
	var digits strings.Builder
	for _, r := range imei {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}

	result := digits.String()

	// IMEI should be 14 or 15 digits (with or without check digit)
	if len(result) != 14 && len(result) != 15 {
		return ""
	}

	// Pad to 15 if only 14 digits (append 0 as placeholder check digit)
	if len(result) == 14 {
		result = result + "0"
	}

	return result
}

// extractPhonePattern extracts the phone number from a tel: URI.
// Input: "tel:+15551234567" or "tel:+1-555-123-4567"
// Output: "15551234567" (digits only, no leading +)
func extractPhonePattern(uri string) string {
	// Remove tel: prefix
	pattern := uri
	if strings.HasPrefix(strings.ToLower(pattern), "tel:") {
		pattern = pattern[4:]
	}

	// Remove visual separators and leading +
	var result strings.Builder
	for _, r := range pattern {
		if r >= '0' && r <= '9' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// MatchResult contains the result of a filter match lookup.
type MatchResult struct {
	// XID is the intercept task that matched.
	XID uuid.UUID
	// FilterID is the specific filter that matched.
	FilterID string
	// Filter is the filter configuration.
	Filter *management.Filter
}

// LookupFilter returns one LI-owned filter without applying task-level
// deduplication. Provenance validation must inspect every supplied filter before
// matches for the same XID can be collapsed.
func (m *FilterManager) LookupFilter(filterID string) (MatchResult, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	xid, exists := m.filterToXID[filterID]
	if !exists {
		return MatchResult{}, false
	}
	filter, exists := m.filterStore[filterID]
	if !exists {
		return MatchResult{}, false
	}
	return MatchResult{XID: xid, FilterID: filterID, Filter: filter}, true
}

// LookupMatches finds all LI tasks that would match a given filter match.
//
// This is called by the packet processing pipeline when a filter matches.
// It returns all matching tasks for X2/X3 delivery.
func (m *FilterManager) LookupMatches(matchedFilterIDs []string) []MatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []MatchResult
	seen := make(map[uuid.UUID]bool)

	for _, filterID := range matchedFilterIDs {
		// Check if this is an LI filter
		xid, exists := m.filterToXID[filterID]
		if !exists {
			continue
		}

		// Avoid duplicates if multiple filters match for same task
		if seen[xid] {
			continue
		}
		seen[xid] = true

		filter, _ := m.filterStore[filterID]
		results = append(results, MatchResult{
			XID:      xid,
			FilterID: filterID,
			Filter:   filter,
		})
	}

	return results
}
