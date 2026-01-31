// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/endorses/lippycat/api/gen/management"
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

		// Store the filter
		m.filterStore[filter.Id] = filter
		m.filterToXID[filter.Id] = task.XID
		filterIDs = append(filterIDs, filter.Id)
		createdFilters = append(createdFilters, filter)
	}

	// Store the XID to filter IDs mapping
	m.xidToFilters[task.XID] = filterIDs

	// Push filters to hunters
	if m.filterPusher != nil {
		for _, filter := range createdFilters {
			if err := m.filterPusher.UpdateFilter(filter); err != nil {
				// Log error but don't fail - filter is still stored locally
				// In production, this would trigger a retry mechanism
			}
		}
	}

	return filterIDs, nil
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

	// Store existing filters for potential rollback
	existingFilters := make([]*management.Filter, 0, len(existingIDs))
	for _, id := range existingIDs {
		if f, ok := m.filterStore[id]; ok {
			existingFilters = append(existingFilters, proto.Clone(f).(*management.Filter))
		}
	}

	// Remove existing filters from local store
	for _, id := range existingIDs {
		delete(m.filterStore, id)
		delete(m.filterToXID, id)
	}
	delete(m.xidToFilters, task.XID)

	// Create new filters
	var newFilterIDs []string
	var newFilters []*management.Filter

	for i, target := range task.Targets {
		filter, err := m.targetToFilter(task.XID, i, target)
		if err != nil {
			// Rollback: restore existing filters
			for _, f := range existingFilters {
				m.filterStore[f.Id] = f
				m.filterToXID[f.Id] = task.XID
			}
			m.xidToFilters[task.XID] = existingIDs
			return fmt.Errorf("failed to create filter for target %d: %w", i, err)
		}

		m.filterStore[filter.Id] = filter
		m.filterToXID[filter.Id] = task.XID
		newFilterIDs = append(newFilterIDs, filter.Id)
		newFilters = append(newFilters, filter)
	}

	m.xidToFilters[task.XID] = newFilterIDs

	// Push updates to hunters
	if m.filterPusher != nil {
		// Delete old filters
		for _, id := range existingIDs {
			if err := m.filterPusher.DeleteFilter(id); err != nil {
				// Log error but continue
			}
		}
		// Add new filters
		for _, filter := range newFilters {
			if err := m.filterPusher.UpdateFilter(filter); err != nil {
				// Log error but continue
			}
		}
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

	// Remove from local store and notify hunters
	for _, id := range filterIDs {
		delete(m.filterStore, id)
		delete(m.filterToXID, id)

		if m.filterPusher != nil {
			if err := m.filterPusher.DeleteFilter(id); err != nil {
				// Log error but continue
			}
		}
	}

	delete(m.xidToFilters, xid)
	return nil
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
	filterID := fmt.Sprintf("li-%s-%d", xid.String()[:8], index)

	return &management.Filter{
		Id:          filterID,
		Type:        filterType,
		Pattern:     pattern,
		Enabled:     true,
		Description: fmt.Sprintf("LI task %s target %d: %s", xid.String()[:8], index, target.Type),
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
