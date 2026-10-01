// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

// FilterManager handles the mapping between LI intercept tasks and lippycat filters.
//
// It translates ETSI TS 103 280 target identities into the internal filter system:
//   - SIPURI (sip:user@domain) → FILTER_SIP_URI
//   - TELURI (tel:+number) → FILTER_PHONE_NUMBER
//   - NAI (user@realm) → exact RADIUS compound criterion
//   - IPv4Address/IPv6Address → FILTER_IP_ADDRESS
//   - IPv4CIDR/IPv6CIDR → FILTER_IP_ADDRESS
//   - Username → FILTER_SIP_USER
//
// The manager maintains a bidirectional mapping between task XIDs and filter IDs
// to enable correlation when packets match filters.
type FilterManager struct {
	// External pushes may drain packet processing, whose lookups require mu.
	// Serialize mutations separately and never hold mu across those calls.
	mutationMu sync.Mutex
	mu         sync.RWMutex

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

// FilterCleanupError means filter reconciliation left unfinished enforcement or
// withdrawal. Residual IDs remain tracked for retry without granting admission.
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

// filterMapping is a detached mutation candidate. Maps and protobufs published
// to packet readers never change in place.
type filterMapping struct {
	xidToFilters map[uuid.UUID][]string
	filterToXID  map[string]uuid.UUID
	filterStore  map[string]*management.Filter
}

func (m *FilterManager) snapshotMapping() filterMapping {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := filterMapping{make(map[uuid.UUID][]string, len(m.xidToFilters)), make(map[string]uuid.UUID, len(m.filterToXID)), make(map[string]*management.Filter, len(m.filterStore))}
	for xid, ids := range m.xidToFilters {
		state.xidToFilters[xid] = append([]string(nil), ids...)
	}
	for id, xid := range m.filterToXID {
		state.filterToXID[id] = xid
	}
	for id, filter := range m.filterStore {
		state.filterStore[id] = proto.Clone(filter).(*management.Filter)
	}
	return state
}

func (m *FilterManager) publishMapping(state filterMapping) {
	m.mu.Lock()
	m.xidToFilters, m.filterToXID, m.filterStore = state.xidToFilters, state.filterToXID, state.filterStore
	m.mu.Unlock()
}

// keepCleanup retains a potentially installed ID without making it an active
// LI correlation. Cleanup obligations must never imply authorization.
func (s *filterMapping) keepCleanup(xid uuid.UUID, id string) {
	delete(s.filterStore, id)
	delete(s.filterToXID, id)
	for _, existing := range s.xidToFilters[xid] {
		if existing == id {
			return
		}
	}
	s.xidToFilters[xid] = append(s.xidToFilters[xid], id)
}

func filterPushError(out securestore.Outcome, err error) error {
	return &securestore.CommitError{Outcome: out, Op: "reconcile LI filters", Err: err}
}

// rollbackFilters runs under mutationMu, with no packet-lookup lock held. A
// committed warning still establishes the restored/deleted desired definition.
// Uncertainty stops subsequent mutations and retains every unfinished cleanup ID.
func (m *FilterManager) rollbackFilters(xid uuid.UUID, applied []*management.Filter, previous filterMapping, candidate *filterMapping) (bool, error) {
	var errs []error
	unresolved := false
	for i := len(applied) - 1; i >= 0; i-- {
		id := applied[i].Id
		var err error
		if old := previous.filterStore[id]; old != nil {
			err = m.filterPusher.UpdateFilter(proto.Clone(old).(*management.Filter))
		} else {
			err = m.filterPusher.DeleteFilter(id)
		}
		if err == nil {
			continue
		}
		errs = append(errs, fmt.Errorf("rollback XID %s filter %s: %w", xid, id, err))
		if securestore.OutcomeOf(err) != securestore.Committed {
			candidate.keepCleanup(xid, id)
			unresolved = true
		}
		if securestore.OutcomeOf(err) == securestore.Uncertain {
			for _, pending := range applied[:i] {
				candidate.keepCleanup(xid, pending.Id)
			}
			break
		}
	}
	return unresolved, errors.Join(errs...)
}

func (m *FilterManager) pushCandidate(xid uuid.UUID, filters []*management.Filter, previous filterMapping, candidate *filterMapping) error {
	if m.filterPusher == nil {
		return nil
	}
	var applied []*management.Filter
	for _, filter := range filters {
		err := m.filterPusher.UpdateFilter(proto.Clone(filter).(*management.Filter))
		if err == nil {
			applied = append(applied, filter)
			continue
		}
		outcome := securestore.OutcomeOf(err)
		pushErr := fmt.Errorf("install filters for XID %s filter %s: %w", xid, filter.Id, err)
		if outcome != securestore.NotCommitted {
			// This failed call may already have installed its candidate too.
			applied = append(applied, filter)
		}
		if outcome == securestore.Uncertain {
			for _, affected := range applied {
				candidate.keepCleanup(xid, affected.Id)
			}
			m.publishMapping(*candidate)
			return &FilterCleanupError{Err: filterPushError(securestore.Uncertain, pushErr)}
		}
		unresolved, rollbackErr := m.rollbackFilters(xid, applied, previous, candidate)
		if unresolved {
			m.publishMapping(*candidate)
			return &FilterCleanupError{Err: filterPushError(securestore.Uncertain, errors.Join(pushErr, rollbackErr))}
		}
		// The complete prior desired policy was restored. Preserve nested
		// committed warnings while describing the compound operation as failed.
		return filterPushError(securestore.NotCommitted, errors.Join(pushErr, rollbackErr))
	}
	return nil
}

// CreateFiltersForTask installs all target filters before publishing correlations.
func (m *FilterManager) CreateFiltersForTask(task *InterceptTask) ([]string, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	return m.createFiltersForTask(task)
}

func (m *FilterManager) createFiltersForTask(task *InterceptTask) ([]string, error) {
	if task == nil || len(task.Targets) == 0 {
		return nil, errors.New("task with targets is required")
	}
	candidate := m.snapshotMapping()
	if _, exists := candidate.xidToFilters[task.XID]; exists {
		return nil, fmt.Errorf("filters or cleanup obligations already exist for task %s", task.XID)
	}
	filters, err := m.filtersForTask(task)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(filters))
	for _, filter := range filters {
		if _, exists := candidate.filterToXID[filter.Id]; exists {
			return nil, fmt.Errorf("filter ID already has an owner")
		}
		ids = append(ids, filter.Id)
	}
	if err := m.pushCandidate(task.XID, filters, candidate, &candidate); err != nil {
		return nil, err
	}
	for _, filter := range filters {
		candidate.filterStore[filter.Id] = filter
		candidate.filterToXID[filter.Id] = task.XID
	}
	candidate.xidToFilters[task.XID] = append([]string(nil), ids...)
	m.publishMapping(candidate)
	return ids, nil
}

// UpdateFiltersForTask stages replacements while packet lookups retain the old
// immutable map. Failed compensation keeps cleanup IDs, without authorization.
func (m *FilterManager) UpdateFiltersForTask(task *InterceptTask) error {
	if task == nil {
		return errors.New("task is nil")
	}
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	candidate := m.snapshotMapping()
	existingIDs, exists := candidate.xidToFilters[task.XID]
	if !exists {
		_, err := m.createFiltersForTask(task)
		return err
	}
	filters, err := m.filtersForTask(task)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(filters))
	newIDs := make(map[string]bool, len(filters))
	for _, filter := range filters {
		if owner, exists := candidate.filterToXID[filter.Id]; exists && owner != task.XID {
			return errors.New("replacement filter ID already has a different owner")
		}
		ids = append(ids, filter.Id)
		newIDs[filter.Id] = true
	}
	if err := m.pushCandidate(task.XID, filters, candidate, &candidate); err != nil {
		return err
	}
	for _, filter := range filters {
		candidate.filterStore[filter.Id] = filter
		candidate.filterToXID[filter.Id] = task.XID
	}
	var errs []error
	uncertain := false
	for _, id := range existingIDs {
		if newIDs[id] {
			continue
		}
		var err error
		if !uncertain && m.filterPusher != nil {
			err = m.filterPusher.DeleteFilter(id)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("replace filters for XID %s delete old filter %s: %w", task.XID, id, err))
			uncertain = securestore.OutcomeOf(err) == securestore.Uncertain
		}
		if uncertain || (err != nil && securestore.OutcomeOf(err) != securestore.Committed) {
			ids = append(ids, id)
		}
		// Superseded definitions never remain an authorization source, even
		// when their external withdrawal needs a later cleanup attempt.
		delete(candidate.filterStore, id)
		delete(candidate.filterToXID, id)
	}
	candidate.xidToFilters[task.XID] = ids
	m.publishMapping(candidate)
	if len(errs) != 0 {
		out := securestore.Committed
		if uncertain {
			out = securestore.Uncertain
		}
		return &FilterCleanupError{Err: filterPushError(out, errors.Join(errs...))}
	}
	return nil
}

// RemoveFiltersForTask withdraws correlations and retains failed cleanup IDs.
func (m *FilterManager) RemoveFiltersForTask(xid uuid.UUID) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	candidate := m.snapshotMapping()
	ids, exists := candidate.xidToFilters[xid]
	if !exists {
		return nil
	}
	var errs []error
	var residual []string
	uncertain := false
	for _, id := range ids {
		var err error
		if !uncertain && m.filterPusher != nil {
			err = m.filterPusher.DeleteFilter(id)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("remove filters for XID %s delete filter %s: %w", xid, id, err))
			uncertain = securestore.OutcomeOf(err) == securestore.Uncertain
		}
		if uncertain || (err != nil && securestore.OutcomeOf(err) != securestore.Committed) {
			residual = append(residual, id)
		}
		delete(candidate.filterStore, id)
		delete(candidate.filterToXID, id)
	}
	if len(residual) == 0 {
		delete(candidate.xidToFilters, xid)
	} else {
		candidate.xidToFilters[xid] = residual
	}
	m.publishMapping(candidate)
	if len(errs) == 0 {
		return nil
	}
	out := securestore.Committed
	if uncertain {
		out = securestore.Uncertain
	}
	return filterPushError(out, errors.Join(errs...))
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

	case TargetTypeTELURI, TargetTypeE164:
		if target.Type == TargetTypeE164 && !schema.ValidE164Number(target.Value) {
			return 0, "", fmt.Errorf("invalid E.164 target: expected 1–15 digits")
		}
		// tel:+15551234567 → extract phone number for phone number filter
		pattern := extractPhonePattern(target.Value)
		return management.FilterType_FILTER_PHONE_NUMBER, pattern, nil

	case TargetTypeNAI:
		if err := radius.ValidateNAI(target.Value); err != nil {
			return 0, "", err
		}
		return management.FilterType_FILTER_RADIUS_USERNAME, target.Value, nil
	case TargetTypeMACAddress:
		raw, err := hex.DecodeString(target.Value)
		if err != nil || len(raw) != 6 {
			return 0, "", fmt.Errorf("MAC target requires six hex-encoded octets")
		}
		parts := make([]string, 6)
		for i, b := range raw {
			parts[i] = fmt.Sprintf("%02X", b)
		}
		return management.FilterType_FILTER_RADIUS_MAC, strings.Join(parts, "-"), nil
	case TargetTypeRADIUSAttribute:
		p, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateAttribute, Value: target.Value})
		if err != nil {
			return 0, "", err
		}
		return management.FilterType_FILTER_RADIUS_ATTRIBUTE, p.Spec().Value, nil

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
	if !exists || filter == nil {
		return MatchResult{}, false
	}
	return MatchResult{XID: xid, FilterID: filterID, Filter: proto.Clone(filter).(*management.Filter)}, true
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

		filter := m.filterStore[filterID]
		if filter == nil {
			continue
		}
		results = append(results, MatchResult{
			XID:      xid,
			FilterID: filterID,
			Filter:   proto.Clone(filter).(*management.Filter),
		})
	}

	return results
}

// IsRADIUSTask identifies tasks containing any RADIUS identity. Mixed protocol
// tasks are recognized here so validation rejects them before filter creation.
func IsRADIUSTask(task *InterceptTask) bool {
	if task == nil {
		return false
	}
	for _, target := range task.Targets {
		if target.Type == TargetTypeNAI || target.Type == TargetTypeMACAddress || target.Type == TargetTypeRADIUSAttribute {
			return true
		}
	}
	return false
}

func (m *FilterManager) filtersForTask(task *InterceptTask) ([]*management.Filter, error) {
	if !IsRADIUSTask(task) {
		var result []*management.Filter
		for i, t := range task.Targets {
			f, err := m.targetToFilter(task.XID, i, t)
			if err != nil {
				return nil, err
			}
			result = append(result, f)
		}
		return result, nil
	}
	f, err := m.radiusFilterForTask(task)
	if err != nil {
		return nil, err
	}
	return []*management.Filter{f}, nil
}

func (m *FilterManager) radiusFilterForTask(task *InterceptTask) (*management.Filter, error) {
	if task.DeliveryType != DeliveryX2Only {
		return nil, fmt.Errorf("%w: RADIUS requires X2Only", ErrUnsupportedDeliveryCombination)
	}
	if task.ActivationGeneration == 0 {
		return nil, fmt.Errorf("RADIUS task requires positive activation generation")
	}
	id := fmt.Sprintf(liFilterIDPrefix+"%s-0", task.XID)
	f := &management.Filter{Id: id, Type: management.FilterType_FILTER_RADIUS_COMPOUND, Enabled: true, Revision: task.ActivationGeneration, Description: fmt.Sprintf("LI RADIUS task %s", task.XID), Radius: &management.RadiusFilterCriteria{}}
	f.Radius.GroupId = id
	f.Radius.TaskId = task.XID.String()
	f.Radius.TaskGeneration = task.ActivationGeneration
	f.Radius.Scope = &management.RadiusScopeBinding{OperatorScope: task.RADIUSScope.OperatorScope, ProfileRevision: task.RADIUSScope.ProfileRevision, OriginNodeId: task.RADIUSScope.OriginNodeID, SourceId: task.RADIUSScope.SourceID}
	for i, t := range canonicalizeTargets(task.Targets) {
		ft, value, err := m.mapTargetToFilterType(t)
		if err != nil {
			return nil, err
		}
		c := &management.RadiusCriterion{Value: value, FilterId: fmt.Sprintf("%s/criterion-%d", id, i), FilterRevision: f.Revision}
		switch ft {
		case management.FilterType_FILTER_RADIUS_USERNAME:
			c.Kind = radius.PredicateUserName
			c.TargetKind = "nai"
		case management.FilterType_FILTER_RADIUS_MAC:
			c.Kind = radius.PredicateMAC
			c.TargetKind = "mac"
			c.MacProfile = task.RADIUSMACProfile
		case management.FilterType_FILTER_RADIUS_ATTRIBUTE:
			c.Kind = radius.PredicateAttribute
		default:
			return nil, fmt.Errorf("RADIUS criteria cannot combine with %s", t.Type)
		}
		p, err := radius.CompilePredicate(radius.PredicateSpec{Kind: c.Kind, Value: c.Value, MACProfile: c.MacProfile, TargetKind: c.TargetKind})
		if err != nil {
			return nil, err
		}
		c.TargetKind = p.Spec().TargetKind
		f.Radius.Criteria = append(f.Radius.Criteria, c)
	}
	if _, _, err := filtering.CompileRADIUSFilter(f); err != nil {
		return nil, err
	}
	return f, nil
}

// LookupRADIUSGroup returns an immutable matcher for the installed task revision.
func (m *FilterManager) LookupRADIUSGroup(filterID string) (*radius.Group, bool) {
	f, ok := m.GetFilter(filterID)
	if !ok {
		return nil, false
	}
	_, g, err := filtering.CompileRADIUSFilter(f)
	return g, err == nil && g != nil
}
