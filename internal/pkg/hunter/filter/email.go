//go:build hunter || tap || all

package filter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// EmailMatcher matches email addresses and subjects.
// Supports glob-style wildcards: *@example.com, admin@*, *confidential*
type EmailMatcher struct {
	BaseProtocolMatcher
	addressPatterns []ParsedPattern
	subjectPatterns []ParsedPattern
}

// NewEmailMatcher creates a new email matcher.
func NewEmailMatcher() *EmailMatcher {
	return &EmailMatcher{}
}

// UpdateFilters updates the matcher with new email filters.
func (m *EmailMatcher) UpdateFilters(filters []*management.Filter) {
	addressPatterns := make([]ParsedPattern, 0)
	subjectPatterns := make([]ParsedPattern, 0)

	for _, f := range filters {
		if !f.Enabled {
			continue
		}

		parsed, patternType := filtering.ParsePattern(f.Pattern)
		pattern := ParsedPattern{
			ID:          f.Id,
			Original:    f.Pattern,
			Pattern:     parsed,
			PatternType: patternType,
		}

		switch f.Type {
		case management.FilterType_FILTER_EMAIL_ADDRESS:
			addressPatterns = append(addressPatterns, pattern)
		case management.FilterType_FILTER_EMAIL_SUBJECT:
			subjectPatterns = append(subjectPatterns, pattern)
		}
	}

	m.mu.Lock()
	m.addressPatterns = addressPatterns
	m.subjectPatterns = subjectPatterns
	m.mu.Unlock()

	logger.Debug("Email filter updated",
		"address_patterns", len(addressPatterns),
		"subject_patterns", len(subjectPatterns))
}

// Match is not implemented for raw packet data - use typed match methods.
func (m *EmailMatcher) Match(data []byte) (matched bool, filterIDs []string) {
	return false, nil
}

// MatchString matches against both address and subject patterns.
func (m *EmailMatcher) MatchString(value string) (matched bool, filterIDs []string) {
	// Try address match first, then subject
	if matched, filterIDs = m.MatchAddress(value); matched {
		return matched, filterIDs
	}
	return m.MatchSubject(value)
}

// MatchAddress checks if the email address matches any address filter pattern.
func (m *EmailMatcher) MatchAddress(address string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.addressPatterns {
		if filtering.MatchGlob(p.Original, address) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}

// MatchSubject checks if the email subject matches any subject filter pattern.
func (m *EmailMatcher) MatchSubject(subject string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.subjectPatterns {
		if filtering.MatchGlob(p.Original, subject) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}

// MatchEnvelope checks sender, recipient, and subject against all email filters.
// Returns true if any filter matches.
func (m *EmailMatcher) MatchEnvelope(sender, recipient, subject string) (matched bool, filterIDs []string) {
	seen := make(map[string]bool)

	// Check sender
	if ok, ids := m.MatchAddress(sender); ok {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				filterIDs = append(filterIDs, id)
			}
		}
		matched = true
	}

	// Check recipient
	if ok, ids := m.MatchAddress(recipient); ok {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				filterIDs = append(filterIDs, id)
			}
		}
		matched = true
	}

	// Check subject
	if ok, ids := m.MatchSubject(subject); ok {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				filterIDs = append(filterIDs, id)
			}
		}
		matched = true
	}

	return matched, filterIDs
}

// HasFilters returns true if there are any active filters.
func (m *EmailMatcher) HasFilters() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.addressPatterns) > 0 || len(m.subjectPatterns) > 0
}
