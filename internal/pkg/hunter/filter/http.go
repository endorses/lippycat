//go:build hunter || all

package filter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// HTTPMatcher matches HTTP Host headers and URL paths.
// Supports glob-style wildcards: *.example.com, /api/*, */admin/*
type HTTPMatcher struct {
	BaseProtocolMatcher
	hostPatterns []ParsedPattern
	urlPatterns  []ParsedPattern
}

// NewHTTPMatcher creates a new HTTP matcher.
func NewHTTPMatcher() *HTTPMatcher {
	return &HTTPMatcher{}
}

// UpdateFilters updates the matcher with new HTTP filters.
func (m *HTTPMatcher) UpdateFilters(filters []*management.Filter) {
	hostPatterns := make([]ParsedPattern, 0)
	urlPatterns := make([]ParsedPattern, 0)

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
		case management.FilterType_FILTER_HTTP_HOST:
			hostPatterns = append(hostPatterns, pattern)
		case management.FilterType_FILTER_HTTP_URL:
			urlPatterns = append(urlPatterns, pattern)
		}
	}

	m.mu.Lock()
	m.hostPatterns = hostPatterns
	m.urlPatterns = urlPatterns
	m.mu.Unlock()

	logger.Debug("HTTP filter updated",
		"host_patterns", len(hostPatterns),
		"url_patterns", len(urlPatterns))
}

// Match is not implemented for raw packet data - use typed match methods.
func (m *HTTPMatcher) Match(data []byte) (matched bool, filterIDs []string) {
	return false, nil
}

// MatchString matches against both host and URL patterns.
func (m *HTTPMatcher) MatchString(value string) (matched bool, filterIDs []string) {
	// Try host match first, then URL
	if matched, filterIDs = m.MatchHost(value); matched {
		return matched, filterIDs
	}
	return m.MatchURL(value)
}

// MatchHost checks if the HTTP Host header matches any host filter pattern.
func (m *HTTPMatcher) MatchHost(host string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.hostPatterns {
		if filtering.MatchGlob(p.Original, host) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}

// MatchURL checks if the URL path matches any URL filter pattern.
func (m *HTTPMatcher) MatchURL(url string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.urlPatterns {
		if filtering.MatchGlob(p.Original, url) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}

// MatchRequest checks host and URL against all HTTP filters.
// Returns true if any filter matches.
func (m *HTTPMatcher) MatchRequest(host, url string) (matched bool, filterIDs []string) {
	seen := make(map[string]bool)

	// Check host
	if ok, ids := m.MatchHost(host); ok {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				filterIDs = append(filterIDs, id)
			}
		}
		matched = true
	}

	// Check URL
	if ok, ids := m.MatchURL(url); ok {
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
func (m *HTTPMatcher) HasFilters() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.hostPatterns) > 0 || len(m.urlPatterns) > 0
}
