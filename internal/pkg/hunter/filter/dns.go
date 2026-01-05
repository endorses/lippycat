//go:build hunter || all

package filter

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// DNSMatcher matches DNS domain patterns.
// Supports glob-style wildcards: *.example.com, malware.*, *bad-domain*
type DNSMatcher struct {
	BaseProtocolMatcher
}

// NewDNSMatcher creates a new DNS domain matcher.
func NewDNSMatcher() *DNSMatcher {
	return &DNSMatcher{}
}

// UpdateFilters updates the matcher with new DNS domain filters.
func (m *DNSMatcher) UpdateFilters(filters []*management.Filter) {
	patterns := make([]ParsedPattern, 0)

	for _, f := range filters {
		if f.Type != management.FilterType_FILTER_DNS_DOMAIN {
			continue
		}
		if !f.Enabled {
			continue
		}

		parsed, patternType := filtering.ParsePattern(f.Pattern)
		patterns = append(patterns, ParsedPattern{
			ID:          f.Id,
			Original:    f.Pattern,
			Pattern:     parsed,
			PatternType: patternType,
		})
	}

	m.SetPatterns(patterns)
	logger.Debug("DNS domain filter updated", "pattern_count", len(patterns))
}

// Match checks if DNS packet data contains a matching domain.
// For DNS, we typically extract the query name from the packet payload.
// This method expects the extracted domain name, not raw packet data.
func (m *DNSMatcher) Match(data []byte) (matched bool, filterIDs []string) {
	// For raw packet matching, we would need to parse DNS wire format
	// This is a placeholder - actual implementation would parse the DNS query
	return false, nil
}

// MatchString checks if the domain matches any filter pattern.
func (m *DNSMatcher) MatchString(domain string) (matched bool, filterIDs []string) {
	return m.MatchStringWithPatterns(domain)
}

// MatchDomain is an alias for MatchString for clarity.
func (m *DNSMatcher) MatchDomain(domain string) (matched bool, filterIDs []string) {
	return m.MatchString(domain)
}
