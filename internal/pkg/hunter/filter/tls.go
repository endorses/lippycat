//go:build hunter || all

package filter

import (
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// TLSMatcher matches TLS SNI hostnames and JA3/JA3S/JA4 fingerprints.
// SNI supports glob-style wildcards: *.google.com, api.*
// JA3/JA3S/JA4 use exact hash matching.
type TLSMatcher struct {
	BaseProtocolMatcher
	sniPatterns []ParsedPattern
	ja3Hashes   map[string]string // hash -> filter ID
	ja3sHashes  map[string]string // hash -> filter ID
	ja4Patterns map[string]string // pattern -> filter ID
}

// NewTLSMatcher creates a new TLS matcher.
func NewTLSMatcher() *TLSMatcher {
	return &TLSMatcher{
		ja3Hashes:   make(map[string]string),
		ja3sHashes:  make(map[string]string),
		ja4Patterns: make(map[string]string),
	}
}

// UpdateFilters updates the matcher with new TLS filters.
func (m *TLSMatcher) UpdateFilters(filters []*management.Filter) {
	sniPatterns := make([]ParsedPattern, 0)
	ja3Hashes := make(map[string]string)
	ja3sHashes := make(map[string]string)
	ja4Patterns := make(map[string]string)

	for _, f := range filters {
		if !f.Enabled {
			continue
		}

		switch f.Type {
		case management.FilterType_FILTER_TLS_SNI:
			parsed, patternType := filtering.ParsePattern(f.Pattern)
			sniPatterns = append(sniPatterns, ParsedPattern{
				ID:          f.Id,
				Original:    f.Pattern,
				Pattern:     parsed,
				PatternType: patternType,
			})

		case management.FilterType_FILTER_TLS_JA3:
			// JA3 fingerprints are 32-char hex MD5 hashes - exact match
			hash := strings.ToLower(strings.TrimSpace(f.Pattern))
			ja3Hashes[hash] = f.Id

		case management.FilterType_FILTER_TLS_JA3S:
			// JA3S fingerprints are 32-char hex MD5 hashes - exact match
			hash := strings.ToLower(strings.TrimSpace(f.Pattern))
			ja3sHashes[hash] = f.Id

		case management.FilterType_FILTER_TLS_JA4:
			// JA4 fingerprints have format like t13d1516h2_8daaf6152771_b186095e22bb
			pattern := strings.TrimSpace(f.Pattern)
			ja4Patterns[pattern] = f.Id
		}
	}

	m.mu.Lock()
	m.sniPatterns = sniPatterns
	m.ja3Hashes = ja3Hashes
	m.ja3sHashes = ja3sHashes
	m.ja4Patterns = ja4Patterns
	m.mu.Unlock()

	logger.Debug("TLS filter updated",
		"sni_patterns", len(sniPatterns),
		"ja3_hashes", len(ja3Hashes),
		"ja3s_hashes", len(ja3sHashes),
		"ja4_patterns", len(ja4Patterns))
}

// Match is not implemented for raw packet data - use typed match methods.
func (m *TLSMatcher) Match(data []byte) (matched bool, filterIDs []string) {
	return false, nil
}

// MatchString tries to match as SNI first.
func (m *TLSMatcher) MatchString(value string) (matched bool, filterIDs []string) {
	return m.MatchSNI(value)
}

// MatchSNI checks if the SNI hostname matches any SNI filter pattern.
func (m *TLSMatcher) MatchSNI(hostname string) (matched bool, filterIDs []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.sniPatterns {
		if filtering.MatchGlob(p.Original, hostname) {
			filterIDs = append(filterIDs, p.ID)
			matched = true
		}
	}
	return matched, filterIDs
}

// MatchJA3 checks if the JA3 fingerprint matches any JA3 filter.
func (m *TLSMatcher) MatchJA3(fingerprint string) (matched bool, filterID string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hash := strings.ToLower(strings.TrimSpace(fingerprint))
	if id, found := m.ja3Hashes[hash]; found {
		return true, id
	}
	return false, ""
}

// MatchJA3S checks if the JA3S fingerprint matches any JA3S filter.
func (m *TLSMatcher) MatchJA3S(fingerprint string) (matched bool, filterID string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hash := strings.ToLower(strings.TrimSpace(fingerprint))
	if id, found := m.ja3sHashes[hash]; found {
		return true, id
	}
	return false, ""
}

// MatchJA4 checks if the JA4 fingerprint matches any JA4 filter.
func (m *TLSMatcher) MatchJA4(fingerprint string) (matched bool, filterID string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pattern := strings.TrimSpace(fingerprint)
	if id, found := m.ja4Patterns[pattern]; found {
		return true, id
	}
	return false, ""
}

// MatchTLSHandshake checks SNI and all fingerprints against TLS filters.
// Returns true if any filter matches.
func (m *TLSMatcher) MatchTLSHandshake(sni, ja3, ja3s, ja4 string) (matched bool, filterIDs []string) {
	seen := make(map[string]bool)

	// Check SNI
	if sni != "" {
		if ok, ids := m.MatchSNI(sni); ok {
			for _, id := range ids {
				if !seen[id] {
					seen[id] = true
					filterIDs = append(filterIDs, id)
				}
			}
			matched = true
		}
	}

	// Check JA3
	if ja3 != "" {
		if ok, id := m.MatchJA3(ja3); ok && !seen[id] {
			seen[id] = true
			filterIDs = append(filterIDs, id)
			matched = true
		}
	}

	// Check JA3S
	if ja3s != "" {
		if ok, id := m.MatchJA3S(ja3s); ok && !seen[id] {
			seen[id] = true
			filterIDs = append(filterIDs, id)
			matched = true
		}
	}

	// Check JA4
	if ja4 != "" {
		if ok, id := m.MatchJA4(ja4); ok && !seen[id] {
			seen[id] = true
			filterIDs = append(filterIDs, id)
			matched = true
		}
	}

	return matched, filterIDs
}

// HasFilters returns true if there are any active filters.
func (m *TLSMatcher) HasFilters() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sniPatterns) > 0 || len(m.ja3Hashes) > 0 || len(m.ja3sHashes) > 0 || len(m.ja4Patterns) > 0
}
