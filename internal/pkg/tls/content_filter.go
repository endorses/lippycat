//go:build cli || hunter || tap || all

package tls

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ContentFilterConfig holds TLS content filter configuration.
type ContentFilterConfig struct {
	// SNIPatterns filters by SNI hostname (glob-style patterns).
	SNIPatterns []string

	// JA3Hashes filters by JA3 fingerprint (exact match, 32-char hex).
	JA3Hashes []string

	// JA3SHashes filters by JA3S fingerprint (exact match, 32-char hex).
	JA3SHashes []string

	// JA4Fingerprints filters by JA4 fingerprint (exact match).
	JA4Fingerprints []string
}

// ContentFilter applies content-based filtering to TLS metadata.
type ContentFilter struct {
	sniPatterns     []string
	ja3Hashes       map[string]bool // Lowercase for case-insensitive matching
	ja3sHashes      map[string]bool
	ja4Fingerprints map[string]bool
}

// NewContentFilter creates a new TLS content filter.
func NewContentFilter(config ContentFilterConfig) *ContentFilter {
	cf := &ContentFilter{
		sniPatterns:     config.SNIPatterns,
		ja3Hashes:       make(map[string]bool),
		ja3sHashes:      make(map[string]bool),
		ja4Fingerprints: make(map[string]bool),
	}

	// Normalize JA3 hashes to lowercase
	for _, h := range config.JA3Hashes {
		cf.ja3Hashes[strings.ToLower(strings.TrimSpace(h))] = true
	}

	// Normalize JA3S hashes to lowercase
	for _, h := range config.JA3SHashes {
		cf.ja3sHashes[strings.ToLower(strings.TrimSpace(h))] = true
	}

	// JA4 fingerprints are case-sensitive
	for _, fp := range config.JA4Fingerprints {
		cf.ja4Fingerprints[strings.TrimSpace(fp)] = true
	}

	return cf
}

// HasFilters returns true if any filters are configured.
func (cf *ContentFilter) HasFilters() bool {
	return len(cf.sniPatterns) > 0 ||
		len(cf.ja3Hashes) > 0 ||
		len(cf.ja3sHashes) > 0 ||
		len(cf.ja4Fingerprints) > 0
}

// Match checks if the TLS metadata matches any configured filter.
// Returns true if no filters are configured (pass-through mode).
// Uses OR logic: matches if ANY filter matches.
func (cf *ContentFilter) Match(metadata *types.TLSMetadata) bool {
	if !cf.HasFilters() {
		return true // No filters = pass everything
	}

	// Check SNI patterns (for ClientHello)
	if len(cf.sniPatterns) > 0 && metadata.SNI != "" {
		if filtering.MatchAnyGlob(cf.sniPatterns, metadata.SNI) {
			return true
		}
	}

	// Check JA3 hash (for ClientHello)
	if len(cf.ja3Hashes) > 0 && metadata.JA3Fingerprint != "" {
		if cf.ja3Hashes[strings.ToLower(metadata.JA3Fingerprint)] {
			return true
		}
	}

	// Check JA3S hash (for ServerHello)
	if len(cf.ja3sHashes) > 0 && metadata.JA3SFingerprint != "" {
		if cf.ja3sHashes[strings.ToLower(metadata.JA3SFingerprint)] {
			return true
		}
	}

	// Check JA4 fingerprint (for ClientHello)
	if len(cf.ja4Fingerprints) > 0 && metadata.JA4Fingerprint != "" {
		if cf.ja4Fingerprints[metadata.JA4Fingerprint] {
			return true
		}
	}

	return false
}

// MatchSNI checks if the SNI matches any SNI pattern.
func (cf *ContentFilter) MatchSNI(sni string) bool {
	if len(cf.sniPatterns) == 0 {
		return true
	}
	return filtering.MatchAnyGlob(cf.sniPatterns, sni)
}

// MatchJA3 checks if the JA3 fingerprint matches.
func (cf *ContentFilter) MatchJA3(fingerprint string) bool {
	if len(cf.ja3Hashes) == 0 {
		return true
	}
	return cf.ja3Hashes[strings.ToLower(fingerprint)]
}

// MatchJA3S checks if the JA3S fingerprint matches.
func (cf *ContentFilter) MatchJA3S(fingerprint string) bool {
	if len(cf.ja3sHashes) == 0 {
		return true
	}
	return cf.ja3sHashes[strings.ToLower(fingerprint)]
}

// MatchJA4 checks if the JA4 fingerprint matches.
func (cf *ContentFilter) MatchJA4(fingerprint string) bool {
	if len(cf.ja4Fingerprints) == 0 {
		return true
	}
	return cf.ja4Fingerprints[fingerprint]
}

// LoadSNIPatternsFromFile loads SNI patterns from a file.
func LoadSNIPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadJA3HashesFromFile loads JA3 hashes from a file.
func LoadJA3HashesFromFile(filename string) ([]string, error) {
	patterns, err := filtering.LoadPatternsFromFile(filename)
	if err != nil {
		return nil, err
	}

	// Validate and normalize hashes
	var hashes []string
	for _, h := range patterns {
		h = strings.ToLower(strings.TrimSpace(h))
		if IsValidJA3Hash(h) {
			hashes = append(hashes, h)
		}
	}
	return hashes, nil
}

// LoadJA3SHashesFromFile loads JA3S hashes from a file.
func LoadJA3SHashesFromFile(filename string) ([]string, error) {
	return LoadJA3HashesFromFile(filename) // Same format
}

// LoadJA4FingerprintsFromFile loads JA4 fingerprints from a file.
func LoadJA4FingerprintsFromFile(filename string) ([]string, error) {
	patterns, err := filtering.LoadPatternsFromFile(filename)
	if err != nil {
		return nil, err
	}

	// Validate fingerprints
	var fingerprints []string
	for _, fp := range patterns {
		fp = strings.TrimSpace(fp)
		if IsValidJA4Fingerprint(fp) {
			fingerprints = append(fingerprints, fp)
		}
	}
	return fingerprints, nil
}
