package http

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ContentFilterConfig holds HTTP content filter configuration.
type ContentFilterConfig struct {
	// HostPatterns filters by Host header (glob-style patterns).
	HostPatterns []string

	// URLPatterns filters by URL path (glob-style patterns).
	URLPatterns []string

	// Methods filters by HTTP method (exact match, case-insensitive).
	Methods []string

	// StatusCodes filters by response status code.
	// Supports individual codes (404) and ranges (4xx, 500-599).
	StatusCodes []string

	// UserAgentPatterns filters by User-Agent header (glob-style patterns).
	UserAgentPatterns []string

	// ContentTypePatterns filters by Content-Type header (glob-style patterns).
	ContentTypePatterns []string

	// Keywords are patterns to search in URL/headers using Aho-Corasick.
	Keywords []string
}

// ContentFilter applies content-based filtering to HTTP metadata.
type ContentFilter struct {
	hostPatterns        []string
	urlPatterns         []string
	methods             map[string]bool // Uppercase methods
	statusCodes         []statusCodeFilter
	userAgentPatterns   []string
	contentTypePatterns []string
	keywords            []string
	keywordsMatcher     *ahocorasick.BufferedMatcher
}

// statusCodeFilter represents a status code filter (exact or range).
type statusCodeFilter struct {
	exact      int  // Single code (e.g., 404)
	rangeStart int  // Range start (e.g., 400)
	rangeEnd   int  // Range end (e.g., 499)
	isRange    bool // True if this is a range filter
}

// NewContentFilter creates a new HTTP content filter.
func NewContentFilter(config ContentFilterConfig) *ContentFilter {
	cf := &ContentFilter{
		hostPatterns:        config.HostPatterns,
		urlPatterns:         config.URLPatterns,
		userAgentPatterns:   config.UserAgentPatterns,
		contentTypePatterns: config.ContentTypePatterns,
		keywords:            config.Keywords,
	}

	// Parse methods (uppercase for matching)
	if len(config.Methods) > 0 {
		cf.methods = make(map[string]bool)
		for _, m := range config.Methods {
			cf.methods[strings.ToUpper(m)] = true
		}
	}

	// Parse status codes
	if len(config.StatusCodes) > 0 {
		cf.statusCodes = parseStatusCodes(config.StatusCodes)
	}

	// Create Aho-Corasick matcher for keywords if provided
	if len(config.Keywords) > 0 {
		cf.keywordsMatcher = ahocorasick.NewBufferedMatcher()

		// Convert keywords to patterns (contains matching, case-insensitive)
		patterns := make([]ahocorasick.Pattern, len(config.Keywords))
		for i, kw := range config.Keywords {
			patterns[i] = ahocorasick.Pattern{
				ID:   i,
				Text: strings.ToLower(kw),
				Type: filtering.PatternTypeContains,
			}
		}
		cf.keywordsMatcher.UpdatePatternsSync(patterns)
	}

	return cf
}

// parseStatusCodes parses status code filters.
// Supports: "404", "4xx", "400-499"
func parseStatusCodes(codes []string) []statusCodeFilter {
	var filters []statusCodeFilter

	for _, code := range codes {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}

		// Check for range (e.g., "400-499")
		if idx := strings.Index(code, "-"); idx != -1 {
			start, err1 := strconv.Atoi(code[:idx])
			end, err2 := strconv.Atoi(code[idx+1:])
			if err1 == nil && err2 == nil && start <= end {
				filters = append(filters, statusCodeFilter{
					rangeStart: start,
					rangeEnd:   end,
					isRange:    true,
				})
				continue
			}
		}

		// Check for pattern (e.g., "4xx")
		if len(code) == 3 && (code[1] == 'x' || code[1] == 'X') && (code[2] == 'x' || code[2] == 'X') {
			digit := code[0] - '0'
			if digit >= 1 && digit <= 5 {
				filters = append(filters, statusCodeFilter{
					rangeStart: int(digit) * 100,
					rangeEnd:   int(digit)*100 + 99,
					isRange:    true,
				})
				continue
			}
		}

		// Exact code
		if exact, err := strconv.Atoi(code); err == nil && exact >= 100 && exact <= 599 {
			filters = append(filters, statusCodeFilter{
				exact: exact,
			})
		}
	}

	return filters
}

// HasFilters returns true if any filters are configured.
func (cf *ContentFilter) HasFilters() bool {
	return len(cf.hostPatterns) > 0 ||
		len(cf.urlPatterns) > 0 ||
		len(cf.methods) > 0 ||
		len(cf.statusCodes) > 0 ||
		len(cf.userAgentPatterns) > 0 ||
		len(cf.contentTypePatterns) > 0 ||
		cf.keywordsMatcher != nil
}

// Match checks if the HTTP metadata matches the configured filters.
// Returns true if no filters are configured (pass-through mode).
// Returns true if ALL configured filter groups match (AND logic between groups).
// Within each group, patterns are OR'd (any pattern in group matches).
func (cf *ContentFilter) Match(metadata *types.HTTPMetadata) bool {
	if !cf.HasFilters() {
		return true // No filters = pass everything
	}

	// Check host patterns
	if len(cf.hostPatterns) > 0 {
		if metadata.Host == "" || !filtering.MatchAnyGlob(cf.hostPatterns, metadata.Host) {
			return false
		}
	}

	// Check URL patterns
	if len(cf.urlPatterns) > 0 {
		if metadata.Path == "" || !filtering.MatchAnyGlob(cf.urlPatterns, metadata.Path) {
			return false
		}
	}

	// Check methods (only for requests)
	if len(cf.methods) > 0 && metadata.Type == "request" {
		if !cf.methods[strings.ToUpper(metadata.Method)] {
			return false
		}
	}

	// Check status codes (only for responses)
	if len(cf.statusCodes) > 0 && metadata.Type == "response" {
		if !cf.matchStatusCode(metadata.StatusCode) {
			return false
		}
	}

	// Check User-Agent patterns
	if len(cf.userAgentPatterns) > 0 {
		if metadata.UserAgent == "" || !filtering.MatchAnyGlob(cf.userAgentPatterns, metadata.UserAgent) {
			return false
		}
	}

	// Check Content-Type patterns
	if len(cf.contentTypePatterns) > 0 {
		if metadata.ContentType == "" || !filtering.MatchAnyGlob(cf.contentTypePatterns, metadata.ContentType) {
			return false
		}
	}

	// Check keyword matches (in URL and headers)
	if cf.keywordsMatcher != nil {
		found := false

		// Search in path
		if metadata.Path != "" {
			results := cf.keywordsMatcher.Match([]byte(strings.ToLower(metadata.Path)))
			if len(results) > 0 {
				found = true
			}
		}

		// Search in query string
		if !found && metadata.QueryString != "" {
			results := cf.keywordsMatcher.Match([]byte(strings.ToLower(metadata.QueryString)))
			if len(results) > 0 {
				found = true
			}
		}

		// Search in User-Agent
		if !found && metadata.UserAgent != "" {
			results := cf.keywordsMatcher.Match([]byte(strings.ToLower(metadata.UserAgent)))
			if len(results) > 0 {
				found = true
			}
		}

		if !found {
			return false
		}
	}

	return true
}

// matchStatusCode checks if a status code matches any configured filter.
func (cf *ContentFilter) matchStatusCode(code int) bool {
	for _, f := range cf.statusCodes {
		if f.isRange {
			if code >= f.rangeStart && code <= f.rangeEnd {
				return true
			}
		} else {
			if code == f.exact {
				return true
			}
		}
	}
	return false
}

// LoadHostPatternsFromFile loads host patterns from a file.
// Each line is a pattern. Empty lines and lines starting with # are ignored.
func LoadHostPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadURLPatternsFromFile loads URL patterns from a file.
// Each line is a pattern. Empty lines and lines starting with # are ignored.
func LoadURLPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadUserAgentPatternsFromFile loads User-Agent patterns from a file.
// Each line is a pattern. Empty lines and lines starting with # are ignored.
func LoadUserAgentPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadKeywordsFromFile loads keywords from a file for Aho-Corasick matching.
// Each line is a keyword. Empty lines and lines starting with # are ignored.
func LoadKeywordsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}
