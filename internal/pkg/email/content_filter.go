package email

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ContentFilterConfig holds email content filter configuration.
type ContentFilterConfig struct {
	// SenderPatterns filters by MAIL FROM address (glob-style patterns).
	SenderPatterns []string

	// RecipientPatterns filters by RCPT TO addresses (glob-style patterns).
	RecipientPatterns []string

	// AddressPatterns filters by either sender OR recipient (glob-style patterns).
	AddressPatterns []string

	// SubjectPatterns filters by Subject header (glob-style patterns).
	SubjectPatterns []string

	// Keywords are patterns to search in subject/body using Aho-Corasick.
	Keywords []string
}

// ContentFilter applies content-based filtering to email metadata.
type ContentFilter struct {
	senderPatterns    []string
	recipientPatterns []string
	addressPatterns   []string
	subjectPatterns   []string
	keywords          []string
	keywordsMatcher   *ahocorasick.BufferedMatcher
}

// NewContentFilter creates a new email content filter.
func NewContentFilter(config ContentFilterConfig) *ContentFilter {
	cf := &ContentFilter{
		senderPatterns:    config.SenderPatterns,
		recipientPatterns: config.RecipientPatterns,
		addressPatterns:   config.AddressPatterns,
		subjectPatterns:   config.SubjectPatterns,
		keywords:          config.Keywords,
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

// HasFilters returns true if any filters are configured.
func (cf *ContentFilter) HasFilters() bool {
	return len(cf.senderPatterns) > 0 ||
		len(cf.recipientPatterns) > 0 ||
		len(cf.addressPatterns) > 0 ||
		len(cf.subjectPatterns) > 0 ||
		cf.keywordsMatcher != nil
}

// Match checks if the email metadata matches the configured filters.
// Returns true if no filters are configured (pass-through mode).
// Returns true if ALL configured filter groups match (AND logic between groups).
// Within each group, patterns are OR'd (any pattern in group matches).
func (cf *ContentFilter) Match(metadata *types.EmailMetadata) bool {
	if !cf.HasFilters() {
		return true // No filters = pass everything
	}

	// Check sender patterns (MAIL FROM)
	if len(cf.senderPatterns) > 0 {
		if metadata.MailFrom == "" || !filtering.MatchAnyGlob(cf.senderPatterns, metadata.MailFrom) {
			return false
		}
	}

	// Check recipient patterns (RCPT TO)
	if len(cf.recipientPatterns) > 0 {
		if !cf.matchAnyRecipient(metadata.RcptTo, cf.recipientPatterns) {
			return false
		}
	}

	// Check address patterns (sender OR recipient)
	if len(cf.addressPatterns) > 0 {
		if !cf.matchAnyAddress(metadata, cf.addressPatterns) {
			return false
		}
	}

	// Check subject patterns
	if len(cf.subjectPatterns) > 0 {
		if metadata.Subject == "" || !filtering.MatchAnyGlob(cf.subjectPatterns, metadata.Subject) {
			return false
		}
	}

	// Check keyword matches (in subject)
	if cf.keywordsMatcher != nil {
		if metadata.Subject != "" {
			// Match returns slice of MatchResults; we just need any match
			results := cf.keywordsMatcher.Match([]byte(strings.ToLower(metadata.Subject)))
			if len(results) == 0 {
				return false
			}
		} else {
			// No subject to match keywords against
			return false
		}
	}

	return true
}

// matchAnyRecipient checks if any recipient matches any pattern.
func (cf *ContentFilter) matchAnyRecipient(recipients []string, patterns []string) bool {
	if len(recipients) == 0 {
		return false
	}
	for _, rcpt := range recipients {
		if filtering.MatchAnyGlob(patterns, rcpt) {
			return true
		}
	}
	return false
}

// matchAnyAddress checks if sender or any recipient matches any pattern.
func (cf *ContentFilter) matchAnyAddress(metadata *types.EmailMetadata, patterns []string) bool {
	// Check sender
	if metadata.MailFrom != "" && filtering.MatchAnyGlob(patterns, metadata.MailFrom) {
		return true
	}

	// Check recipients
	for _, rcpt := range metadata.RcptTo {
		if filtering.MatchAnyGlob(patterns, rcpt) {
			return true
		}
	}

	return false
}

// LoadEmailPatternsFromFile loads email address patterns from a file.
// Each line is a pattern. Empty lines and lines starting with # are ignored.
func LoadEmailPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadSubjectPatternsFromFile loads subject patterns from a file.
// Each line is a pattern. Empty lines and lines starting with # are ignored.
func LoadSubjectPatternsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}

// LoadKeywordsFromFile loads keywords from a file for Aho-Corasick matching.
// Each line is a keyword. Empty lines and lines starting with # are ignored.
func LoadKeywordsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}
