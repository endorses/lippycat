package sipusers

import (
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// SipUser represents a surveilled SIP user with optional expiration
type SipUser struct {
	ExpirationDate time.Time
}

// parsedPattern holds a parsed pattern with its type for matching
type parsedPattern struct {
	original    string                // Original pattern from user
	pattern     string                // Parsed pattern (wildcards stripped)
	patternType filtering.PatternType // Type of matching (prefix, suffix, contains)
}

var (
	// sipUserMap stores the SIP user metadata (expiration, etc.)
	sipUserMap = make(map[string]*SipUser)
	// parsedPatterns stores the parsed patterns for matching
	parsedPatterns = make(map[string]parsedPattern)
	muSu           sync.Mutex
)

func AddSipUser(username string, newSipUser *SipUser) {
	muSu.Lock()
	defer muSu.Unlock()
	_, exists := sipUserMap[username]
	if !exists {
		su := &SipUser{ExpirationDate: newSipUser.ExpirationDate}
		sipUserMap[username] = su

		// Normalize phone number patterns (e.g., +49123456789 → 49123456789)
		// This allows users to input phone numbers in various formats
		normalizedUsername := normalizeIfPhoneNumber(username)

		// Parse the pattern for wildcard support
		pattern, patternType := filtering.ParsePattern(normalizedUsername)
		parsedPatterns[username] = parsedPattern{
			original:    username,
			pattern:     pattern,
			patternType: patternType,
		}
	}
}

// normalizeIfPhoneNumber normalizes the input if it looks like a phone number.
// Returns the original input if it appears to be a SIP username (contains letters).
func normalizeIfPhoneNumber(input string) string {
	// tel: URIs are always phone numbers
	if strings.HasPrefix(input, "tel:") {
		return filtering.NormalizePhonePattern(input)
	}

	// Strip wildcards for detection
	working := strings.TrimPrefix(input, "*")
	working = strings.TrimSuffix(working, "*")

	// Strip common phone number prefixes for detection
	working = strings.TrimPrefix(working, "+")
	working = strings.TrimPrefix(working, "sip:")
	working = strings.TrimPrefix(working, "sips:")

	// If it has @ it's a SIP URI - extract user part for detection
	if atIdx := strings.IndexByte(working, '@'); atIdx != -1 {
		working = working[:atIdx]
	}

	// Check if remaining content is all digits (phone number)
	isPhoneNumber := true
	hasDigits := false
	for _, r := range working {
		if r >= '0' && r <= '9' {
			hasDigits = true
		} else if r != ' ' && r != '-' && r != '.' && r != '(' && r != ')' {
			// Contains non-digit, non-separator character - likely a username
			isPhoneNumber = false
			break
		}
	}

	if isPhoneNumber && hasDigits {
		return filtering.NormalizePhonePattern(input)
	}

	return input
}

func AddMultipleSipUsers(sipUsers map[string]*SipUser) {
	for username, sipUser := range sipUsers {
		AddSipUser(username, sipUser)
	}
}

func DeleteSipUser(username string) {
	muSu.Lock()
	defer muSu.Unlock()
	if _, ok := sipUserMap[username]; ok {
		delete(sipUserMap, username)
		delete(parsedPatterns, username)
	}
}

func DeleteMultipleSipUsers(usernames []string) {
	muSu.Lock()
	defer muSu.Unlock()
	for _, username := range usernames {
		delete(sipUserMap, username)
		delete(parsedPatterns, username)
	}
}

func ClearAll() {
	muSu.Lock()
	defer muSu.Unlock()
	sipUserMap = make(map[string]*SipUser)
	parsedPatterns = make(map[string]parsedPattern)
}

func HasSurveiled() bool {
	muSu.Lock()
	defer muSu.Unlock()
	return len(sipUserMap) > 0
}

// extractUserFromSIPURI extracts the username from a SIP URI
// Example: "Alicent <sip:alicent@domain.com>" -> "alicent"
// Example: "sip:robb@example.org" -> "robb"
// Example: "+49123456789" (already extracted) -> "+49123456789"
func extractUserFromSIPURI(uri string) string {
	// Find "sip:" or "sips:" prefix
	sipIdx := strings.Index(uri, "sip:")
	if sipIdx == -1 {
		sipIdx = strings.Index(uri, "sips:")
		if sipIdx == -1 {
			// No SIP URI found, the value might already be just the username
			// This happens when the caller extracts headers differently
			return uri
		}
		sipIdx += 5 // len("sips:")
	} else {
		sipIdx += 4 // len("sip:")
	}

	// Find the @ symbol
	remaining := uri[sipIdx:]
	atIdx := strings.Index(remaining, "@")
	if atIdx == -1 {
		return ""
	}

	return remaining[:atIdx]
}

func IsSurveiled(sipHeader string) bool {
	muSu.Lock()
	defer muSu.Unlock()

	// Extract username from the SIP header value
	// e.g., "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent"
	extractedUser := extractUserFromSIPURI(sipHeader)

	// Match against all parsed patterns
	for _, parsed := range parsedPatterns {
		// Match using the appropriate pattern type (prefix, suffix, contains)
		if filtering.Match(extractedUser, parsed.pattern, parsed.patternType) {
			return true
		}
	}

	return false
}
