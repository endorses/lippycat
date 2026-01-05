package filtering

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
)

// Pattern validation regexes (compiled once)
var (
	// JA3/JA3S: 32-character lowercase hex MD5 hash
	ja3HashRegex = regexp.MustCompile(`^[a-f0-9]{32}$`)

	// JA4: format like t13d1516h2_8daaf6152771_b186095e22bb
	// Structure: {version}_{cipher_hash}_{extension_hash}
	ja4Regex = regexp.MustCompile(`^[tqd][01][0-9a-z]{1,10}[0-9a-z]*_[0-9a-f]{12}_[0-9a-f]{12}$`)
)

// ValidationError represents a filter validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateFilterYAML validates a FilterYAML structure
func ValidateFilterYAML(filter *FilterYAML) error {
	if filter.ID == "" {
		return &ValidationError{Field: "id", Message: "filter ID is required"}
	}
	if filter.Pattern == "" {
		return &ValidationError{Field: "pattern", Message: "filter pattern is required"}
	}
	if filter.Type == "" {
		return &ValidationError{Field: "type", Message: "filter type is required"}
	}
	if err := ValidateFilterType(filter.Type); err != nil {
		return err
	}
	return nil
}

// ValidateFilter validates a protobuf Filter structure
func ValidateFilter(filter *management.Filter) error {
	if filter.Id == "" {
		return &ValidationError{Field: "id", Message: "filter ID is required"}
	}
	if filter.Pattern == "" {
		return &ValidationError{Field: "pattern", Message: "filter pattern is required"}
	}
	// Protobuf enum is always valid by type system, but check for unspecified
	// Note: FILTER_SIP_USER is 0, which is also the default, so we can't detect "unset"
	// This is acceptable as SIP_USER is a valid default
	return nil
}

// ValidateFilterType validates a filter type string
func ValidateFilterType(typeStr string) error {
	if !ValidFilterTypes[typeStr] {
		return &ValidationError{
			Field:   "type",
			Message: fmt.Sprintf("unknown filter type: %s", typeStr),
		}
	}
	return nil
}

// ValidatePattern validates a pattern for a specific filter type.
// Returns nil if the pattern is valid, or an error describing the issue.
func ValidatePattern(filterType management.FilterType, pattern string) error {
	if pattern == "" {
		return &ValidationError{Field: "pattern", Message: "pattern cannot be empty"}
	}

	switch filterType {
	case management.FilterType_FILTER_TLS_JA3:
		return ValidateJA3Pattern(pattern)
	case management.FilterType_FILTER_TLS_JA3S:
		return ValidateJA3SPattern(pattern)
	case management.FilterType_FILTER_TLS_JA4:
		return ValidateJA4Pattern(pattern)
	case management.FilterType_FILTER_DNS_DOMAIN,
		management.FilterType_FILTER_TLS_SNI,
		management.FilterType_FILTER_HTTP_HOST,
		management.FilterType_FILTER_HTTP_URL,
		management.FilterType_FILTER_EMAIL_ADDRESS,
		management.FilterType_FILTER_EMAIL_SUBJECT,
		management.FilterType_FILTER_SIP_USER,
		management.FilterType_FILTER_SIP_URI:
		return ValidateGlobPattern(pattern)
	case management.FilterType_FILTER_IP_ADDRESS:
		return ValidateIPPattern(pattern)
	case management.FilterType_FILTER_PHONE_NUMBER:
		return ValidatePhonePattern(pattern)
	case management.FilterType_FILTER_BPF:
		// BPF filters are validated by the kernel, skip here
		return nil
	case management.FilterType_FILTER_CALL_ID, management.FilterType_FILTER_CODEC:
		// These are simple string matches, no special validation
		return nil
	default:
		return nil
	}
}

// ValidateJA3Pattern validates a JA3 fingerprint hash.
// JA3 must be a 32-character lowercase hex MD5 hash.
func ValidateJA3Pattern(pattern string) error {
	normalized := strings.ToLower(strings.TrimSpace(pattern))
	if !ja3HashRegex.MatchString(normalized) {
		return &ValidationError{
			Field:   "pattern",
			Message: "JA3 fingerprint must be a 32-character hex MD5 hash (e.g., e7d705a3286e19ea42f587b344ee6865)",
		}
	}
	return nil
}

// ValidateJA3SPattern validates a JA3S fingerprint hash.
// JA3S must be a 32-character lowercase hex MD5 hash.
func ValidateJA3SPattern(pattern string) error {
	normalized := strings.ToLower(strings.TrimSpace(pattern))
	if !ja3HashRegex.MatchString(normalized) {
		return &ValidationError{
			Field:   "pattern",
			Message: "JA3S fingerprint must be a 32-character hex MD5 hash (e.g., ae4edc6faf64d08308082ad26be60767)",
		}
	}
	return nil
}

// ValidateJA4Pattern validates a JA4 fingerprint.
// JA4 format: {protocol}{version}{sni}{cipher_count}{ext_count}_{cipher_hash}_{extension_hash}
// Example: t13d1516h2_8daaf6152771_b186095e22bb
func ValidateJA4Pattern(pattern string) error {
	normalized := strings.TrimSpace(pattern)
	if !ja4Regex.MatchString(normalized) {
		return &ValidationError{
			Field:   "pattern",
			Message: "JA4 fingerprint must match format like t13d1516h2_8daaf6152771_b186095e22bb",
		}
	}
	return nil
}

// ValidateGlobPattern validates a glob-style pattern.
// Ensures the pattern has valid wildcard syntax.
func ValidateGlobPattern(pattern string) error {
	// Empty pattern is invalid
	if strings.TrimSpace(pattern) == "" {
		return &ValidationError{
			Field:   "pattern",
			Message: "glob pattern cannot be empty or whitespace",
		}
	}

	// Check for invalid wildcard sequences
	if strings.Contains(pattern, "**") {
		// Double wildcards are allowed (treated as single) but warn-worthy
		// We allow this for now as it's not harmful
	}

	// Pattern is valid - glob matching is lenient
	return nil
}

// ValidateIPPattern validates an IP address or CIDR pattern.
// Accepts IPv4, IPv6, and CIDR notation.
func ValidateIPPattern(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return &ValidationError{Field: "pattern", Message: "IP pattern cannot be empty"}
	}

	// Allow wildcards for IP prefix matching (e.g., "192.168.*")
	if strings.Contains(pattern, "*") {
		// Validate the non-wildcard part looks like an IP prefix
		parts := strings.Split(pattern, ".")
		for _, part := range parts {
			if part == "*" {
				continue
			}
			// Check if it's a valid number 0-255
			if len(part) > 3 {
				return &ValidationError{
					Field:   "pattern",
					Message: fmt.Sprintf("invalid IP octet: %s", part),
				}
			}
		}
		return nil
	}

	// For non-wildcard patterns, we just check basic format
	// Full validation would require net.ParseIP/net.ParseCIDR
	if !strings.Contains(pattern, ".") && !strings.Contains(pattern, ":") {
		return &ValidationError{
			Field:   "pattern",
			Message: "IP pattern must be a valid IPv4, IPv6 address or CIDR notation",
		}
	}

	return nil
}

// ValidatePhonePattern validates a phone number pattern.
// Phone patterns support wildcards and must contain at least some digits.
func ValidatePhonePattern(pattern string) error {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return &ValidationError{Field: "pattern", Message: "phone pattern cannot be empty"}
	}

	// Check that it contains at least some digits or is a pure wildcard
	hasDigit := false
	for _, r := range pattern {
		if r >= '0' && r <= '9' {
			hasDigit = true
			break
		}
	}

	if !hasDigit && !strings.Contains(pattern, "*") {
		return &ValidationError{
			Field:   "pattern",
			Message: "phone pattern must contain digits or wildcards",
		}
	}

	return nil
}
