//go:build tui || all

package filters

import (
	"fmt"
	"strings"
)

// VoIPFilter filters based on VoIP-specific criteria (packet-only filter)
type VoIPFilter struct {
	field    string // "user", "from", "to", "fromtag", "totag", "method", "callid", "codec"
	value    string // value to match (supports wildcards like "555*")
	wildcard bool   // whether value contains wildcards
}

// NewVoIPFilter creates a new VoIP filter
func NewVoIPFilter(field, value string) *VoIPFilter {
	wildcard := strings.Contains(value, "*")
	return &VoIPFilter{
		field:    field,
		value:    value,
		wildcard: wildcard,
	}
}

// Match checks if the record matches the VoIP filter
// This filter only supports packet records
func (f *VoIPFilter) Match(record Filterable) bool {
	// VoIP filter only works on packets
	if record.RecordType() != "packet" {
		return false
	}

	// Check protocol - only match SIP packets
	if record.GetStringField("protocol") != "SIP" {
		return false
	}

	// Get field value using Filterable interface
	var fieldValue string
	switch f.field {
	case "user", "from":
		fieldValue = record.GetStringField("sip.user")
		if fieldValue == "" {
			fieldValue = record.GetStringField("sip.from")
		}
	case "to":
		fieldValue = record.GetStringField("sip.to")
	case "fromtag":
		fieldValue = record.GetStringField("sip.fromtag")
	case "totag":
		fieldValue = record.GetStringField("sip.totag")
	case "method":
		fieldValue = record.GetStringField("sip.method")
	case "callid":
		fieldValue = record.GetStringField("sip.callid")
	case "codec":
		fieldValue = record.GetStringField("sip.codec")
	}

	// Fall back to parsing Info string if field value not available
	if fieldValue == "" {
		info := strings.ToLower(record.GetStringField("info"))
		switch f.field {
		case "user", "from":
			// Look for "From: " or "sip:" in the info
			if idx := strings.Index(info, "from:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			} else if idx := strings.Index(info, "sip:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}

		case "to":
			if idx := strings.Index(info, "to:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}

		case "method":
			// SIP methods appear at the start of the info
			words := strings.Fields(record.GetStringField("info"))
			if len(words) > 0 {
				fieldValue = words[0]
			}

		case "callid":
			if idx := strings.Index(info, "call-id:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}
		}
	}

	if fieldValue == "" {
		return false
	}

	// Match with wildcard support
	return f.matchValue(strings.ToLower(fieldValue))
}

// matchValue matches a value with wildcard support
func (f *VoIPFilter) matchValue(value string) bool {
	if !f.wildcard {
		// Exact match (case-insensitive)
		return strings.Contains(value, strings.ToLower(f.value))
	}

	// Wildcard matching
	pattern := strings.ToLower(f.value)

	// Handle simple prefix/suffix wildcards
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *pattern* - contains
		return strings.Contains(value, strings.Trim(pattern, "*"))
	} else if strings.HasPrefix(pattern, "*") {
		// *pattern - ends with
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	} else if strings.HasSuffix(pattern, "*") {
		// pattern* - starts with
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}

	// Default to contains
	return strings.Contains(value, pattern)
}

// String returns a human-readable representation
func (f *VoIPFilter) String() string {
	return fmt.Sprintf("sip.%s:%s", f.field, f.value)
}

// Type returns the filter type
func (f *VoIPFilter) Type() string {
	return "voip"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// VoIP filters are moderately selective - they pre-filter by SIP protocol
func (f *VoIPFilter) Selectivity() float64 {
	return 0.7 // Moderately selective - only applies to SIP packets
}

// SupportedRecordTypes returns ["packet"] as VoIP filters only work on packets
func (f *VoIPFilter) SupportedRecordTypes() []string {
	return []string{"packet"}
}

// extractSIPField extracts a SIP field value from a string
func extractSIPField(s string) string {
	// Simple extraction - get everything up to the next space or special char
	var result strings.Builder
	inBrackets := false
	started := false

	for _, r := range s {
		if r == '<' {
			inBrackets = true
			continue
		}
		if r == '>' {
			break
		}
		if !started && (r == ' ' || r == ':') {
			continue
		}
		if !inBrackets && (r == ' ' || r == ';' || r == ',') {
			break
		}
		started = true
		result.WriteRune(r)
	}

	return strings.TrimSpace(result.String())
}
