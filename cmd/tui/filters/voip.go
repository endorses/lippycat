//go:build tui || all
// +build tui all

package filters

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/cmd/tui/components"
)

// VoIPFilter filters based on VoIP-specific criteria
type VoIPFilter struct {
	field    string // "user", "from", "to", "method", "callid", "codec"
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

// Match checks if the packet matches the VoIP filter
func (f *VoIPFilter) Match(packet components.PacketDisplay) bool {
	// Only match SIP packets for now
	if packet.Protocol != "SIP" {
		return false
	}

	// Extract the field value from the packet info
	var fieldValue string
	info := strings.ToLower(packet.Info)

	switch f.field {
	case "user", "from":
		// Look for "From: " or "sip:" in the info
		if idx := strings.Index(info, "from:"); idx != -1 {
			fieldValue = extractSIPField(packet.Info[idx:])
		} else if idx := strings.Index(info, "sip:"); idx != -1 {
			fieldValue = extractSIPField(packet.Info[idx:])
		}

	case "to":
		if idx := strings.Index(info, "to:"); idx != -1 {
			fieldValue = extractSIPField(packet.Info[idx:])
		}

	case "method":
		// SIP methods appear at the start of the info
		words := strings.Fields(packet.Info)
		if len(words) > 0 {
			fieldValue = words[0]
		}

	case "callid":
		if idx := strings.Index(info, "call-id:"); idx != -1 {
			fieldValue = extractSIPField(packet.Info[idx:])
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
