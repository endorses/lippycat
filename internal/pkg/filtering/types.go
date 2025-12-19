// Package filtering provides shared filter types and utilities for lippycat.
// This package is used by both the processor (for persistence) and CLI commands
// (for remote filter management via gRPC).
package filtering

// FilterConfig represents the YAML structure for filter persistence
type FilterConfig struct {
	Filters []*FilterYAML `yaml:"filters" json:"filters"`
}

// FilterYAML represents a filter in YAML/JSON format
type FilterYAML struct {
	ID            string   `yaml:"id" json:"id"`
	Type          string   `yaml:"type" json:"type"`
	Pattern       string   `yaml:"pattern" json:"pattern"`
	TargetHunters []string `yaml:"target_hunters,omitempty" json:"target_hunters,omitempty"`
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	Description   string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// ValidFilterTypes contains all valid filter type strings
var ValidFilterTypes = map[string]bool{
	"sip_user":            true,
	"FILTER_SIP_USER":     true,
	"phone_number":        true,
	"FILTER_PHONE_NUMBER": true,
	"ip_address":          true,
	"FILTER_IP_ADDRESS":   true,
	"call_id":             true,
	"FILTER_CALL_ID":      true,
	"codec":               true,
	"FILTER_CODEC":        true,
	"bpf":                 true,
	"FILTER_BPF":          true,
}
