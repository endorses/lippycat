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
	Radius        *RadiusFilterYAML `yaml:"radius,omitempty" json:"radius,omitempty"`
	Revision      uint64            `yaml:"revision,omitempty" json:"revision,omitempty"`
	ID            string            `yaml:"id" json:"id"`
	Type          string            `yaml:"type" json:"type"`
	Pattern       string            `yaml:"pattern" json:"pattern"`
	TargetHunters []string          `yaml:"target_hunters,omitempty" json:"target_hunters,omitempty"`
	Enabled       bool              `yaml:"enabled" json:"enabled"`
	Description   string            `yaml:"description,omitempty" json:"description,omitempty"`
}

// ValidFilterTypes contains all valid filter type strings
var ValidFilterTypes = map[string]bool{
	"radius_username": true, "FILTER_RADIUS_USERNAME": true,
	"radius_mac": true, "FILTER_RADIUS_MAC": true,
	"radius_attribute": true, "FILTER_RADIUS_ATTRIBUTE": true,
	"radius_compound": true, "FILTER_RADIUS_COMPOUND": true,
	// VoIP filters
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
	"sip_uri":             true,
	"FILTER_SIP_URI":      true,
	"imsi":                true,
	"FILTER_IMSI":         true,
	"imei":                true,
	"FILTER_IMEI":         true,
	// DNS filters
	"dns_domain":        true,
	"FILTER_DNS_DOMAIN": true,
	// Email filters
	"email_address":        true,
	"FILTER_EMAIL_ADDRESS": true,
	"email_subject":        true,
	"FILTER_EMAIL_SUBJECT": true,
	// TLS filters
	"tls_sni":         true,
	"FILTER_TLS_SNI":  true,
	"tls_ja3":         true,
	"FILTER_TLS_JA3":  true,
	"tls_ja3s":        true,
	"FILTER_TLS_JA3S": true,
	"tls_ja4":         true,
	"FILTER_TLS_JA4":  true,
	// HTTP filters
	"http_host":        true,
	"FILTER_HTTP_HOST": true,
	"http_url":         true,
	"FILTER_HTTP_URL":  true,
}

// Explicit YAML fields avoid protobuf implementation-specific YAML names.
type RadiusFilterYAML struct {
	MacProfile     string                 `yaml:"mac_profile,omitempty" json:"mac_profile,omitempty"`
	TargetKind     string                 `yaml:"target_kind,omitempty" json:"target_kind,omitempty"`
	GroupID        string                 `yaml:"group_id,omitempty" json:"group_id,omitempty"`
	TaskID         string                 `yaml:"task_id,omitempty" json:"task_id,omitempty"`
	TaskGeneration uint64                 `yaml:"task_generation,omitempty" json:"task_generation,omitempty"`
	Scope          *RadiusScopeYAML       `yaml:"scope,omitempty" json:"scope,omitempty"`
	Criteria       []*RadiusCriterionYAML `yaml:"criteria,omitempty" json:"criteria,omitempty"`
}
type RadiusScopeYAML struct {
	OperatorScope   string `yaml:"operator_scope" json:"operator_scope"`
	ProfileRevision string `yaml:"profile_revision" json:"profile_revision"`
	OriginNodeID    string `yaml:"origin_node_id,omitempty" json:"origin_node_id,omitempty"`
	SourceID        string `yaml:"source_id,omitempty" json:"source_id,omitempty"`
}
type RadiusCriterionYAML struct {
	FilterID       string `yaml:"filter_id" json:"filter_id"`
	FilterRevision uint64 `yaml:"filter_revision" json:"filter_revision"`
	Kind           string `yaml:"kind" json:"kind"`
	Value          string `yaml:"value" json:"value"`
	MacProfile     string `yaml:"mac_profile,omitempty" json:"mac_profile,omitempty"`
	TargetKind     string `yaml:"target_kind,omitempty" json:"target_kind,omitempty"`
}
