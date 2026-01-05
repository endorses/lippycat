package filtering

import (
	"encoding/json"
	"fmt"

	"github.com/endorses/lippycat/api/gen/management"
)

// YAMLToProto converts a FilterYAML to a protobuf Filter
func YAMLToProto(yaml *FilterYAML) (*management.Filter, error) {
	if yaml.ID == "" {
		return nil, &ValidationError{Field: "id", Message: "filter ID is required"}
	}
	if yaml.Pattern == "" {
		return nil, &ValidationError{Field: "pattern", Message: "filter pattern is required"}
	}

	filterType, err := ParseFilterType(yaml.Type)
	if err != nil {
		return nil, err
	}

	return &management.Filter{
		Id:            yaml.ID,
		Type:          filterType,
		Pattern:       yaml.Pattern,
		TargetHunters: yaml.TargetHunters,
		Enabled:       yaml.Enabled,
		Description:   yaml.Description,
	}, nil
}

// ProtoToYAML converts a protobuf Filter to FilterYAML
func ProtoToYAML(proto *management.Filter) *FilterYAML {
	return &FilterYAML{
		ID:            proto.Id,
		Type:          FilterTypeToString(proto.Type),
		Pattern:       proto.Pattern,
		TargetHunters: proto.TargetHunters,
		Enabled:       proto.Enabled,
		Description:   proto.Description,
	}
}

// ProtoToJSON converts a protobuf Filter to JSON bytes
func ProtoToJSON(proto *management.Filter) ([]byte, error) {
	yaml := ProtoToYAML(proto)
	return json.Marshal(yaml)
}

// ProtoSliceToJSON converts a slice of protobuf Filters to JSON bytes
func ProtoSliceToJSON(filters []*management.Filter) ([]byte, error) {
	yamlFilters := make([]*FilterYAML, len(filters))
	for i, f := range filters {
		yamlFilters[i] = ProtoToYAML(f)
	}
	return json.Marshal(yamlFilters)
}

// ParseFilterType converts a string to FilterType enum
func ParseFilterType(typeStr string) (management.FilterType, error) {
	switch typeStr {
	// VoIP filters
	case "FILTER_SIP_USER", "sip_user":
		return management.FilterType_FILTER_SIP_USER, nil
	case "FILTER_PHONE_NUMBER", "phone_number":
		return management.FilterType_FILTER_PHONE_NUMBER, nil
	case "FILTER_IP_ADDRESS", "ip_address":
		return management.FilterType_FILTER_IP_ADDRESS, nil
	case "FILTER_CALL_ID", "call_id":
		return management.FilterType_FILTER_CALL_ID, nil
	case "FILTER_CODEC", "codec":
		return management.FilterType_FILTER_CODEC, nil
	case "FILTER_BPF", "bpf":
		return management.FilterType_FILTER_BPF, nil
	case "FILTER_SIP_URI", "sip_uri":
		return management.FilterType_FILTER_SIP_URI, nil
	// DNS filters
	case "FILTER_DNS_DOMAIN", "dns_domain":
		return management.FilterType_FILTER_DNS_DOMAIN, nil
	// Email filters
	case "FILTER_EMAIL_ADDRESS", "email_address":
		return management.FilterType_FILTER_EMAIL_ADDRESS, nil
	case "FILTER_EMAIL_SUBJECT", "email_subject":
		return management.FilterType_FILTER_EMAIL_SUBJECT, nil
	// TLS filters
	case "FILTER_TLS_SNI", "tls_sni":
		return management.FilterType_FILTER_TLS_SNI, nil
	case "FILTER_TLS_JA3", "tls_ja3":
		return management.FilterType_FILTER_TLS_JA3, nil
	case "FILTER_TLS_JA3S", "tls_ja3s":
		return management.FilterType_FILTER_TLS_JA3S, nil
	case "FILTER_TLS_JA4", "tls_ja4":
		return management.FilterType_FILTER_TLS_JA4, nil
	// HTTP filters
	case "FILTER_HTTP_HOST", "http_host":
		return management.FilterType_FILTER_HTTP_HOST, nil
	case "FILTER_HTTP_URL", "http_url":
		return management.FilterType_FILTER_HTTP_URL, nil
	default:
		return 0, fmt.Errorf("unknown filter type: %s", typeStr)
	}
}

// FilterTypeToString converts FilterType enum to string
func FilterTypeToString(filterType management.FilterType) string {
	switch filterType {
	// VoIP filters
	case management.FilterType_FILTER_SIP_USER:
		return "sip_user"
	case management.FilterType_FILTER_PHONE_NUMBER:
		return "phone_number"
	case management.FilterType_FILTER_IP_ADDRESS:
		return "ip_address"
	case management.FilterType_FILTER_CALL_ID:
		return "call_id"
	case management.FilterType_FILTER_CODEC:
		return "codec"
	case management.FilterType_FILTER_BPF:
		return "bpf"
	case management.FilterType_FILTER_SIP_URI:
		return "sip_uri"
	// DNS filters
	case management.FilterType_FILTER_DNS_DOMAIN:
		return "dns_domain"
	// Email filters
	case management.FilterType_FILTER_EMAIL_ADDRESS:
		return "email_address"
	case management.FilterType_FILTER_EMAIL_SUBJECT:
		return "email_subject"
	// TLS filters
	case management.FilterType_FILTER_TLS_SNI:
		return "tls_sni"
	case management.FilterType_FILTER_TLS_JA3:
		return "tls_ja3"
	case management.FilterType_FILTER_TLS_JA3S:
		return "tls_ja3s"
	case management.FilterType_FILTER_TLS_JA4:
		return "tls_ja4"
	// HTTP filters
	case management.FilterType_FILTER_HTTP_HOST:
		return "http_host"
	case management.FilterType_FILTER_HTTP_URL:
		return "http_url"
	default:
		return "unknown"
	}
}
