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
	default:
		return 0, fmt.Errorf("unknown filter type: %s", typeStr)
	}
}

// FilterTypeToString converts FilterType enum to string
func FilterTypeToString(filterType management.FilterType) string {
	switch filterType {
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
	default:
		return "unknown"
	}
}
