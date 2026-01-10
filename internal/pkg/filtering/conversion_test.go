package filtering

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestYAMLToProto(t *testing.T) {
	t.Run("valid filter", func(t *testing.T) {
		yaml := &FilterYAML{
			ID:            "test-filter",
			Type:          "sip_user",
			Pattern:       "user@domain.com",
			TargetHunters: []string{"hunter-1"},
			Enabled:       true,
			Description:   "Test filter",
		}

		proto, err := YAMLToProto(yaml)
		require.NoError(t, err)
		assert.Equal(t, "test-filter", proto.Id)
		assert.Equal(t, management.FilterType_FILTER_SIP_USER, proto.Type)
		assert.Equal(t, "user@domain.com", proto.Pattern)
		assert.Equal(t, []string{"hunter-1"}, proto.TargetHunters)
		assert.True(t, proto.Enabled)
		assert.Equal(t, "Test filter", proto.Description)
	})

	t.Run("missing ID", func(t *testing.T) {
		yaml := &FilterYAML{
			Type:    "sip_user",
			Pattern: "user@domain.com",
		}

		_, err := YAMLToProto(yaml)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID is required")
	})

	t.Run("missing pattern", func(t *testing.T) {
		yaml := &FilterYAML{
			ID:   "test-filter",
			Type: "sip_user",
		}

		_, err := YAMLToProto(yaml)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pattern is required")
	})

	t.Run("invalid type", func(t *testing.T) {
		yaml := &FilterYAML{
			ID:      "test-filter",
			Type:    "invalid_type",
			Pattern: "user@domain.com",
		}

		_, err := YAMLToProto(yaml)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown filter type")
	})

	t.Run("all filter types", func(t *testing.T) {
		cases := []struct {
			typeStr   string
			protoType management.FilterType
		}{
			{"sip_user", management.FilterType_FILTER_SIP_USER},
			{"FILTER_SIP_USER", management.FilterType_FILTER_SIP_USER},
			{"phone_number", management.FilterType_FILTER_PHONE_NUMBER},
			{"ip_address", management.FilterType_FILTER_IP_ADDRESS},
			{"call_id", management.FilterType_FILTER_CALL_ID},
			{"codec", management.FilterType_FILTER_CODEC},
			{"bpf", management.FilterType_FILTER_BPF},
		}

		for _, tc := range cases {
			yaml := &FilterYAML{
				ID:      "test",
				Type:    tc.typeStr,
				Pattern: "pattern",
			}
			proto, err := YAMLToProto(yaml)
			require.NoError(t, err)
			assert.Equal(t, tc.protoType, proto.Type)
		}
	})
}

func TestProtoToYAML(t *testing.T) {
	proto := &management.Filter{
		Id:            "test-filter",
		Type:          management.FilterType_FILTER_IP_ADDRESS,
		Pattern:       "10.0.0.0/8",
		TargetHunters: []string{"hunter-1", "hunter-2"},
		Enabled:       false,
		Description:   "Private network",
	}

	yaml := ProtoToYAML(proto)
	assert.Equal(t, "test-filter", yaml.ID)
	assert.Equal(t, "ip_address", yaml.Type)
	assert.Equal(t, "10.0.0.0/8", yaml.Pattern)
	assert.Equal(t, []string{"hunter-1", "hunter-2"}, yaml.TargetHunters)
	assert.False(t, yaml.Enabled)
	assert.Equal(t, "Private network", yaml.Description)
}

func TestProtoToJSON(t *testing.T) {
	proto := &management.Filter{
		Id:      "test-filter",
		Type:    management.FilterType_FILTER_SIP_USER,
		Pattern: "user@example.com",
		Enabled: true,
	}

	jsonBytes, err := ProtoToJSON(proto, false)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(jsonBytes, &result)
	require.NoError(t, err)

	assert.Equal(t, "test-filter", result["id"])
	assert.Equal(t, "sip_user", result["type"])
	assert.Equal(t, "user@example.com", result["pattern"])
	assert.Equal(t, true, result["enabled"])
}

func TestProtoSliceToJSON(t *testing.T) {
	filters := []*management.Filter{
		{
			Id:      "filter-1",
			Type:    management.FilterType_FILTER_SIP_USER,
			Pattern: "user1@example.com",
			Enabled: true,
		},
		{
			Id:      "filter-2",
			Type:    management.FilterType_FILTER_IP_ADDRESS,
			Pattern: "192.168.1.0/24",
			Enabled: false,
		},
	}

	jsonBytes, err := ProtoSliceToJSON(filters, false)
	require.NoError(t, err)

	var result []map[string]interface{}
	err = json.Unmarshal(jsonBytes, &result)
	require.NoError(t, err)

	assert.Len(t, result, 2)
	assert.Equal(t, "filter-1", result[0]["id"])
	assert.Equal(t, "filter-2", result[1]["id"])
}

func TestParseFilterType(t *testing.T) {
	tests := []struct {
		name      string
		typeStr   string
		expected  management.FilterType
		expectErr bool
	}{
		{"SIPUser lowercase", "sip_user", management.FilterType_FILTER_SIP_USER, false},
		{"SIPUser uppercase", "FILTER_SIP_USER", management.FilterType_FILTER_SIP_USER, false},
		{"PhoneNumber", "phone_number", management.FilterType_FILTER_PHONE_NUMBER, false},
		{"IPAddress", "ip_address", management.FilterType_FILTER_IP_ADDRESS, false},
		{"CallID", "call_id", management.FilterType_FILTER_CALL_ID, false},
		{"Codec", "codec", management.FilterType_FILTER_CODEC, false},
		{"BPF", "bpf", management.FilterType_FILTER_BPF, false},
		{"Invalid", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFilterType(tt.typeStr)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestFilterTypeToString(t *testing.T) {
	tests := []struct {
		filterType management.FilterType
		expected   string
	}{
		{management.FilterType_FILTER_SIP_USER, "sip_user"},
		{management.FilterType_FILTER_PHONE_NUMBER, "phone_number"},
		{management.FilterType_FILTER_IP_ADDRESS, "ip_address"},
		{management.FilterType_FILTER_CALL_ID, "call_id"},
		{management.FilterType_FILTER_CODEC, "codec"},
		{management.FilterType_FILTER_BPF, "bpf"},
		{management.FilterType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := FilterTypeToString(tt.filterType)
			assert.Equal(t, tt.expected, result)
		})
	}
}
