package filtering

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

func TestValidateFilterYAML(t *testing.T) {
	tests := []struct {
		name     string
		filter   *FilterYAML
		wantErr  bool
		errField string
	}{
		{
			name: "valid filter",
			filter: &FilterYAML{
				ID:      "test-filter",
				Type:    "sip_user",
				Pattern: "user@example.com",
				Enabled: true,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			filter: &FilterYAML{
				Type:    "sip_user",
				Pattern: "user@example.com",
			},
			wantErr:  true,
			errField: "id",
		},
		{
			name: "missing pattern",
			filter: &FilterYAML{
				ID:   "test-filter",
				Type: "sip_user",
			},
			wantErr:  true,
			errField: "pattern",
		},
		{
			name: "missing type",
			filter: &FilterYAML{
				ID:      "test-filter",
				Pattern: "user@example.com",
			},
			wantErr:  true,
			errField: "type",
		},
		{
			name: "invalid type",
			filter: &FilterYAML{
				ID:      "test-filter",
				Type:    "invalid_type",
				Pattern: "user@example.com",
			},
			wantErr:  true,
			errField: "type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilterYAML(tt.filter)
			if tt.wantErr {
				assert.Error(t, err)
				if verr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errField, verr.Field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   *management.Filter
		wantErr  bool
		errField string
	}{
		{
			name: "valid filter",
			filter: &management.Filter{
				Id:      "test-filter",
				Type:    management.FilterType_FILTER_SIP_USER,
				Pattern: "user@example.com",
				Enabled: true,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			filter: &management.Filter{
				Type:    management.FilterType_FILTER_SIP_USER,
				Pattern: "user@example.com",
			},
			wantErr:  true,
			errField: "id",
		},
		{
			name: "missing pattern",
			filter: &management.Filter{
				Id:   "test-filter",
				Type: management.FilterType_FILTER_SIP_USER,
			},
			wantErr:  true,
			errField: "pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilter(tt.filter)
			if tt.wantErr {
				assert.Error(t, err)
				if verr, ok := err.(*ValidationError); ok {
					assert.Equal(t, tt.errField, verr.Field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateFilterType(t *testing.T) {
	validTypes := []string{
		"sip_user", "FILTER_SIP_USER",
		"phone_number", "FILTER_PHONE_NUMBER",
		"ip_address", "FILTER_IP_ADDRESS",
		"call_id", "FILTER_CALL_ID",
		"codec", "FILTER_CODEC",
		"bpf", "FILTER_BPF",
	}

	for _, typeStr := range validTypes {
		t.Run("valid_"+typeStr, func(t *testing.T) {
			err := ValidateFilterType(typeStr)
			assert.NoError(t, err)
		})
	}

	invalidTypes := []string{"invalid", "SIP_USER", "filter_sip", ""}
	for _, typeStr := range invalidTypes {
		t.Run("invalid_"+typeStr, func(t *testing.T) {
			err := ValidateFilterType(typeStr)
			assert.Error(t, err)
		})
	}
}

func TestValidationError(t *testing.T) {
	err := &ValidationError{Field: "id", Message: "filter ID is required"}
	assert.Equal(t, "id: filter ID is required", err.Error())
}
