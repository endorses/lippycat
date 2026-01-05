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

func TestValidateJA3Pattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid lowercase", "e7d705a3286e19ea42f587b344ee6865", false},
		{"valid uppercase", "E7D705A3286E19EA42F587B344EE6865", false},
		{"valid mixed case", "E7d705A3286e19Ea42f587B344Ee6865", false},
		{"valid with spaces", "  e7d705a3286e19ea42f587b344ee6865  ", false},
		{"too short", "e7d705a3286e19ea42f587b344ee686", true},
		{"too long", "e7d705a3286e19ea42f587b344ee68651", true},
		{"invalid chars", "e7d705a3286e19ea42f587b344ee686g", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJA3Pattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateJA4Pattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid TLS fingerprint", "t13d1516h2_8daaf6152771_b186095e22bb", false},
		{"valid QUIC fingerprint", "q13d1516h2_8daaf6152771_b186095e22bb", false},
		{"valid DTLS fingerprint", "d13d1516h2_8daaf6152771_b186095e22bb", false},
		{"valid with spaces", "  t13d1516h2_8daaf6152771_b186095e22bb  ", false},
		{"missing underscore", "t13d1516h28daaf6152771b186095e22bb", true},
		{"wrong hash length", "t13d1516h2_8daaf615277_b186095e22bb", true},
		{"invalid prefix", "x13d1516h2_8daaf6152771_b186095e22bb", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJA4Pattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateGlobPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"exact match", "example.com", false},
		{"prefix wildcard", "*.example.com", false},
		{"suffix wildcard", "admin.*", false},
		{"contains wildcard", "*malware*", false},
		{"double wildcard", "**foo**", false}, // Allowed
		{"empty", "", true},
		{"whitespace only", "   ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGlobPattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"IPv4", "192.168.1.1", false},
		{"IPv4 CIDR", "192.168.0.0/24", false},
		{"IPv6", "2001:db8::1", false},
		{"IPv4 wildcard", "192.168.*.*", false},
		{"empty", "", true},
		{"no dots or colons", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPPattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePhonePattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"full number", "+14155551234", false},
		{"digits only", "4155551234", false},
		{"prefix wildcard", "+1415*", false},
		{"suffix wildcard", "*1234", false},
		{"pure wildcard", "*", false},
		{"empty", "", true},
		{"no digits no wildcard", "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePhonePattern(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	// Test that ValidatePattern delegates correctly
	tests := []struct {
		name       string
		filterType management.FilterType
		pattern    string
		wantErr    bool
	}{
		{"valid JA3", management.FilterType_FILTER_TLS_JA3, "e7d705a3286e19ea42f587b344ee6865", false},
		{"invalid JA3", management.FilterType_FILTER_TLS_JA3, "invalid", true},
		{"valid SNI glob", management.FilterType_FILTER_TLS_SNI, "*.example.com", false},
		{"valid DNS glob", management.FilterType_FILTER_DNS_DOMAIN, "*.malware.com", false},
		{"empty pattern", management.FilterType_FILTER_SIP_USER, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePattern(tt.filterType, tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
