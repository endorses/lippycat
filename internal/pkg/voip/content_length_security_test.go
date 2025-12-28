package voip

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateContentLength(t *testing.T) {
	// Reset configuration
	viper.Reset()
	ResetSecurityConfigForTesting()

	tests := []struct {
		name          string
		contentLength int
		maxContentLen int
		shouldSucceed bool
		expectedError string
	}{
		{
			name:          "Valid content length - zero",
			contentLength: 0,
			maxContentLen: 1048576,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - normal",
			contentLength: 1024,
			maxContentLen: 1048576,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - at limit",
			contentLength: 1048576,
			maxContentLen: 1048576,
			shouldSucceed: true,
		},
		{
			name:          "Invalid content length - negative",
			contentLength: -1,
			maxContentLen: 1048576,
			shouldSucceed: false,
			expectedError: "negative Content-Length not allowed",
		},
		{
			name:          "Invalid content length - exceeds limit",
			contentLength: 1048577,
			maxContentLen: 1048576,
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed",
		},
		{
			name:          "Very large content length",
			contentLength: 100000000,
			maxContentLen: 1048576,
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set configuration
			viper.Set("voip.security.max_content_length", tt.maxContentLen)
			ResetSecurityConfigForTesting() // Reset to pick up new config

			err := ValidateContentLength(tt.contentLength)

			if tt.shouldSucceed {
				assert.NoError(t, err, "Content-Length validation should succeed")
			} else {
				require.Error(t, err, "Content-Length validation should fail")
				assert.Contains(t, err.Error(), tt.expectedError,
					"Error should contain expected text")
			}
		})
	}
}

func TestValidateMessageSize(t *testing.T) {
	// Reset configuration
	viper.Reset()
	ResetSecurityConfigForTesting()

	tests := []struct {
		name           string
		messageSize    int
		maxMessageSize int
		shouldSucceed  bool
		expectedError  string
	}{
		{
			name:           "Valid message size - zero",
			messageSize:    0,
			maxMessageSize: 2097152,
			shouldSucceed:  true,
		},
		{
			name:           "Valid message size - normal",
			messageSize:    4096,
			maxMessageSize: 2097152,
			shouldSucceed:  true,
		},
		{
			name:           "Valid message size - at limit",
			messageSize:    2097152,
			maxMessageSize: 2097152,
			shouldSucceed:  true,
		},
		{
			name:           "Invalid message size - negative",
			messageSize:    -1,
			maxMessageSize: 2097152,
			shouldSucceed:  false,
			expectedError:  "negative message size not allowed",
		},
		{
			name:           "Invalid message size - exceeds limit",
			messageSize:    2097153,
			maxMessageSize: 2097152,
			shouldSucceed:  false,
			expectedError:  "message size exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set configuration
			viper.Set("voip.security.max_message_size", tt.maxMessageSize)
			ResetSecurityConfigForTesting() // Reset to pick up new config

			err := ValidateMessageSize(tt.messageSize)

			if tt.shouldSucceed {
				assert.NoError(t, err, "Message size validation should succeed")
			} else {
				require.Error(t, err, "Message size validation should fail")
				assert.Contains(t, err.Error(), tt.expectedError,
					"Error should contain expected text")
			}
		})
	}
}

func TestParseContentLengthSecurely(t *testing.T) {
	// Reset configuration
	viper.Reset()
	viper.Set("voip.security.max_content_length", 1048576) // 1MB
	ResetSecurityConfigForTesting()

	tests := []struct {
		name          string
		input         string
		expected      int
		shouldSucceed bool
		expectedError string
	}{
		{
			name:          "Valid content length - zero",
			input:         "0",
			expected:      0,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - normal",
			input:         "1024",
			expected:      1024,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - with whitespace",
			input:         "  2048  ",
			expected:      2048,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - with trailing text",
			input:         "4096 bytes",
			expected:      4096,
			shouldSucceed: true,
		},
		{
			name:          "Valid content length - large but under limit",
			input:         "1048576",
			expected:      1048576,
			shouldSucceed: true,
		},
		{
			name:          "Invalid - empty string",
			input:         "",
			shouldSucceed: false,
			expectedError: "empty Content-Length value",
		},
		{
			name:          "Invalid - whitespace only",
			input:         "   ",
			shouldSucceed: false,
			expectedError: "empty Content-Length value",
		},
		{
			name:          "Invalid - no digits",
			input:         "abc",
			shouldSucceed: false,
			expectedError: "no valid digits found",
		},
		{
			name:          "Invalid - negative value",
			input:         "-1",
			shouldSucceed: false,
			expectedError: "no valid digits found",
		},
		{
			name:          "Invalid - exceeds security limit",
			input:         "2097152",
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed",
		},
		{
			name:          "Invalid - extremely long number string",
			input:         strings.Repeat("1", 15),
			shouldSucceed: false,
			expectedError: "Content-Length value too long",
		},
		{
			name:          "Invalid - integer overflow",
			input:         "99999999999",
			shouldSucceed: false,
			expectedError: "Content-Length value too long",
		},
		{
			name:          "Edge case - starts with zero",
			input:         "01024",
			expected:      1024,
			shouldSucceed: true,
		},
		{
			name:          "Edge case - maximum valid digits",
			input:         "1000000000", // 1GB - will fail security check
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseContentLengthSecurely(tt.input)

			if tt.shouldSucceed {
				require.NoError(t, err, "Parse should succeed")
				assert.Equal(t, tt.expected, result, "Parsed value should match expected")
			} else {
				require.Error(t, err, "Parse should fail")
				assert.Contains(t, err.Error(), tt.expectedError,
					"Error should contain expected text")
			}
		})
	}
}

func TestParseContentLengthSecurityConfiguration(t *testing.T) {
	tests := []struct {
		name          string
		maxContentLen int
		input         string
		shouldSucceed bool
		expectedError string
	}{
		{
			name:          "Strict limit - small value passes",
			maxContentLen: 1024,
			input:         "512",
			shouldSucceed: true,
		},
		{
			name:          "Strict limit - at limit passes",
			maxContentLen: 1024,
			input:         "1024",
			shouldSucceed: true,
		},
		{
			name:          "Strict limit - over limit fails",
			maxContentLen: 1024,
			input:         "1025",
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed: 1025 > 1024",
		},
		{
			name:          "Generous limit - large value passes",
			maxContentLen: 10485760,  // 10MB
			input:         "5242880", // 5MB
			shouldSucceed: true,
		},
		{
			name:          "Very strict limit - zero only",
			maxContentLen: 0,
			input:         "0",
			shouldSucceed: true,
		},
		{
			name:          "Very strict limit - one fails",
			maxContentLen: 0,
			input:         "1",
			shouldSucceed: false,
			expectedError: "Content-Length exceeds maximum allowed: 1 > 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset and configure
			viper.Reset()
			viper.Set("voip.security.max_content_length", tt.maxContentLen)
			ResetSecurityConfigForTesting()

			_, err := ParseContentLengthSecurely(tt.input)

			if tt.shouldSucceed {
				assert.NoError(t, err, "Parse should succeed with configured limit")
			} else {
				require.Error(t, err, "Parse should fail with configured limit")
				assert.Contains(t, err.Error(), tt.expectedError,
					"Error should contain expected text")
			}
		})
	}
}

func TestContentLengthDoSProtection(t *testing.T) {
	// Test protection against various DoS attack vectors

	// Reset configuration with small limits for testing
	viper.Reset()
	viper.Set("voip.security.max_content_length", 4096)
	ResetSecurityConfigForTesting()

	tests := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Extremely large number",
			input:       "999999999999999",
			description: "Should prevent integer overflow attacks",
		},
		{
			name:        "Very long digit string",
			input:       strings.Repeat("1", 20),
			description: "Should prevent memory exhaustion via long parsing",
		},
		{
			name:        "Max int32 value",
			input:       "2147483647",
			description: "Should respect security limits even for valid integers",
		},
		{
			name:        "Realistic attack - 1GB",
			input:       "1073741824",
			description: "Should prevent realistic memory exhaustion attacks",
		},
		{
			name:        "Very large multiplier",
			input:       "9999999999999999999",
			description: "Should prevent extremely large numbers",
		},
		{
			name:        "Malformed large value",
			input:       "1" + strings.Repeat("0", 15),
			description: "Should prevent malformed large inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseContentLengthSecurely(tt.input)
			assert.Error(t, err, tt.description)
		})
	}
}

func TestContentLengthEdgeCases(t *testing.T) {
	// Reset configuration
	viper.Reset()
	viper.Set("voip.security.max_content_length", 1048576)
	ResetSecurityConfigForTesting()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Leading zeros",
			input:    "000123",
			expected: 123,
		},
		{
			name:     "Trailing whitespace and comment",
			input:    "456 ; SDP",
			expected: 456,
		},
		{
			name:     "Tab and space mixing",
			input:    "\t 789 \t",
			expected: 789,
		},
		{
			name:     "Number followed by semicolon",
			input:    "1024;",
			expected: 1024,
		},
		{
			name:     "Short descriptive text",
			input:    "2048 bytes",
			expected: 2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseContentLengthSecurely(tt.input)
			require.NoError(t, err, "Parse should succeed for edge case")
			assert.Equal(t, tt.expected, result, "Should parse correct value")
		})
	}
}

func TestContentLengthSecurityMetrics(t *testing.T) {
	// Test that security violations are properly logged/counted
	viper.Reset()
	viper.Set("voip.security.max_content_length", 1024)
	ResetSecurityConfigForTesting()

	// Test cases that should trigger security violations
	violations := []string{
		"2048",                  // Exceeds limit
		"999999999",             // Way too large
		strings.Repeat("9", 15), // Too long string
	}

	for _, violation := range violations {
		_, err := ParseContentLengthSecurely(violation)
		assert.Error(t, err, "Security violation should be caught: %s", violation)

		// In a real implementation, you might also check that these are logged
		// or counted in metrics for monitoring purposes
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// Ensure that normal, valid Content-Length values still work correctly
	viper.Reset()
	// Use default security settings
	ResetSecurityConfigForTesting()

	normalValues := []struct {
		input    string
		expected int
	}{
		{"0", 0},
		{"123", 123},
		{"1024", 1024},
		{"65536", 65536},
		{"100000", 100000},
	}

	for _, test := range normalValues {
		t.Run("normal_value_"+test.input, func(t *testing.T) {
			result, err := ParseContentLengthSecurely(test.input)
			assert.NoError(t, err, "Normal value should parse successfully")
			assert.Equal(t, test.expected, result, "Should get expected value")
		})
	}
}
