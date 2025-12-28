package voip

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeCallIDForLogging(t *testing.T) {
	// Reset viper for clean test environment
	viper.Reset()
	ResetSecurityConfigForTesting()

	tests := []struct {
		name              string
		callID            string
		sanitizeEnabled   bool
		expectedPrefix    string
		shouldContainHash bool
		shouldBeTruncated bool
		expectedResult    string
	}{
		{
			name:            "Empty Call-ID",
			callID:          "",
			sanitizeEnabled: true,
			expectedResult:  "",
		},
		{
			name:            "Short Call-ID - sanitization disabled",
			callID:          "short-id",
			sanitizeEnabled: false,
			expectedResult:  "short-id",
		},
		{
			name:            "Short Call-ID - sanitization enabled",
			callID:          "short-id",
			sanitizeEnabled: true,
			expectedResult:  "short-id",
		},
		{
			name:              "Long Call-ID - sanitization enabled",
			callID:            "very-long-call-id-that-should-be-sanitized-for-security",
			sanitizeEnabled:   true,
			expectedPrefix:    "very-l",
			shouldContainHash: true,
		},
		{
			name:            "Long Call-ID - sanitization disabled",
			callID:          "very-long-call-id-that-should-be-sanitized-for-security",
			sanitizeEnabled: false,
			expectedResult:  "very-long-call-id-that-should-be-sanitized-for-security",
		},
		{
			name:              "Call-ID with special characters",
			callID:            "call-id-with-@#$%^&*()_+-={}[]|\\:;\"'<>?,./",
			sanitizeEnabled:   true,
			expectedPrefix:    "call-i",
			shouldContainHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up configuration for this test
			viper.Set("voip.security.sanitize_call_ids", tt.sanitizeEnabled)
			viper.Set("voip.security.call_id_hash_length", 8)
			viper.Set("voip.security.call_id_max_log_length", 16)

			// Reset security config to pick up new settings
			ResetSecurityConfigForTesting()

			result := SanitizeCallIDForLogging(tt.callID)

			if tt.expectedResult != "" {
				assert.Equal(t, tt.expectedResult, result, "Expected exact result match")
			} else {
				if tt.shouldContainHash {
					assert.Contains(t, result, "...", "Sanitized result should contain ellipsis")
					assert.True(t, strings.HasPrefix(result, tt.expectedPrefix),
						"Result should start with expected prefix: %s", tt.expectedPrefix)
					assert.True(t, len(result) > len(tt.expectedPrefix),
						"Result should be longer than just the prefix")
				}
			}

			// Ensure result is never longer than original for sanitized calls
			if tt.sanitizeEnabled && len(tt.callID) > 16 {
				assert.True(t, len(result) < len(tt.callID),
					"Sanitized result should be shorter than original")
			}
		})
	}
}

func TestSanitizeCallIDForDisplay(t *testing.T) {
	viper.Reset()
	ResetSecurityConfigForTesting()

	tests := []struct {
		name            string
		callID          string
		sanitizeEnabled bool
		expectedPrefix  string
	}{
		{
			name:            "Empty Call-ID",
			callID:          "",
			sanitizeEnabled: true,
			expectedPrefix:  "",
		},
		{
			name:            "Normal Call-ID - sanitization disabled",
			callID:          "normal-call-id-123",
			sanitizeEnabled: false,
			expectedPrefix:  "normal-call-id-123",
		},
		{
			name:            "Normal Call-ID - sanitization enabled",
			callID:          "normal-call-id-123",
			sanitizeEnabled: true,
			expectedPrefix:  "call-",
		},
		{
			name:            "Sensitive Call-ID with personal info",
			callID:          "user-john.doe@company.com-session-12345",
			sanitizeEnabled: true,
			expectedPrefix:  "call-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Set("voip.security.sanitize_call_ids", tt.sanitizeEnabled)
			ResetSecurityConfigForTesting()

			result := SanitizeCallIDForDisplay(tt.callID)

			if tt.expectedPrefix == "" {
				assert.Empty(t, result)
			} else if !tt.sanitizeEnabled {
				assert.Equal(t, tt.callID, result)
			} else {
				assert.True(t, strings.HasPrefix(result, tt.expectedPrefix),
					"Result should start with %s, got: %s", tt.expectedPrefix, result)
				// Display sanitization should always be short for privacy
				assert.True(t, len(result) <= 12, "Display result should be short for privacy")
			}
		})
	}
}

func TestValidateCallIDForSecurity(t *testing.T) {
	tests := []struct {
		name          string
		callID        string
		shouldSucceed bool
		expectedError string
	}{
		{
			name:          "Empty Call-ID",
			callID:        "",
			shouldSucceed: false,
			expectedError: "empty Call-ID",
		},
		{
			name:          "Normal Call-ID",
			callID:        "normal-call-id-123",
			shouldSucceed: true,
		},
		{
			name:          "Call-ID with special characters (allowed)",
			callID:        "call-id-with-@#$%^&*()_+-={}[]|\\:;\"'<>?,./",
			shouldSucceed: true,
		},
		{
			name:          "Excessively long Call-ID",
			callID:        strings.Repeat("very-long-call-id-", 100), // Over 1024 chars
			shouldSucceed: false,
			expectedError: "Call-ID too long",
		},
		{
			name:          "Call-ID with null byte",
			callID:        "call-id-with\x00null-byte",
			shouldSucceed: false,
			expectedError: "null byte found",
		},
		{
			name:          "Call-ID with path traversal - ../",
			callID:        "call-id-with-../path-traversal",
			shouldSucceed: false,
			expectedError: "suspicious pattern detected",
		},
		{
			name:          "Call-ID with path traversal - ..\\",
			callID:        "call-id-with-..\\windows-traversal",
			shouldSucceed: false,
			expectedError: "suspicious pattern detected",
		},
		{
			name:          "Call-ID with multiple dots (safe)",
			callID:        "call.id.with.dots",
			shouldSucceed: true,
		},
		{
			name:          "Call-ID with suspicious pattern /..",
			callID:        "call-id/..dangerous",
			shouldSucceed: false,
			expectedError: "suspicious pattern detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCallIDForSecurity(tt.callID)

			if tt.shouldSucceed {
				assert.NoError(t, err, "Validation should succeed for valid Call-ID")
			} else {
				require.Error(t, err, "Validation should fail for invalid Call-ID")
				assert.Contains(t, err.Error(), tt.expectedError,
					"Error message should contain expected text")
			}
		})
	}
}

func TestGetSecurityConfig(t *testing.T) {
	// Clean slate
	viper.Reset()
	ResetSecurityConfigForTesting()

	// Test default configuration
	config := GetSecurityConfig()
	assert.NotNil(t, config)
	assert.False(t, config.SanitizeCallIDs, "Default should be false for backward compatibility")
	assert.Equal(t, 8, config.CallIDHashLength)
	assert.Equal(t, 16, config.CallIDMaxLogLength)
	assert.False(t, config.EnablePCAPEncryption)

	// Test custom configuration
	viper.Set("voip.security.sanitize_call_ids", true)
	viper.Set("voip.security.call_id_hash_length", 12)
	viper.Set("voip.security.call_id_max_log_length", 20)
	viper.Set("voip.security.enable_pcap_encryption", true)

	// Reset to pick up new config
	ResetSecurityConfigForTesting()
	config = GetSecurityConfig()

	assert.True(t, config.SanitizeCallIDs)
	assert.Equal(t, 12, config.CallIDHashLength)
	assert.Equal(t, 20, config.CallIDMaxLogLength)
	assert.True(t, config.EnablePCAPEncryption)
}

func TestSanitizeCallIDConsistency(t *testing.T) {
	// Ensure sanitization is consistent for the same Call-ID
	viper.Reset()
	viper.Set("voip.security.sanitize_call_ids", true)
	ResetSecurityConfigForTesting()

	callID := "consistent-test-call-id-for-hashing"

	// Call sanitization multiple times
	result1 := SanitizeCallIDForLogging(callID)
	result2 := SanitizeCallIDForLogging(callID)
	result3 := SanitizeCallIDForLogging(callID)

	// Results should be identical
	assert.Equal(t, result1, result2, "Sanitization should be consistent")
	assert.Equal(t, result2, result3, "Sanitization should be consistent")

	// Display sanitization should also be consistent
	display1 := SanitizeCallIDForDisplay(callID)
	display2 := SanitizeCallIDForDisplay(callID)
	assert.Equal(t, display1, display2, "Display sanitization should be consistent")
}

func TestSanitizeCallIDUniqueness(t *testing.T) {
	// Ensure different Call-IDs produce different sanitized outputs
	viper.Reset()
	viper.Set("voip.security.sanitize_call_ids", true)
	ResetSecurityConfigForTesting()

	callID1 := "unique-test-call-id-1"
	callID2 := "unique-test-call-id-2"
	callID3 := "completely-different-call-id"

	result1 := SanitizeCallIDForLogging(callID1)
	result2 := SanitizeCallIDForLogging(callID2)
	result3 := SanitizeCallIDForLogging(callID3)

	// All results should be different
	assert.NotEqual(t, result1, result2, "Different Call-IDs should produce different results")
	assert.NotEqual(t, result2, result3, "Different Call-IDs should produce different results")
	assert.NotEqual(t, result1, result3, "Different Call-IDs should produce different results")

	// Display results should also be different
	display1 := SanitizeCallIDForDisplay(callID1)
	display2 := SanitizeCallIDForDisplay(callID2)
	display3 := SanitizeCallIDForDisplay(callID3)

	assert.NotEqual(t, display1, display2, "Different Call-IDs should produce different display results")
	assert.NotEqual(t, display2, display3, "Different Call-IDs should produce different display results")
	assert.NotEqual(t, display1, display3, "Different Call-IDs should produce different display results")
}
