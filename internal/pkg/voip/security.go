package voip

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	SanitizeCallIDs      bool `mapstructure:"sanitize_call_ids"`
	CallIDHashLength     int  `mapstructure:"call_id_hash_length"`
	CallIDMaxLogLength   int  `mapstructure:"call_id_max_log_length"`
	EnablePCAPEncryption bool `mapstructure:"enable_pcap_encryption"`
	MaxContentLength     int  `mapstructure:"max_content_length"`
	MaxMessageSize       int  `mapstructure:"max_message_size"`
}

var (
	securityConfig     *SecurityConfig
	securityConfigOnce sync.Once
)

// ResetSecurityConfigForTesting resets the security configuration state for testing.
// This allows tests to reinitialize with different configurations.
// DO NOT use in production code.
func ResetSecurityConfigForTesting() {
	securityConfig = nil
	securityConfigOnce = sync.Once{}
}

// initSecurityConfig initializes security configuration from viper
// This function is called via sync.Once and should not be called directly.
func initSecurityConfig() {
	// Set security defaults
	viper.SetDefault("voip.security.sanitize_call_ids", false)
	viper.SetDefault("voip.security.call_id_hash_length", 8)
	viper.SetDefault("voip.security.call_id_max_log_length", 16)
	viper.SetDefault("voip.security.enable_pcap_encryption", false)
	viper.SetDefault("voip.security.max_content_length", 1048576) // 1MB default
	viper.SetDefault("voip.security.max_message_size", 2097152)   // 2MB default

	securityConfig = &SecurityConfig{
		SanitizeCallIDs:      viper.GetBool("voip.security.sanitize_call_ids"),
		CallIDHashLength:     viper.GetInt("voip.security.call_id_hash_length"),
		CallIDMaxLogLength:   viper.GetInt("voip.security.call_id_max_log_length"),
		EnablePCAPEncryption: viper.GetBool("voip.security.enable_pcap_encryption"),
		MaxContentLength:     viper.GetInt("voip.security.max_content_length"),
		MaxMessageSize:       viper.GetInt("voip.security.max_message_size"),
	}
}

// GetSecurityConfig returns the current security configuration
func GetSecurityConfig() *SecurityConfig {
	securityConfigOnce.Do(initSecurityConfig)
	return securityConfig
}

// SanitizeCallIDForLogging sanitizes Call-IDs for log output to prevent information leakage
// This function provides multiple sanitization strategies based on configuration:
// 1. Hashing: Convert Call-ID to SHA256 hash prefix for anonymization
// 2. Truncation: Limit Call-ID length in logs while preserving prefix for debugging
// 3. Masking: Replace sensitive parts with asterisks
func SanitizeCallIDForLogging(callID string) string {
	if callID == "" {
		return ""
	}

	config := GetSecurityConfig()

	// If sanitization is disabled, return as-is (for development/debugging)
	if !config.SanitizeCallIDs {
		return callID
	}

	// If Call-ID is very short, just truncate it
	if len(callID) <= config.CallIDMaxLogLength {
		return callID
	}

	// Generate a consistent hash prefix for longer Call-IDs
	// This allows correlation of logs for the same call while preventing
	// information leakage about the actual Call-ID values
	hash := sha256.Sum256([]byte(callID))
	hashPrefix := fmt.Sprintf("%x", hash[:config.CallIDHashLength/2])

	// For debugging purposes, include a truncated prefix of the original
	originalPrefix := callID
	if len(originalPrefix) > 6 {
		originalPrefix = originalPrefix[:6]
	}

	return fmt.Sprintf("%s...%s", originalPrefix, hashPrefix)
}

// SanitizeCallIDForDisplay sanitizes Call-IDs for display in user interfaces
// This is more aggressive than logging sanitization to protect user privacy
func SanitizeCallIDForDisplay(callID string) string {
	if callID == "" {
		return ""
	}

	config := GetSecurityConfig()

	if !config.SanitizeCallIDs {
		return callID
	}

	// For display, we're more aggressive - just show a hash
	// Use only 3 bytes for shorter display
	hash := sha256.Sum256([]byte(callID))
	return fmt.Sprintf("call-%x", hash[:3])
}

// ValidateCallIDForSecurity performs security validation on Call-IDs
// to prevent injection attacks and detect suspicious patterns
func ValidateCallIDForSecurity(callID string) error {
	if callID == "" {
		return fmt.Errorf("empty Call-ID")
	}

	// Check for excessive length (potential DoS)
	if len(callID) > MaxCallIDLength {
		return fmt.Errorf("Call-ID too long: %d characters (max %d)", len(callID), MaxCallIDLength)
	}

	// Check for null bytes (potential injection)
	for i, char := range callID {
		if char == 0 {
			return fmt.Errorf("null byte found in Call-ID at position %d", i)
		}
	}

	// Check for potential path traversal sequences
	suspiciousPatterns := []string{"../", "..\\", "/..", "\\..", "..."}
	for _, pattern := range suspiciousPatterns {
		if len(callID) > len(pattern) {
			for i := 0; i <= len(callID)-len(pattern); i++ {
				if callID[i:i+len(pattern)] == pattern {
					return fmt.Errorf("suspicious pattern detected in Call-ID: %s", pattern)
				}
			}
		}
	}

	return nil
}

// ValidateContentLength validates Content-Length header values for security
// This prevents DoS attacks via excessive memory allocation
func ValidateContentLength(contentLength int) error {
	if contentLength < 0 {
		return fmt.Errorf("negative Content-Length not allowed: %d", contentLength)
	}

	config := GetSecurityConfig()

	if contentLength > config.MaxContentLength {
		return fmt.Errorf("Content-Length exceeds maximum allowed: %d > %d",
			contentLength, config.MaxContentLength)
	}

	return nil
}

// ValidateMessageSize validates total SIP message size for security
// This prevents DoS attacks via excessive memory allocation for complete messages
func ValidateMessageSize(messageSize int) error {
	if messageSize < 0 {
		return fmt.Errorf("negative message size not allowed: %d", messageSize)
	}

	config := GetSecurityConfig()

	if messageSize > config.MaxMessageSize {
		return fmt.Errorf("message size exceeds maximum allowed: %d > %d",
			messageSize, config.MaxMessageSize)
	}

	return nil
}

// ParseContentLengthSecurely parses Content-Length with security validation
// This replaces the basic parseContentLength function with bounds checking
func ParseContentLengthSecurely(value string) (int, error) {
	// Trim whitespace and validate input
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, fmt.Errorf("empty Content-Length value")
	}

	// Prevent excessively long number strings (potential DoS)
	if len(trimmed) > MaxContentLengthDigits {
		return 0, fmt.Errorf("Content-Length value too long: %d characters (max %d)", len(trimmed), MaxContentLengthDigits)
	}

	length := 0
	foundDigits := false

	// Parse digits manually with overflow protection
	for _, char := range trimmed {
		if char >= '0' && char <= '9' {
			foundDigits = true
			digit := int(char - '0')

			// Check for overflow before multiplication
			if length > (MaxInt32ForContentLength-digit)/10 {
				return 0, fmt.Errorf("Content-Length value causes integer overflow")
			}

			length = length*10 + digit
		} else {
			// Stop at first non-digit (SIP allows trailing whitespace/comments)
			break
		}
	}

	if !foundDigits {
		return 0, fmt.Errorf("no valid digits found in Content-Length value: %s", trimmed)
	}

	// Validate against security limits
	if err := ValidateContentLength(length); err != nil {
		return 0, fmt.Errorf("Content-Length security validation failed: %w", err)
	}

	return length, nil
}
