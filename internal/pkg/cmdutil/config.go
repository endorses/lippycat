// Package cmdutil provides shared utilities for CLI command implementations.
package cmdutil

import (
	"fmt"

	"github.com/spf13/viper"
)

// GetStringConfig returns the config value for key, or flagValue if the key is not set.
// Flag values take precedence over config file values.
func GetStringConfig(key, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return viper.GetString(key)
}

// GetStringSliceConfig returns the config value for key, or flagValue if the key is not set.
// Flag values take precedence over config file values.
// The special value "any" in flagValue[0] is treated as unset.
func GetStringSliceConfig(key string, flagValue []string) []string {
	if len(flagValue) > 0 && flagValue[0] != "any" {
		return flagValue
	}
	// Check actual config value instead of viper.IsSet() which returns true
	// for bound flags even when config file doesn't define them
	if configValue := viper.GetStringSlice(key); len(configValue) > 0 {
		return configValue
	}
	return flagValue
}

// GetIntConfig returns the config value for key, or flagValue if the key is not set.
func GetIntConfig(key string, flagValue int) int {
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return flagValue
}

// GetBoolConfig returns the config value for key, or flagValue if the key is not set.
func GetBoolConfig(key string, flagValue bool) bool {
	if viper.IsSet(key) {
		return viper.GetBool(key)
	}
	return flagValue
}

// GetFloat64Config returns the config value for key, or flagValue if the key is not set.
func GetFloat64Config(key string, flagValue float64) float64 {
	if viper.IsSet(key) {
		return viper.GetFloat64(key)
	}
	return flagValue
}

// ParseSizeString parses a size string (e.g., "100M", "1G", "500K") and returns bytes.
// Supported suffixes: K/k (KiB), M/m (MiB), G/g (GiB), T/t (TiB).
func ParseSizeString(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	lastChar := s[len(s)-1]
	var multiplier int64 = 1

	switch lastChar {
	case 'K', 'k':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}

	var value int64
	_, err := fmt.Sscanf(s, "%d", &value)
	if err != nil {
		return 0, fmt.Errorf("invalid size value: %w", err)
	}

	return value * multiplier, nil
}
