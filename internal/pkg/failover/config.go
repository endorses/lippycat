// Package failover provides transport-independent processor candidate selection.
package failover

import (
	"fmt"
	"time"
)

// Config bounds setup attempts and controls retries of unavailable candidates.
type Config struct {
	AttemptTimeout    time.Duration `mapstructure:"attempt_timeout"`
	ReconnectAttempts int           `mapstructure:"reconnect_attempts"`
	RetryInitial      time.Duration `mapstructure:"retry_initial"`
	RetryMax          time.Duration `mapstructure:"retry_max"`
}

func DefaultConfig() Config {
	return Config{AttemptTimeout: 10 * time.Second, ReconnectAttempts: 1, RetryInitial: time.Second, RetryMax: time.Minute}
}

// NormalizeConfig supplies compatibility defaults. A completely empty config
// receives all defaults; a partially supplied config preserves an explicit zero
// reconnect count and supplies only missing durations.
func NormalizeConfig(config Config) (Config, error) {
	defaults := DefaultConfig()
	if config == (Config{}) {
		return defaults, nil
	}
	if config.AttemptTimeout < 0 || config.RetryInitial < 0 || config.RetryMax < 0 {
		return Config{}, fmt.Errorf("failover durations must be positive")
	}
	if config.ReconnectAttempts < 0 {
		return Config{}, fmt.Errorf("failover reconnect_attempts must be non-negative")
	}
	if config.AttemptTimeout == 0 {
		config.AttemptTimeout = defaults.AttemptTimeout
	}
	if config.RetryInitial == 0 {
		config.RetryInitial = defaults.RetryInitial
	}
	if config.RetryMax == 0 {
		config.RetryMax = defaults.RetryMax
	}
	if config.RetryInitial > config.RetryMax {
		return Config{}, fmt.Errorf("failover retry_initial must not exceed retry_max")
	}
	return config, nil
}
