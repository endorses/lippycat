package voip

import (
	"sync"
	"time"

	"github.com/spf13/viper"
)

var configOnce sync.Once

// Config holds all configurable VoIP processing parameters
type Config struct {
	// Goroutine limits
	MaxGoroutines int `mapstructure:"max_goroutines"`

	// Timeout configurations
	CallIDDetectionTimeout time.Duration `mapstructure:"call_id_detection_timeout"`
	JanitorCleanupInterval time.Duration `mapstructure:"janitor_cleanup_interval"`
	CallExpirationTime     time.Duration `mapstructure:"call_expiration_time"`

	// Buffer configurations
	StreamQueueBuffer int `mapstructure:"stream_queue_buffer"`

	// File handling
	MaxFilenameLength int `mapstructure:"max_filename_length"`

	// Logging
	LogGoroutineLimitInterval time.Duration `mapstructure:"log_goroutine_limit_interval"`
}

// initConfigDefaults initializes viper defaults once
func initConfigDefaults() {
	viper.SetDefault("voip.max_goroutines", DefaultGoroutineLimit)
	viper.SetDefault("voip.call_id_detection_timeout", DefaultCallIDDetectionTimeout)
	viper.SetDefault("voip.janitor_cleanup_interval", DefaultJanitorCleanupInterval)
	viper.SetDefault("voip.call_expiration_time", DefaultCallExpirationTime)
	viper.SetDefault("voip.stream_queue_buffer", DefaultStreamQueueBuffer)
	viper.SetDefault("voip.max_filename_length", 100)
	viper.SetDefault("voip.log_goroutine_limit_interval", 30*time.Second)
}

// GetConfig returns the current VoIP configuration with defaults
func GetConfig() *Config {
	// Initialize defaults only once to prevent race conditions
	configOnce.Do(initConfigDefaults)

	config := &Config{
		MaxGoroutines:             viper.GetInt("voip.max_goroutines"),
		CallIDDetectionTimeout:    viper.GetDuration("voip.call_id_detection_timeout"),
		JanitorCleanupInterval:    viper.GetDuration("voip.janitor_cleanup_interval"),
		CallExpirationTime:        viper.GetDuration("voip.call_expiration_time"),
		StreamQueueBuffer:         viper.GetInt("voip.stream_queue_buffer"),
		MaxFilenameLength:         viper.GetInt("voip.max_filename_length"),
		LogGoroutineLimitInterval: viper.GetDuration("voip.log_goroutine_limit_interval"),
	}

	return config
}