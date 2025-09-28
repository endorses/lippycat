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

	// TCP-specific configurations
	TCPCleanupInterval    time.Duration `mapstructure:"tcp_cleanup_interval"`
	TCPBufferMaxAge       time.Duration `mapstructure:"tcp_buffer_max_age"`
	TCPStreamMaxQueueTime time.Duration `mapstructure:"tcp_stream_max_queue_time"`
	MaxTCPBuffers         int           `mapstructure:"max_tcp_buffers"`
	TCPStreamTimeout      time.Duration `mapstructure:"tcp_stream_timeout"`
	TCPAssemblerMaxPages  int           `mapstructure:"tcp_assembler_max_pages"`

	// TCP Performance configurations
	TCPPerformanceMode string `mapstructure:"tcp_performance_mode"`
	TCPBufferStrategy  string `mapstructure:"tcp_buffer_strategy"`
	EnableBackpressure bool   `mapstructure:"enable_backpressure"`
	MemoryOptimization bool   `mapstructure:"memory_optimization"`

	// Performance tuning parameters
	TCPBufferPoolSize      int   `mapstructure:"tcp_buffer_pool_size"`
	TCPBatchSize           int   `mapstructure:"tcp_batch_size"`
	TCPIOThreads           int   `mapstructure:"tcp_io_threads"`
	TCPCompressionLevel    int   `mapstructure:"tcp_compression_level"`
	TCPMemoryLimit         int64 `mapstructure:"tcp_memory_limit"`
	TCPLatencyOptimization bool  `mapstructure:"tcp_latency_optimization"`
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

	// TCP-specific defaults
	viper.SetDefault("voip.tcp_cleanup_interval", DefaultTCPCleanupInterval)
	viper.SetDefault("voip.tcp_buffer_max_age", DefaultTCPBufferMaxAge)
	viper.SetDefault("voip.tcp_stream_max_queue_time", DefaultTCPStreamMaxQueueTime)
	viper.SetDefault("voip.max_tcp_buffers", DefaultMaxTCPBuffers)
	viper.SetDefault("voip.tcp_stream_timeout", DefaultTCPStreamTimeout)
	viper.SetDefault("voip.tcp_assembler_max_pages", DefaultTCPAssemblerMaxPages)

	// TCP Performance defaults
	viper.SetDefault("voip.tcp_performance_mode", DefaultTCPPerformanceMode)
	viper.SetDefault("voip.tcp_buffer_strategy", DefaultTCPBufferStrategy)
	viper.SetDefault("voip.enable_backpressure", DefaultEnableBackpressure)
	viper.SetDefault("voip.memory_optimization", DefaultMemoryOptimization)
	viper.SetDefault("voip.tcp_buffer_pool_size", DefaultTCPBufferPoolSize)
	viper.SetDefault("voip.tcp_batch_size", DefaultTCPBatchSize)
	viper.SetDefault("voip.tcp_io_threads", DefaultTCPIOThreads)
	viper.SetDefault("voip.tcp_compression_level", DefaultTCPCompressionLevel)
	viper.SetDefault("voip.tcp_memory_limit", DefaultTCPMemoryLimit)
	viper.SetDefault("voip.tcp_latency_optimization", DefaultTCPLatencyOptimization)
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

		// TCP-specific configurations
		TCPCleanupInterval:    viper.GetDuration("voip.tcp_cleanup_interval"),
		TCPBufferMaxAge:       viper.GetDuration("voip.tcp_buffer_max_age"),
		TCPStreamMaxQueueTime: viper.GetDuration("voip.tcp_stream_max_queue_time"),
		MaxTCPBuffers:         viper.GetInt("voip.max_tcp_buffers"),
		TCPStreamTimeout:      viper.GetDuration("voip.tcp_stream_timeout"),
		TCPAssemblerMaxPages:  viper.GetInt("voip.tcp_assembler_max_pages"),

		// TCP Performance configurations
		TCPPerformanceMode:     viper.GetString("voip.tcp_performance_mode"),
		TCPBufferStrategy:      viper.GetString("voip.tcp_buffer_strategy"),
		EnableBackpressure:     viper.GetBool("voip.enable_backpressure"),
		MemoryOptimization:     viper.GetBool("voip.memory_optimization"),
		TCPBufferPoolSize:      viper.GetInt("voip.tcp_buffer_pool_size"),
		TCPBatchSize:           viper.GetInt("voip.tcp_batch_size"),
		TCPIOThreads:           viper.GetInt("voip.tcp_io_threads"),
		TCPCompressionLevel:    viper.GetInt("voip.tcp_compression_level"),
		TCPMemoryLimit:         viper.GetInt64("voip.tcp_memory_limit"),
		TCPLatencyOptimization: viper.GetBool("voip.tcp_latency_optimization"),
	}

	return config
}
