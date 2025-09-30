package voip

import (
	"time"
)

// Buffer strategy options
const (
	BufferStrategyAdaptive = "adaptive"
	BufferStrategyFixed    = "fixed"
	BufferStrategyRing     = "ring"
)

// TCPConfiguration holds TCP-specific configuration options
type TCPConfiguration struct {
	// Performance tuning
	TCPPerformanceMode string `mapstructure:"tcp_performance_mode" yaml:"tcp_performance_mode"`
	TCPBatchSize       int    `mapstructure:"tcp_batch_size" yaml:"tcp_batch_size"`
	MaxTCPBuffers      int    `mapstructure:"max_tcp_buffers" yaml:"max_tcp_buffers"`
	TCPBufferStrategy  string `mapstructure:"tcp_buffer_strategy" yaml:"tcp_buffer_strategy"`

	// Resource limits
	TCPMemoryLimit        int           `mapstructure:"tcp_memory_limit" yaml:"tcp_memory_limit"`
	StreamQueueBuffer     int           `mapstructure:"stream_queue_buffer" yaml:"stream_queue_buffer"`
	TCPStreamMaxQueueTime time.Duration `mapstructure:"tcp_stream_max_queue_time" yaml:"tcp_stream_max_queue_time"`

	// Cleanup and maintenance
	TCPBufferMaxAge    time.Duration `mapstructure:"tcp_buffer_max_age" yaml:"tcp_buffer_max_age"`
	TCPCleanupInterval time.Duration `mapstructure:"tcp_cleanup_interval" yaml:"tcp_cleanup_interval"`

	// Optimization flags
	MemoryOptimization bool `mapstructure:"memory_optimization" yaml:"memory_optimization"`
	EnableAutoTuning   bool `mapstructure:"enable_auto_tuning" yaml:"enable_auto_tuning"`
}

// GetDefaultTCPConfig returns the default TCP configuration
func GetDefaultTCPConfig() TCPConfiguration {
	return TCPConfiguration{
		TCPPerformanceMode:    DefaultTCPPerformanceMode,
		TCPBatchSize:          DefaultTCPBatchSize,
		MaxTCPBuffers:         DefaultMaxTCPBuffers,
		TCPBufferStrategy:     BufferStrategyAdaptive,
		TCPMemoryLimit:        DefaultTCPMemoryLimit,
		StreamQueueBuffer:     DefaultStreamQueueBuffer,
		TCPStreamMaxQueueTime: DefaultTCPStreamMaxQueueTime,
		TCPBufferMaxAge:       DefaultTCPBufferMaxAge,
		TCPCleanupInterval:    DefaultTCPCleanupInterval,
		MemoryOptimization:    DefaultMemoryOptimization,
		EnableAutoTuning:      true,
	}
}

// ValidateTCPConfig validates TCP configuration values
func ValidateTCPConfig(config *TCPConfiguration) error {
	// Validate performance mode
	validModes := map[string]bool{
		"balanced":   true,
		"throughput": true,
		"latency":    true,
		"memory":     true,
	}
	if !validModes[config.TCPPerformanceMode] {
		config.TCPPerformanceMode = DefaultTCPPerformanceMode
	}

	// Validate buffer strategy
	validStrategies := map[string]bool{
		BufferStrategyAdaptive: true,
		BufferStrategyFixed:    true,
		BufferStrategyRing:     true,
	}
	if !validStrategies[config.TCPBufferStrategy] {
		config.TCPBufferStrategy = BufferStrategyAdaptive
	}

	// Ensure minimum values
	if config.TCPBatchSize < 1 {
		config.TCPBatchSize = 1
	}
	if config.MaxTCPBuffers < 100 {
		config.MaxTCPBuffers = 100
	}
	if config.StreamQueueBuffer < 10 {
		config.StreamQueueBuffer = 10
	}
	if config.TCPMemoryLimit < 10*1024*1024 { // Minimum 10MB
		config.TCPMemoryLimit = 10 * 1024 * 1024
	}

	// Ensure reasonable durations
	if config.TCPStreamMaxQueueTime < time.Second {
		config.TCPStreamMaxQueueTime = time.Second
	}
	if config.TCPBufferMaxAge < time.Minute {
		config.TCPBufferMaxAge = time.Minute
	}
	if config.TCPCleanupInterval < 10*time.Second {
		config.TCPCleanupInterval = 10 * time.Second
	}

	return nil
}

// ApplyTCPPerformanceProfile applies a performance profile to TCP configuration
func ApplyTCPPerformanceProfile(config *TCPConfiguration, profile string) {
	switch profile {
	case "high_throughput":
		config.TCPPerformanceMode = "throughput"
		config.TCPBatchSize = 64
		config.MaxTCPBuffers = 20000
		config.TCPBufferStrategy = BufferStrategyRing
		config.StreamQueueBuffer = 1000
		config.EnableAutoTuning = true

	case "low_latency":
		config.TCPPerformanceMode = "latency"
		config.TCPBatchSize = 1
		config.MaxTCPBuffers = 5000
		config.TCPBufferStrategy = BufferStrategyFixed
		config.StreamQueueBuffer = 100
		config.EnableAutoTuning = false

	case "memory_optimized":
		config.TCPPerformanceMode = "memory"
		config.TCPBatchSize = 16
		config.MaxTCPBuffers = 1000
		config.TCPBufferStrategy = BufferStrategyAdaptive
		config.StreamQueueBuffer = 50
		config.MemoryOptimization = true
		config.TCPMemoryLimit = 50 * 1024 * 1024 // 50MB
		config.EnableAutoTuning = true

	default: // "balanced"
		*config = GetDefaultTCPConfig()
	}
}

// GetTCPConfigSummary returns a summary of the current TCP configuration
func GetTCPConfigSummary(config *TCPConfiguration) map[string]interface{} {
	return map[string]interface{}{
		"performance_mode":    config.TCPPerformanceMode,
		"batch_size":          config.TCPBatchSize,
		"max_buffers":         config.MaxTCPBuffers,
		"buffer_strategy":     config.TCPBufferStrategy,
		"memory_limit_mb":     config.TCPMemoryLimit / (1024 * 1024),
		"queue_buffer_size":   config.StreamQueueBuffer,
		"max_queue_time":      config.TCPStreamMaxQueueTime.String(),
		"buffer_max_age":      config.TCPBufferMaxAge.String(),
		"cleanup_interval":    config.TCPCleanupInterval.String(),
		"memory_optimization": config.MemoryOptimization,
		"auto_tuning_enabled": config.EnableAutoTuning,
	}
}
