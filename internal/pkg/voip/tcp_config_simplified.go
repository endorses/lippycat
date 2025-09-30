package voip

import (
	"runtime"
	"time"
)

// SimplifiedTCPConfig contains only essential TCP configuration parameters
// Reducing complexity from 25+ parameters to 8 core settings
type SimplifiedTCPConfig struct {
	// Core Performance Profile - determines most other settings automatically
	PerformanceProfile string `mapstructure:"performance_profile" yaml:"performance_profile"`

	// Essential Resource Limits
	MaxMemoryMB     int           `mapstructure:"max_memory_mb" yaml:"max_memory_mb"`
	MaxActiveStreams int           `mapstructure:"max_active_streams" yaml:"max_active_streams"`
	StreamTimeout   time.Duration `mapstructure:"stream_timeout" yaml:"stream_timeout"`

	// Core Processing Settings
	WorkerThreads int  `mapstructure:"worker_threads" yaml:"worker_threads"`
	EnableMetrics bool `mapstructure:"enable_metrics" yaml:"enable_metrics"`

	// Advanced Settings (for power users)
	CustomBufferSize int  `mapstructure:"custom_buffer_size" yaml:"custom_buffer_size"`
	DebugMode       bool `mapstructure:"debug_mode" yaml:"debug_mode"`
}

// PerformanceProfile determines optimal settings for different use cases
type PerformanceProfile struct {
	Name                   string
	TCPPerformanceMode     string
	TCPBatchSize           int
	MaxTCPBuffers          int
	TCPBufferStrategy      string
	TCPMemoryLimit         int64
	StreamQueueBuffer      int
	TCPStreamMaxQueueTime  time.Duration
	TCPBufferMaxAge        time.Duration
	TCPCleanupInterval     time.Duration
	MemoryOptimization     bool
	EnableAutoTuning       bool
	TCPStreamTimeout       time.Duration
	TCPAssemblerMaxPages   int
	EnableBackpressure     bool
	TCPBufferPoolSize      int
	TCPIOThreads           int
	TCPCompressionLevel    int
	TCPLatencyOptimization bool
}

// GetSimplifiedDefaults returns the default simplified configuration
func GetSimplifiedDefaults() SimplifiedTCPConfig {
	return SimplifiedTCPConfig{
		PerformanceProfile: "balanced",
		MaxMemoryMB:        100,
		MaxActiveStreams:   1000,
		StreamTimeout:      300 * time.Second,
		WorkerThreads:      runtime.NumCPU(),
		EnableMetrics:      true,
		CustomBufferSize:   0, // 0 means auto-calculate
		DebugMode:          false,
	}
}

// GetPerformanceProfiles returns predefined performance profiles
func GetPerformanceProfiles() map[string]PerformanceProfile {
	return map[string]PerformanceProfile{
		"minimal": {
			Name:                   "minimal",
			TCPPerformanceMode:     "memory",
			TCPBatchSize:           8,
			MaxTCPBuffers:          500,
			TCPBufferStrategy:      "fixed",
			TCPMemoryLimit:         25 * 1024 * 1024, // 25MB
			StreamQueueBuffer:      50,
			TCPStreamMaxQueueTime:  60 * time.Second,
			TCPBufferMaxAge:        120 * time.Second,
			TCPCleanupInterval:     30 * time.Second,
			MemoryOptimization:     true,
			EnableAutoTuning:       false,
			TCPStreamTimeout:       180 * time.Second,
			TCPAssemblerMaxPages:   25,
			EnableBackpressure:     true,
			TCPBufferPoolSize:      100,
			TCPIOThreads:           1,
			TCPCompressionLevel:    1,
			TCPLatencyOptimization: false,
		},
		"balanced": {
			Name:                   "balanced",
			TCPPerformanceMode:     "balanced",
			TCPBatchSize:           32,
			MaxTCPBuffers:          5000,
			TCPBufferStrategy:      "adaptive",
			TCPMemoryLimit:         100 * 1024 * 1024, // 100MB
			StreamQueueBuffer:      250,
			TCPStreamMaxQueueTime:  120 * time.Second,
			TCPBufferMaxAge:        300 * time.Second,
			TCPCleanupInterval:     60 * time.Second,
			MemoryOptimization:     false,
			EnableAutoTuning:       true,
			TCPStreamTimeout:       300 * time.Second,
			TCPAssemblerMaxPages:   100,
			EnableBackpressure:     true,
			TCPBufferPoolSize:      1000,
			TCPIOThreads:           runtime.NumCPU(),
			TCPCompressionLevel:    1,
			TCPLatencyOptimization: false,
		},
		"high_performance": {
			Name:                   "high_performance",
			TCPPerformanceMode:     "throughput",
			TCPBatchSize:           64,
			MaxTCPBuffers:          20000,
			TCPBufferStrategy:      "ring",
			TCPMemoryLimit:         500 * 1024 * 1024, // 500MB
			StreamQueueBuffer:      1000,
			TCPStreamMaxQueueTime:  180 * time.Second,
			TCPBufferMaxAge:        600 * time.Second,
			TCPCleanupInterval:     120 * time.Second,
			MemoryOptimization:     false,
			EnableAutoTuning:       true,
			TCPStreamTimeout:       600 * time.Second,
			TCPAssemblerMaxPages:   500,
			EnableBackpressure:     false,
			TCPBufferPoolSize:      5000,
			TCPIOThreads:           runtime.NumCPU() * 2,
			TCPCompressionLevel:    0, // No compression for max speed
			TCPLatencyOptimization: false,
		},
		"low_latency": {
			Name:                   "low_latency",
			TCPPerformanceMode:     "latency",
			TCPBatchSize:           1,
			MaxTCPBuffers:          2000,
			TCPBufferStrategy:      "fixed",
			TCPMemoryLimit:         200 * 1024 * 1024, // 200MB
			StreamQueueBuffer:      100,
			TCPStreamMaxQueueTime:  30 * time.Second,
			TCPBufferMaxAge:        60 * time.Second,
			TCPCleanupInterval:     15 * time.Second,
			MemoryOptimization:     false,
			EnableAutoTuning:       false,
			TCPStreamTimeout:       120 * time.Second,
			TCPAssemblerMaxPages:   50,
			EnableBackpressure:     false,
			TCPBufferPoolSize:      500,
			TCPIOThreads:           runtime.NumCPU(),
			TCPCompressionLevel:    0,
			TCPLatencyOptimization: true,
		},
	}
}

// ExpandSimplifiedConfig converts simplified config to full detailed config
func ExpandSimplifiedConfig(simple SimplifiedTCPConfig) *Config {
	profiles := GetPerformanceProfiles()
	profile, exists := profiles[simple.PerformanceProfile]
	if !exists {
		profile = profiles["balanced"] // Fallback to balanced
	}

	// Override profile settings with user-specified values
	if simple.MaxMemoryMB > 0 {
		profile.TCPMemoryLimit = int64(simple.MaxMemoryMB) * 1024 * 1024
	}
	if simple.MaxActiveStreams > 0 {
		profile.MaxTCPBuffers = simple.MaxActiveStreams
		profile.StreamQueueBuffer = simple.MaxActiveStreams / 4
	}
	if simple.StreamTimeout > 0 {
		profile.TCPStreamTimeout = simple.StreamTimeout
		profile.TCPStreamMaxQueueTime = simple.StreamTimeout / 2
	}
	if simple.WorkerThreads > 0 {
		profile.TCPIOThreads = simple.WorkerThreads
	}
	if simple.CustomBufferSize > 0 {
		profile.TCPBatchSize = simple.CustomBufferSize
	}

	// Create full config from profile
	config := &Config{
		MaxGoroutines:             simple.MaxActiveStreams,
		CallIDDetectionTimeout:    DefaultCallIDDetectionTimeout,
		JanitorCleanupInterval:    profile.TCPCleanupInterval / 2, // More frequent cleanup
		CallExpirationTime:        profile.TCPBufferMaxAge,
		StreamQueueBuffer:         profile.StreamQueueBuffer,
		MaxFilenameLength:         100,
		LogGoroutineLimitInterval: 30 * time.Second,

		// TCP-specific configurations from profile
		TCPCleanupInterval:    profile.TCPCleanupInterval,
		TCPBufferMaxAge:       profile.TCPBufferMaxAge,
		TCPStreamMaxQueueTime: profile.TCPStreamMaxQueueTime,
		MaxTCPBuffers:         profile.MaxTCPBuffers,
		TCPStreamTimeout:      profile.TCPStreamTimeout,
		TCPAssemblerMaxPages:  profile.TCPAssemblerMaxPages,

		// TCP Performance configurations from profile
		TCPPerformanceMode:     profile.TCPPerformanceMode,
		TCPBufferStrategy:      profile.TCPBufferStrategy,
		EnableBackpressure:     profile.EnableBackpressure,
		MemoryOptimization:     profile.MemoryOptimization,
		TCPBufferPoolSize:      profile.TCPBufferPoolSize,
		TCPBatchSize:           profile.TCPBatchSize,
		TCPIOThreads:           profile.TCPIOThreads,
		TCPCompressionLevel:    profile.TCPCompressionLevel,
		TCPMemoryLimit:         profile.TCPMemoryLimit,
		TCPLatencyOptimization: profile.TCPLatencyOptimization,
	}

	return config
}

// ValidateSimplifiedConfig validates the simplified configuration
func ValidateSimplifiedConfig(config *SimplifiedTCPConfig) error {
	profiles := GetPerformanceProfiles()
	if _, exists := profiles[config.PerformanceProfile]; !exists {
		config.PerformanceProfile = "balanced"
	}

	if config.MaxMemoryMB < 10 {
		config.MaxMemoryMB = 25 // Minimum 25MB
	}
	if config.MaxMemoryMB > 2048 {
		config.MaxMemoryMB = 2048 // Maximum 2GB
	}

	if config.MaxActiveStreams < 10 {
		config.MaxActiveStreams = 100
	}
	if config.MaxActiveStreams > 50000 {
		config.MaxActiveStreams = 50000
	}

	if config.StreamTimeout < 30*time.Second {
		config.StreamTimeout = 30 * time.Second
	}
	if config.StreamTimeout > 3600*time.Second {
		config.StreamTimeout = 3600 * time.Second // Max 1 hour
	}

	if config.WorkerThreads < 1 {
		config.WorkerThreads = 1
	}
	if config.WorkerThreads > runtime.NumCPU()*4 {
		config.WorkerThreads = runtime.NumCPU() * 4
	}

	return nil
}

// GetConfigurationSummary returns a human-readable summary of the simplified config
func GetConfigurationSummary(config SimplifiedTCPConfig) map[string]interface{} {
	return map[string]interface{}{
		"profile":             config.PerformanceProfile,
		"memory_limit_mb":     config.MaxMemoryMB,
		"max_active_streams":  config.MaxActiveStreams,
		"stream_timeout":      config.StreamTimeout.String(),
		"worker_threads":      config.WorkerThreads,
		"metrics_enabled":     config.EnableMetrics,
		"custom_buffer_size":  config.CustomBufferSize,
		"debug_mode":          config.DebugMode,
		"auto_tuned_params":   getAutoTunedParamsCount(config.PerformanceProfile),
	}
}

// getAutoTunedParamsCount returns how many parameters are automatically set by the profile
func getAutoTunedParamsCount(profile string) int {
	switch profile {
	case "minimal":
		return 17 // Most parameters auto-tuned for minimal resource usage
	case "balanced":
		return 19 // Balanced auto-tuning
	case "high_performance":
		return 19 // Performance-oriented auto-tuning
	case "low_latency":
		return 18 // Latency-focused auto-tuning
	default:
		return 19
	}
}