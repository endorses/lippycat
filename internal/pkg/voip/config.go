package voip

import (
	"sync"
	"time"
)

var (
	configMu sync.RWMutex
	config   = DefaultConfig()
	// configOnce remains only for compatibility with legacy in-package tests.
	configOnce sync.Once
)

// ResetConfigCache restores the immutable process configuration to defaults.
// It exists for tests; production composition should call SetConfig once.
func ResetConfigCache() {
	SetConfig(DefaultConfig())
}

// initConfigDefaults is retained for older in-package tests. Defaults are now
// ordinary Go values rather than registrations in a global config registry.
func initConfigDefaults() {}

// Config holds all configurable VoIP processing parameters
type Config struct {
	// Output and registry settings are resolved by command composition.
	WriteVoIP               bool
	OutputFile              string
	MaxCalls                int
	MaxEndpointsPerCall     int
	MaxEndpointAssociations int
	PCAPGracePeriod         time.Duration
	Security                SecurityConfig

	VirtualInterface      bool
	VIFName               string
	VIFType               string
	VIFBufferSize         int
	VIFNetNS              string
	VIFDropPrivilegesUser string
	VIFReplayTiming       bool
	VIFStartupDelay       time.Duration
	ProcessorWorkers      int
	ProcessorWorkerBuffer int
	// Goroutine limits
	MaxGoroutines int `mapstructure:"max_goroutines"`

	// MaxStreams is a hard cap on concurrent TCP SIP streams. 0 = unlimited.
	// Unlike MaxGoroutines (a warning threshold), exceeding this rejects new streams.
	MaxStreams int `mapstructure:"max_streams"`

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
	TCPSIPIdleTimeout     time.Duration `mapstructure:"tcp_sip_idle_timeout"` // Idle timeout for SIP TCP connections

	// Phase 3: State-based TCP timeout configurations
	EnableStateTCPTimeouts bool          `mapstructure:"enable_state_tcp_timeouts"` // Enable state-based timeouts
	TCPOpeningTimeout      time.Duration `mapstructure:"tcp_opening_timeout"`       // Timeout for OPENING state (no SIP yet)
	TCPEstablishedTimeout  time.Duration `mapstructure:"tcp_established_timeout"`   // Timeout for ESTABLISHED state (valid SIP)
	TCPClosingTimeout      time.Duration `mapstructure:"tcp_closing_timeout"`       // Timeout for CLOSING state
	EnableCallAwareTimeout bool          `mapstructure:"enable_call_aware_timeout"` // Keep streams open for active calls

	// TCP Performance configurations
	TCPPerformanceMode string `mapstructure:"tcp_performance_mode"`
	TCPBufferStrategy  string `mapstructure:"tcp_buffer_strategy"`
	EnableBackpressure bool   `mapstructure:"enable_backpressure"`
	MemoryOptimization bool   `mapstructure:"memory_optimization"`

	// Performance tuning parameters
	TCPBufferPoolSize   int   `mapstructure:"tcp_buffer_pool_size"`
	TCPBatchSize        int   `mapstructure:"tcp_batch_size"`
	TCPIOThreads        int   `mapstructure:"tcp_io_threads"`
	TCPCompressionLevel int   `mapstructure:"tcp_compression_level"`
	TCPMemoryLimit      int64 `mapstructure:"tcp_memory_limit"`

	// Plugin system configurations
	PluginsEnabled       bool     `mapstructure:"plugins_enabled"`
	PluginPaths          []string `mapstructure:"plugin_paths"`
	PluginWatchEnabled   bool     `mapstructure:"plugin_watch_enabled"`
	PluginSIPEnabled     bool     `mapstructure:"plugin_sip_enabled"`
	PluginRTPEnabled     bool     `mapstructure:"plugin_rtp_enabled"`
	PluginGenericEnabled bool     `mapstructure:"plugin_generic_enabled"`

	// Monitoring configurations - disabled by default
	MonitoringEnabled        bool          `mapstructure:"monitoring_enabled"`
	MetricsEnabled           bool          `mapstructure:"metrics_enabled"`
	TracingEnabled           bool          `mapstructure:"tracing_enabled"`
	MonitoringUpdateInterval time.Duration `mapstructure:"monitoring_update_interval"`
	EnableRuntimeMetrics     bool          `mapstructure:"enable_runtime_metrics"`
	EnableSystemMetrics      bool          `mapstructure:"enable_system_metrics"`
	EnablePluginMetrics      bool          `mapstructure:"enable_plugin_metrics"`
	TCPLatencyOptimization   bool          `mapstructure:"tcp_latency_optimization"`
	EnableAutoTuning         bool          `mapstructure:"enable_auto_tuning"`
}

// GetConfig returns a copy of the installed process configuration.
func GetConfig() *Config {
	configMu.RLock()
	defer configMu.RUnlock()
	cfg := *config
	cfg.PluginPaths = append([]string(nil), config.PluginPaths...)
	return &cfg
}

// SetConfig installs a defensive copy. Call it at a command/composition boundary
// before starting packet-processing goroutines.
func SetConfig(cfg *Config) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	clone := *cfg
	clone.PluginPaths = append([]string(nil), cfg.PluginPaths...)
	configMu.Lock()
	config = &clone
	configMu.Unlock()
}

func securityConfigSnapshot() SecurityConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return config.Security
}

// DefaultConfig returns the balanced, dependency-free library defaults.
func DefaultConfig() *Config {
	profile := GetPerformanceProfiles()[DefaultTCPPerformanceMode]
	return &Config{
		PCAPGracePeriod: 5 * time.Second,
		Security:        DefaultSecurityConfig(), VIFName: "lc0", VIFType: "tap", VIFBufferSize: 4096,
		MaxGoroutines: DefaultGoroutineLimit, MaxStreams: DefaultMaxStreams,
		MaxEndpointsPerCall: 64, MaxEndpointAssociations: DefaultMaxCalls * 8,
		CallIDDetectionTimeout: DefaultCallIDDetectionTimeout,
		JanitorCleanupInterval: profile.TCPCleanupInterval / 2,
		CallExpirationTime:     profile.TCPBufferMaxAge,
		StreamQueueBuffer:      profile.StreamQueueBuffer,
		MaxFilenameLength:      DefaultMaxFilenameLength, LogGoroutineLimitInterval: 30 * time.Second,
		TCPCleanupInterval:    profile.TCPCleanupInterval,
		TCPBufferMaxAge:       profile.TCPBufferMaxAge,
		TCPStreamMaxQueueTime: profile.TCPStreamMaxQueueTime,
		MaxTCPBuffers:         profile.MaxTCPBuffers,
		TCPStreamTimeout:      profile.TCPStreamTimeout,
		TCPAssemblerMaxPages:  profile.TCPAssemblerMaxPages,
		TCPSIPIdleTimeout:     DefaultTCPSIPIdleTimeout,
		TCPOpeningTimeout:     DefaultTCPOpeningTimeout, TCPEstablishedTimeout: DefaultTCPEstablishedTimeout,
		TCPClosingTimeout:      DefaultTCPClosingTimeout,
		TCPPerformanceMode:     DefaultTCPPerformanceMode,
		TCPBufferStrategy:      profile.TCPBufferStrategy,
		EnableBackpressure:     profile.EnableBackpressure,
		MemoryOptimization:     profile.MemoryOptimization,
		TCPBufferPoolSize:      profile.TCPBufferPoolSize,
		TCPBatchSize:           profile.TCPBatchSize,
		TCPIOThreads:           profile.TCPIOThreads,
		TCPCompressionLevel:    profile.TCPCompressionLevel,
		TCPMemoryLimit:         profile.TCPMemoryLimit,
		TCPLatencyOptimization: profile.TCPLatencyOptimization,

		PluginSIPEnabled: true, PluginRTPEnabled: true, PluginGenericEnabled: true,
		MonitoringUpdateInterval: 30 * time.Second,
		EnableRuntimeMetrics:     true, EnablePluginMetrics: true, EnableAutoTuning: true,
	}
}
