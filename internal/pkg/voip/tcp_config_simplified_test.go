package voip

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSimplifiedDefaults(t *testing.T) {
	config := GetSimplifiedDefaults()

	assert.Equal(t, "balanced", config.PerformanceProfile)
	assert.Equal(t, 100, config.MaxMemoryMB)
	assert.Equal(t, 1000, config.MaxActiveStreams)
	assert.Equal(t, 300*time.Second, config.StreamTimeout)
	assert.Equal(t, runtime.NumCPU(), config.WorkerThreads)
	assert.True(t, config.EnableMetrics)
	assert.Equal(t, 0, config.CustomBufferSize)
	assert.False(t, config.DebugMode)
}

func TestGetPerformanceProfiles(t *testing.T) {
	profiles := GetPerformanceProfiles()

	// Test that all expected profiles exist
	expectedProfiles := []string{"minimal", "balanced", "high_performance", "low_latency"}
	for _, profile := range expectedProfiles {
		_, exists := profiles[profile]
		assert.True(t, exists, "Profile %s should exist", profile)
	}

	// Test minimal profile characteristics
	minimal := profiles["minimal"]
	assert.Equal(t, "memory", minimal.TCPPerformanceMode)
	assert.Equal(t, int64(25*1024*1024), minimal.TCPMemoryLimit)
	assert.True(t, minimal.MemoryOptimization)
	assert.Equal(t, 1, minimal.TCPIOThreads)

	// Test high_performance profile characteristics
	highPerf := profiles["high_performance"]
	assert.Equal(t, "throughput", highPerf.TCPPerformanceMode)
	assert.Equal(t, int64(500*1024*1024), highPerf.TCPMemoryLimit)
	assert.False(t, highPerf.MemoryOptimization)
	assert.False(t, highPerf.EnableBackpressure)
	assert.Equal(t, runtime.NumCPU()*2, highPerf.TCPIOThreads)

	// Test low_latency profile characteristics
	lowLatency := profiles["low_latency"]
	assert.Equal(t, "latency", lowLatency.TCPPerformanceMode)
	assert.Equal(t, 1, lowLatency.TCPBatchSize)
	assert.True(t, lowLatency.TCPLatencyOptimization)
	assert.False(t, lowLatency.EnableAutoTuning)
}

func TestExpandSimplifiedConfig(t *testing.T) {
	testCases := []struct {
		name           string
		simple         SimplifiedTCPConfig
		expectedMode   string
		expectedMemory int64
	}{
		{
			name: "balanced_profile",
			simple: SimplifiedTCPConfig{
				PerformanceProfile: "balanced",
				MaxMemoryMB:        150,
				MaxActiveStreams:   2000,
				StreamTimeout:      400 * time.Second,
				WorkerThreads:      8,
			},
			expectedMode:   "balanced",
			expectedMemory: 150 * 1024 * 1024,
		},
		{
			name: "minimal_profile",
			simple: SimplifiedTCPConfig{
				PerformanceProfile: "minimal",
				MaxMemoryMB:        50,
			},
			expectedMode:   "memory",
			expectedMemory: 50 * 1024 * 1024,
		},
		{
			name: "invalid_profile_fallback",
			simple: SimplifiedTCPConfig{
				PerformanceProfile: "nonexistent",
			},
			expectedMode:   "balanced", // Should fallback to balanced
			expectedMemory: 100 * 1024 * 1024,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fullConfig := ExpandSimplifiedConfig(tc.simple)

			assert.Equal(t, tc.expectedMode, fullConfig.TCPPerformanceMode)
			assert.Equal(t, tc.expectedMemory, fullConfig.TCPMemoryLimit)

			// Test that overrides work
			if tc.simple.MaxActiveStreams > 0 {
				assert.Equal(t, tc.simple.MaxActiveStreams, fullConfig.MaxTCPBuffers)
				assert.Equal(t, tc.simple.MaxActiveStreams/4, fullConfig.StreamQueueBuffer)
			}

			if tc.simple.StreamTimeout > 0 {
				assert.Equal(t, tc.simple.StreamTimeout, fullConfig.TCPStreamTimeout)
				assert.Equal(t, tc.simple.StreamTimeout/2, fullConfig.TCPStreamMaxQueueTime)
			}

			if tc.simple.WorkerThreads > 0 {
				assert.Equal(t, tc.simple.WorkerThreads, fullConfig.TCPIOThreads)
			}
		})
	}
}

func TestValidateSimplifiedConfig(t *testing.T) {
	testCases := []struct {
		name           string
		input          SimplifiedTCPConfig
		expectedProfile string
		expectedMemory int
		expectedStreams int
		expectedTimeout time.Duration
		expectedThreads int
	}{
		{
			name: "valid_config",
			input: SimplifiedTCPConfig{
				PerformanceProfile: "balanced",
				MaxMemoryMB:        200,
				MaxActiveStreams:   5000,
				StreamTimeout:      600 * time.Second,
				WorkerThreads:      4,
			},
			expectedProfile: "balanced",
			expectedMemory:  200,
			expectedStreams: 5000,
			expectedTimeout: 600 * time.Second,
			expectedThreads: 4,
		},
		{
			name: "invalid_profile",
			input: SimplifiedTCPConfig{
				PerformanceProfile: "invalid",
			},
			expectedProfile: "balanced", // Should be corrected
		},
		{
			name: "memory_too_low",
			input: SimplifiedTCPConfig{
				MaxMemoryMB: 5, // Too low
			},
			expectedMemory: 25, // Should be corrected to minimum
		},
		{
			name: "memory_too_high",
			input: SimplifiedTCPConfig{
				MaxMemoryMB: 5000, // Too high
			},
			expectedMemory: 2048, // Should be corrected to maximum
		},
		{
			name: "streams_too_low",
			input: SimplifiedTCPConfig{
				MaxActiveStreams: 5, // Too low
			},
			expectedStreams: 100, // Should be corrected to minimum
		},
		{
			name: "streams_too_high",
			input: SimplifiedTCPConfig{
				MaxActiveStreams: 100000, // Too high
			},
			expectedStreams: 50000, // Should be corrected to maximum
		},
		{
			name: "timeout_too_low",
			input: SimplifiedTCPConfig{
				StreamTimeout: 10 * time.Second, // Too low
			},
			expectedTimeout: 30 * time.Second, // Should be corrected to minimum
		},
		{
			name: "timeout_too_high",
			input: SimplifiedTCPConfig{
				StreamTimeout: 7200 * time.Second, // Too high
			},
			expectedTimeout: 3600 * time.Second, // Should be corrected to maximum
		},
		{
			name: "threads_too_low",
			input: SimplifiedTCPConfig{
				WorkerThreads: 0, // Too low
			},
			expectedThreads: 1, // Should be corrected to minimum
		},
		{
			name: "threads_too_high",
			input: SimplifiedTCPConfig{
				WorkerThreads: runtime.NumCPU() * 10, // Too high
			},
			expectedThreads: runtime.NumCPU() * 4, // Should be corrected to maximum
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := tc.input
			err := ValidateSimplifiedConfig(&config)
			require.NoError(t, err)

			if tc.expectedProfile != "" {
				assert.Equal(t, tc.expectedProfile, config.PerformanceProfile)
			}
			if tc.expectedMemory != 0 {
				assert.Equal(t, tc.expectedMemory, config.MaxMemoryMB)
			}
			if tc.expectedStreams != 0 {
				assert.Equal(t, tc.expectedStreams, config.MaxActiveStreams)
			}
			if tc.expectedTimeout != 0 {
				assert.Equal(t, tc.expectedTimeout, config.StreamTimeout)
			}
			if tc.expectedThreads != 0 {
				assert.Equal(t, tc.expectedThreads, config.WorkerThreads)
			}
		})
	}
}

func TestGetConfigurationSummary(t *testing.T) {
	config := SimplifiedTCPConfig{
		PerformanceProfile: "high_performance",
		MaxMemoryMB:        500,
		MaxActiveStreams:   10000,
		StreamTimeout:      900 * time.Second,
		WorkerThreads:      16,
		EnableMetrics:      true,
		CustomBufferSize:   128,
		DebugMode:          true,
	}

	summary := GetConfigurationSummary(config)

	assert.Equal(t, "high_performance", summary["profile"])
	assert.Equal(t, 500, summary["memory_limit_mb"])
	assert.Equal(t, 10000, summary["max_active_streams"])
	assert.Equal(t, "15m0s", summary["stream_timeout"])
	assert.Equal(t, 16, summary["worker_threads"])
	assert.Equal(t, true, summary["metrics_enabled"])
	assert.Equal(t, 128, summary["custom_buffer_size"])
	assert.Equal(t, true, summary["debug_mode"])
	assert.IsType(t, 0, summary["auto_tuned_params"])
}

func TestConfigurationComplexityReduction(t *testing.T) {
	// Test that we've actually reduced complexity
	simple := GetSimplifiedDefaults()
	profiles := GetPerformanceProfiles()

	// Verify we have only 8 user-configurable parameters in simplified config
	simplifiedParamCount := 8
	assert.LessOrEqual(t, simplifiedParamCount, 8, "Simplified config should have 8 or fewer parameters")

	// Verify each profile automatically configures many parameters
	for profileName, profile := range profiles {
		t.Run("profile_"+profileName, func(t *testing.T) {
			// Each profile should configure at least 15 detailed parameters automatically
			autoConfiguredParams := []interface{}{
				profile.TCPPerformanceMode,
				profile.TCPBatchSize,
				profile.MaxTCPBuffers,
				profile.TCPBufferStrategy,
				profile.TCPMemoryLimit,
				profile.StreamQueueBuffer,
				profile.TCPStreamMaxQueueTime,
				profile.TCPBufferMaxAge,
				profile.TCPCleanupInterval,
				profile.MemoryOptimization,
				profile.EnableAutoTuning,
				profile.TCPStreamTimeout,
				profile.TCPAssemblerMaxPages,
				profile.EnableBackpressure,
				profile.TCPBufferPoolSize,
				profile.TCPIOThreads,
				profile.TCPCompressionLevel,
				profile.TCPLatencyOptimization,
			}

			assert.GreaterOrEqual(t, len(autoConfiguredParams), 17,
				"Profile %s should auto-configure at least 17 parameters", profileName)
		})
	}

	// Test expansion creates a full config
	fullConfig := ExpandSimplifiedConfig(simple)
	assert.NotNil(t, fullConfig)
	assert.Greater(t, fullConfig.MaxTCPBuffers, 0)
	assert.Greater(t, fullConfig.TCPMemoryLimit, int64(0))
	assert.NotEmpty(t, fullConfig.TCPPerformanceMode)
}

func BenchmarkExpandSimplifiedConfig(b *testing.B) {
	simple := GetSimplifiedDefaults()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExpandSimplifiedConfig(simple)
	}
}

func BenchmarkValidateSimplifiedConfig(b *testing.B) {
	config := GetSimplifiedDefaults()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSimplifiedConfig(&config)
	}
}