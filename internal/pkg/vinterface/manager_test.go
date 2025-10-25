package vinterface

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "lc0", cfg.Name)
	assert.Equal(t, "tap", cfg.Type)
	assert.Equal(t, 4096, cfg.BufferSize)
	assert.Equal(t, 1500, cfg.MTU)
}

func TestConfig_Validate_Valid(t *testing.T) {
	testCases := []struct {
		name   string
		config Config
	}{
		{
			name:   "default config",
			config: DefaultConfig(),
		},
		{
			name: "tap interface",
			config: Config{
				Name:       "lc0",
				Type:       "tap",
				BufferSize: 4096,
				MTU:        1500,
			},
		},
		{
			name: "tun interface",
			config: Config{
				Name:       "lc0",
				Type:       "tun",
				BufferSize: 4096,
				MTU:        1500,
			},
		},
		{
			name: "custom buffer size",
			config: Config{
				Name:       "lc0",
				Type:       "tap",
				BufferSize: 8192,
				MTU:        1500,
			},
		},
		{
			name: "jumbo frames",
			config: Config{
				Name:       "lc0",
				Type:       "tap",
				BufferSize: 4096,
				MTU:        9000,
			},
		},
		{
			name: "custom name",
			config: Config{
				Name:       "lippycat-voip0",
				Type:       "tap",
				BufferSize: 4096,
				MTU:        1500,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestConfig_Validate_InvalidName(t *testing.T) {
	cfg := Config{
		Name:       "", // Empty name
		Type:       "tap",
		BufferSize: 4096,
		MTU:        1500,
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidName)
}

func TestConfig_Validate_InvalidType(t *testing.T) {
	testCases := []struct {
		name       string
		ifaceType  string
		shouldFail bool
	}{
		{"tap is valid", "tap", false},
		{"tun is valid", "tun", false},
		{"empty type", "", true},
		{"invalid type", "invalid", true},
		{"ethernet", "ethernet", true},
		{"TAP (uppercase)", "TAP", true},
		{"TUN (uppercase)", "TUN", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Name:       "lc0",
				Type:       tc.ifaceType,
				BufferSize: 4096,
				MTU:        1500,
			}

			err := cfg.Validate()
			if tc.shouldFail {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidType)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_InvalidBufferSize(t *testing.T) {
	testCases := []struct {
		name       string
		bufferSize int
		shouldFail bool
	}{
		{"valid buffer size", 4096, false},
		{"small buffer", 1, false},
		{"large buffer", 65536, false},
		{"zero buffer", 0, true},
		{"negative buffer", -1, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Name:       "lc0",
				Type:       "tap",
				BufferSize: tc.bufferSize,
				MTU:        1500,
			}

			err := cfg.Validate()
			if tc.shouldFail {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidBufferSize)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_InvalidMTU(t *testing.T) {
	testCases := []struct {
		name       string
		mtu        int
		shouldFail bool
	}{
		{"standard MTU", 1500, false},
		{"minimum MTU", 1, false},
		{"maximum MTU", 65535, false},
		{"jumbo frames", 9000, false},
		{"zero MTU", 0, true},
		{"negative MTU", -1, true},
		{"too large MTU", 65536, true},
		{"way too large MTU", 100000, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Name:       "lc0",
				Type:       "tap",
				BufferSize: 4096,
				MTU:        tc.mtu,
			}

			err := cfg.Validate()
			if tc.shouldFail {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidMTU)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_Validate_MultipleErrors(t *testing.T) {
	// Test that validation returns the first error encountered
	cfg := Config{
		Name:       "",    // Invalid
		Type:       "bad", // Invalid
		BufferSize: -1,    // Invalid
		MTU:        0,     // Invalid
	}

	err := cfg.Validate()
	require.Error(t, err)

	// Should return the first error (invalid name)
	assert.ErrorIs(t, err, ErrInvalidName)
}

func TestErrors(t *testing.T) {
	// Test that all errors are defined and distinct
	errors := []error{
		ErrPlatformUnsupported,
		ErrInvalidName,
		ErrInvalidType,
		ErrInvalidBufferSize,
		ErrInvalidMTU,
		ErrInterfaceExists,
		ErrPermissionDenied,
		ErrNotStarted,
		ErrAlreadyStarted,
		ErrShuttingDown,
	}

	// All errors should be non-nil
	for i, err := range errors {
		assert.NotNil(t, err, "Error at index %d should not be nil", i)
	}

	// All errors should have unique messages
	messages := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		assert.False(t, messages[msg], "Duplicate error message: %s", msg)
		messages[msg] = true
	}

	// Verify specific error messages
	assert.Contains(t, ErrPlatformUnsupported.Error(), "not supported")
	assert.Contains(t, ErrInvalidName.Error(), "invalid interface name")
	assert.Contains(t, ErrInvalidType.Error(), "tap")
	assert.Contains(t, ErrInvalidType.Error(), "tun")
	assert.Contains(t, ErrInvalidBufferSize.Error(), "buffer size")
	assert.Contains(t, ErrInvalidMTU.Error(), "MTU")
	assert.Contains(t, ErrInterfaceExists.Error(), "already exists")
	assert.Contains(t, ErrPermissionDenied.Error(), "CAP_NET_ADMIN")
	assert.Contains(t, ErrNotStarted.Error(), "not started")
	assert.Contains(t, ErrAlreadyStarted.Error(), "already started")
	assert.Contains(t, ErrShuttingDown.Error(), "shutting down")
}

func TestStats_InitialValues(t *testing.T) {
	stats := Stats{}

	assert.Equal(t, uint64(0), stats.PacketsInjected)
	assert.Equal(t, uint64(0), stats.PacketsDropped)
	assert.Equal(t, uint64(0), stats.InjectionErrors)
	assert.Equal(t, uint64(0), stats.ConversionErrors)
	assert.Equal(t, 0.0, stats.QueueUtilization)
	assert.Equal(t, uint64(0), stats.BytesInjected)
	assert.True(t, stats.LastInjection.IsZero())
}
