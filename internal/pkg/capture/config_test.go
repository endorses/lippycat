package capture

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGetPacketBufferConfig(t *testing.T) {
	originalRegular := viper.Get("packet_buffer_size")
	originalSIP := viper.Get("sip_buffer_size")
	t.Cleanup(func() {
		viper.Set("packet_buffer_size", originalRegular)
		viper.Set("sip_buffer_size", originalSIP)
	})

	viper.Set("packet_buffer_size", 12)
	viper.Set("sip_buffer_size", 0)
	config, err := getPacketBufferConfig()
	assert.NoError(t, err)
	resolved, err := ResolvePacketBufferConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, 12, resolved.RegularCapacity)
	assert.Equal(t, 12, resolved.SIPCapacity)

	viper.Set("sip_buffer_size", 5)
	config, err = getPacketBufferConfig()
	assert.NoError(t, err)
	resolved, err = ResolvePacketBufferConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, 5, resolved.SIPCapacity)

	viper.Set("sip_buffer_size", -1)
	_, err = getPacketBufferConfig()
	assert.ErrorContains(t, err, "sip_buffer_size")
}

func TestGetPacketBufferConfigEnvironment(t *testing.T) {
	originalValue := viper.Get("sip_buffer_size")
	originalEnv, hadEnv := os.LookupEnv("LIPPYCAT_SIP_BUFFER_SIZE")
	t.Cleanup(func() {
		viper.Set("sip_buffer_size", originalValue)
		if hadEnv {
			assert.NoError(t, os.Setenv("LIPPYCAT_SIP_BUFFER_SIZE", originalEnv))
		} else {
			assert.NoError(t, os.Unsetenv("LIPPYCAT_SIP_BUFFER_SIZE"))
		}
	})

	viper.Set("sip_buffer_size", nil)
	assert.NoError(t, os.Setenv("LIPPYCAT_SIP_BUFFER_SIZE", "23"))
	config, err := getPacketBufferConfig()
	assert.NoError(t, err)
	assert.Equal(t, 23, config.SIPCapacity)
}

func TestGetPacketBufferConfigRejectsMalformedSIPCapacity(t *testing.T) {
	originalValue := viper.Get("sip_buffer_size")
	t.Cleanup(func() { viper.Set("sip_buffer_size", originalValue) })

	viper.Set("sip_buffer_size", "not-a-number")
	_, err := getPacketBufferConfig()
	assert.ErrorContains(t, err, "sip_buffer_size")
}

func TestGetPacketBufferSize(t *testing.T) {
	// Save original value
	originalValue := viper.Get("packet_buffer_size")
	defer func() {
		if originalValue != nil {
			viper.Set("packet_buffer_size", originalValue)
		} else {
			viper.Set("packet_buffer_size", nil)
		}
	}()

	t.Run("Default buffer size", func(t *testing.T) {
		// Clear any existing configuration
		viper.Set("packet_buffer_size", nil)

		size := getPacketBufferSize()
		assert.Equal(t, DefaultPacketBufferSize, size, "Should return default buffer size")
	})

	t.Run("Configured buffer size", func(t *testing.T) {
		viper.Set("packet_buffer_size", 5000)

		size := getPacketBufferSize()
		assert.Equal(t, 5000, size, "Should return configured buffer size")
	})

	t.Run("Invalid buffer size falls back to default", func(t *testing.T) {
		viper.Set("packet_buffer_size", 0)

		size := getPacketBufferSize()
		assert.Equal(t, DefaultPacketBufferSize, size, "Should fallback to default for invalid size")
	})

	t.Run("Negative buffer size falls back to default", func(t *testing.T) {
		viper.Set("packet_buffer_size", -100)

		size := getPacketBufferSize()
		assert.Equal(t, DefaultPacketBufferSize, size, "Should fallback to default for negative size")
	})
}
