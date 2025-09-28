package capture

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

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
