//go:build cli || all

package sniff

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestValidateLiveCaptureBufferConfigRejectsInvalidSIPCapacity(t *testing.T) {
	original := viper.Get("sip_buffer_size")
	t.Cleanup(func() { viper.Set("sip_buffer_size", original) })

	for _, value := range []any{-1, "not-an-integer", ""} {
		viper.Set("sip_buffer_size", value)
		err := validateLiveCaptureBufferConfig(nil, nil)
		require.ErrorContains(t, err, "sip_buffer_size")
	}
}
