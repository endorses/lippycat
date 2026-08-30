//go:build tap || all

package tap

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventAuthorizationFlagsAreBound(t *testing.T) {
	testEventAuthorizationFlagBinding(t, "event-allow-sensitive-fields", "tap.events.allow_sensitive_fields")
	testEventAuthorizationFlagBinding(t, "event-allow-file-metadata", "tap.events.allow_file_metadata")
}

func testEventAuthorizationFlagBinding(t *testing.T, flagName, key string) {
	t.Helper()
	flag := TapCmd.PersistentFlags().Lookup(flagName)
	require.NotNil(t, flag)
	previous := flag.Value.String()
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(previous))
		flag.Changed = false
	})

	viper.SetDefault(key, false)
	require.NoError(t, flag.Value.Set("true"))
	flag.Changed = true
	require.True(t, viper.GetBool(key))
}
