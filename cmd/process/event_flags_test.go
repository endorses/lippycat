//go:build processor || all

package process

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventAuthorizationFlagsAreBound(t *testing.T) {
	testEventAuthorizationFlagBinding(t, "event-allow-sensitive-fields", "processor.events.allow_sensitive_fields")
	testEventAuthorizationFlagBinding(t, "event-allow-file-metadata", "processor.events.allow_file_metadata")
}

func testEventAuthorizationFlagBinding(t *testing.T, flagName, key string) {
	t.Helper()
	flag := ProcessCmd.Flags().Lookup(flagName)
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
