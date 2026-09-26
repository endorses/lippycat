//go:build tap || all

package tap

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestTapFilterStoreConfiguration(t *testing.T) {
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`tap:
  filter_file: /configured/filters.enc
  filter_store:
    mode: encrypted
    key_file: /configured/key
    key_id: active
    read_keys: [old=/configured/old]
`)))
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
	var config processor.Config
	require.NoError(t, applyTapFilterStoreConfig(&config))
	require.Equal(t, "/configured/filters.enc", config.FilterFile)
	require.Equal(t, filtering.StoreEncrypted, config.FilterStoreMode)
	require.Equal(t, securestore.KeyRef{ID: "active", File: "/configured/key"}, config.FilterStoreKeys.Active)
	require.Equal(t, []securestore.KeyRef{{ID: "old", File: "/configured/old"}}, config.FilterStoreKeys.Prior)

	t.Setenv("LIPPYCAT_TAP_FILTER_STORE_KEY_ID", "env-active")
	t.Setenv("LIPPYCAT_TAP_FILTER_STORE_READ_KEYS", "")
	require.NoError(t, applyTapFilterStoreConfig(&config))
	require.Equal(t, "env-active", config.FilterStoreKeys.Active.ID)
	require.Empty(t, config.FilterStoreKeys.Prior)
	flag := TapCmd.PersistentFlags().Lookup("filter-store-key-id")
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(previous)); flag.Changed = changed })
	require.NoError(t, TapCmd.PersistentFlags().Set("filter-store-key-id", ""))
	require.NoError(t, applyTapFilterStoreConfig(&config))
	require.Empty(t, config.FilterStoreKeys.Active.ID)
}

func TestTapFilterStoreFlagsInheritedByEveryProtocol(t *testing.T) {
	for _, cmd := range []*cobra.Command{dnsTapCmd, tlsTapCmd, httpTapCmd, emailTapCmd, voipTapCmd, radiusTapCmd} {
		for name, expected := range map[string]string{
			"filter-file": "", "filter-store-mode": "auto", "filter-store-key-file": "", "filter-store-key-id": "", "filter-store-read-key": "[]",
		} {
			flag := cmd.InheritedFlags().Lookup(name)
			require.NotNil(t, flag, "%s --%s", cmd.Name(), name)
			require.Equal(t, expected, flag.DefValue)
		}
	}
}

func TestTapRuntimeValidatesFilterStoreForEveryProtocol(t *testing.T) {
	flag := TapCmd.PersistentFlags().Lookup("filter-store-read-key")
	values := flag.Value.(pflag.SliceValue)
	previous, changed := values.GetSlice(), flag.Changed
	t.Cleanup(func() { require.NoError(t, values.Replace(previous)); flag.Changed = changed })
	require.NoError(t, values.Replace([]string{"invalid-private-reference"}))
	flag.Changed = true
	for _, name := range []string{"generic", "dns", "tls", "http", "email", "voip", "radius"} {
		t.Run(name, func(t *testing.T) {
			_, err := newTapRuntime(processor.Config{}, "", protocolcatalog.MustLookup(name), tapRuntimeHooks{})
			require.ErrorContains(t, err, "filter-store read key")
			require.NotContains(t, err.Error(), "invalid-private-reference")
		})
	}
}
