//go:build processor || all

package process

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestProcessFilterStoreConfiguration(t *testing.T) {
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(`processor:
  filter_file: /configured/filters.enc
  filter_store:
    mode: encrypted
    key_file: /configured/key
    key_id: active
    read_keys: [old=/configured/old]
`)))
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
	var config processor.Config
	require.NoError(t, applyProcessFilterStoreConfig(&config))
	require.Equal(t, "/configured/filters.enc", config.FilterFile)
	require.Equal(t, filtering.StoreEncrypted, config.FilterStoreMode)
	require.Equal(t, securestore.KeyRef{ID: "active", File: "/configured/key"}, config.FilterStoreKeys.Active)
	require.Equal(t, []securestore.KeyRef{{ID: "old", File: "/configured/old"}}, config.FilterStoreKeys.Prior)

	t.Setenv("LIPPYCAT_PROCESSOR_FILTER_FILE", "/env/filters.enc")
	t.Setenv("LIPPYCAT_PROCESSOR_FILTER_STORE_READ_KEYS", "")
	require.NoError(t, applyProcessFilterStoreConfig(&config))
	require.Equal(t, "/env/filters.enc", config.FilterFile)
	require.Empty(t, config.FilterStoreKeys.Prior)
	flag := ProcessCmd.Flags().Lookup("filter-file")
	previous, changed := flag.Value.String(), flag.Changed
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(previous)); flag.Changed = changed })
	require.NoError(t, ProcessCmd.Flags().Set("filter-file", ""))
	require.NoError(t, applyProcessFilterStoreConfig(&config))
	require.Empty(t, config.FilterFile, "explicit CLI empty selects the core's mode-dependent default")
}

func TestProcessFilterStoreFlagsAvailableWithoutLI(t *testing.T) {
	for name, expected := range map[string]string{
		"filter-file": "", "filter-store-mode": "auto", "filter-store-key-file": "", "filter-store-key-id": "", "filter-store-read-key": "[]",
	} {
		flag := ProcessCmd.Flags().Lookup(name)
		require.NotNil(t, flag, name)
		require.Equal(t, expected, flag.DefValue)
	}
	require.Equal(t, "f", ProcessCmd.Flags().Lookup("filter-file").Shorthand)
}
