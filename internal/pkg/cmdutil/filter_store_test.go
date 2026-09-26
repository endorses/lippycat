package cmdutil

import (
	"os"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func filterStoreTestConfig(t *testing.T, role, yaml string) (*pflag.FlagSet, *viper.Viper) {
	t.Helper()
	for _, setting := range filterStoreSettings {
		name := filterStoreEnv(role, setting.key)
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
	flags := pflag.NewFlagSet("filter-store", pflag.ContinueOnError)
	flags.String("filter-file", "", "")
	config := viper.New()
	require.NoError(t, RegisterFilterStoreFlags(flags, config, role))
	config.SetConfigType("yaml")
	if yaml != "" {
		require.NoError(t, config.ReadConfig(strings.NewReader(yaml)))
	}
	return flags, config
}

func TestFilterStoreConfigDefaultsAndConstructorValues(t *testing.T) {
	flags, config := filterStoreTestConfig(t, "processor", "")
	got, err := ReadFilterStoreConfig(flags, config, "processor", filtering.StoreConfig{})
	require.NoError(t, err)
	require.Equal(t, filtering.StoreAuto, got.Mode)
	require.Empty(t, got.File, "only the effective runtime can choose a default filename")
	require.Empty(t, got.Keys.Active)
	require.Empty(t, got.Keys.Prior)

	base := filtering.StoreConfig{Mode: filtering.StoreEncrypted, File: "/constructor/store", Keys: securestore.KeyConfig{
		Active: securestore.KeyRef{ID: "active", File: "/constructor/key"},
		Prior:  []securestore.KeyRef{{ID: "old", File: "/constructor/old"}},
	}}
	got, err = ReadFilterStoreConfig(flags, config, "processor", base)
	require.NoError(t, err)
	require.Equal(t, base, got)
	got.Keys.Prior[0].File = "/changed"
	require.Equal(t, "/constructor/old", base.Keys.Prior[0].File)
}

func TestFilterStoreConfigPrecedence(t *testing.T) {
	for _, role := range []string{"processor", "tap"} {
		t.Run(role, func(t *testing.T) {
			flags, config := filterStoreTestConfig(t, role, role+`:
  filter_file: /yaml/store
  filter_store:
    mode: encrypted
    key_file: /yaml/key
    key_id: yaml-active
    read_keys: [yaml-old=/yaml/old]
`)
			got, err := ReadFilterStoreConfig(flags, config, role, filtering.StoreConfig{})
			require.NoError(t, err)
			require.Equal(t, "/yaml/store", got.File)
			require.Equal(t, filtering.StoreEncrypted, got.Mode)
			require.Equal(t, securestore.KeyRef{ID: "yaml-active", File: "/yaml/key"}, got.Keys.Active)
			require.Equal(t, []securestore.KeyRef{{ID: "yaml-old", File: "/yaml/old"}}, got.Keys.Prior)

			for key, value := range map[string]string{
				"filter_file": "/env/store", "filter_store.mode": "yaml", "filter_store.key_file": "/env/key",
				"filter_store.key_id": "env-active", "filter_store.read_keys": `env-old=/env/old,"env-older=/env/with,comma"`,
			} {
				t.Setenv(filterStoreEnv(role, key), value)
			}
			got, err = ReadFilterStoreConfig(flags, config, role, filtering.StoreConfig{})
			require.NoError(t, err)
			require.Equal(t, "/env/store", got.File)
			require.Equal(t, filtering.StoreYAML, got.Mode)
			require.Equal(t, securestore.KeyRef{ID: "env-active", File: "/env/key"}, got.Keys.Active)
			require.Equal(t, []securestore.KeyRef{{ID: "env-old", File: "/env/old"}, {ID: "env-older", File: "/env/with,comma"}}, got.Keys.Prior)

			require.NoError(t, flags.Parse([]string{"--filter-file=/cli/store", "--filter-store-mode=auto", "--filter-store-key-file=/cli/key", "--filter-store-key-id=cli-active", "--filter-store-read-key=cli-old=/cli/with,comma", "--filter-store-read-key=cli-older=/cli/older"}))
			got, err = ReadFilterStoreConfig(flags, config, role, filtering.StoreConfig{})
			require.NoError(t, err)
			require.Equal(t, "/cli/store", got.File)
			require.Equal(t, filtering.StoreAuto, got.Mode)
			require.Equal(t, securestore.KeyRef{ID: "cli-active", File: "/cli/key"}, got.Keys.Active)
			require.Equal(t, []securestore.KeyRef{{ID: "cli-old", File: "/cli/with,comma"}, {ID: "cli-older", File: "/cli/older"}}, got.Keys.Prior)
		})
	}
}

func TestFilterStoreConfigExplicitEmptyClearsLowerPrecedence(t *testing.T) {
	for _, source := range []string{"cli", "environment"} {
		t.Run(source, func(t *testing.T) {
			flags, config := filterStoreTestConfig(t, "tap", `tap:
  filter_file: /yaml/store
  filter_store:
    mode: encrypted
    key_file: /yaml/key
    key_id: yaml-active
    read_keys: [yaml-old=/yaml/old]
`)
			for _, setting := range filterStoreSettings {
				if source == "cli" {
					t.Setenv(filterStoreEnv("tap", setting.key), "nonempty-environment")
					require.NoError(t, flags.Set(setting.flag, ""))
				} else {
					t.Setenv(filterStoreEnv("tap", setting.key), "")
				}
			}
			got, err := ReadFilterStoreConfig(flags, config, "tap", filtering.StoreConfig{})
			require.NoError(t, err)
			require.Equal(t, filtering.StoreAuto, got.Mode)
			require.Empty(t, got.File)
			require.Empty(t, got.Keys.Active)
			require.Empty(t, got.Keys.Prior)
		})
	}
}

func TestFilterStoreConfigExplicitEmptyYAMLClearsConstructorValues(t *testing.T) {
	flags, config := filterStoreTestConfig(t, "tap", `tap:
  filter_file: ""
  filter_store:
    mode: ""
    key_file: ""
    key_id: ""
    read_keys: []
`)
	base := filtering.StoreConfig{File: "/constructor/store", Mode: filtering.StoreEncrypted, Keys: securestore.KeyConfig{
		Active: securestore.KeyRef{ID: "active", File: "/constructor/key"},
		Prior:  []securestore.KeyRef{{ID: "old", File: "/constructor/old"}},
	}}
	got, err := ReadFilterStoreConfig(flags, config, "tap", base)
	require.NoError(t, err)
	require.Equal(t, filtering.StoreAuto, got.Mode)
	require.Empty(t, got.File)
	require.Empty(t, got.Keys.Active)
	require.Empty(t, got.Keys.Prior)
}

func TestFilterStoreConfigRejectsMalformedReferencesWithoutEcho(t *testing.T) {
	const secret = "SENSITIVE_MARKER"
	for name, yaml := range map[string]string{
		"non-list":      "read_keys: " + secret,
		"non-string":    "read_keys: [42]",
		"invalid-id":    "read_keys: ['!=" + secret + "']",
		"empty-path":    "read_keys: ['" + secret + "=']",
		"duplicate":     "read_keys: ['old=/a', 'old=/b']",
		"active-prior":  "key_id: old\n    read_keys: ['old=/a']",
		"too-many":      "read_keys: ['a=/a', 'b=/b', 'c=/c', 'd=/d', 'e=/e']",
		"partial-empty": "read_keys: ['', 'old=/old']",
		"nonstring-key": "key_id: 42",
	} {
		t.Run(name, func(t *testing.T) {
			flags, config := filterStoreTestConfig(t, "tap", "tap:\n  filter_store:\n    "+yaml+"\n")
			_, err := ReadFilterStoreConfig(flags, config, "tap", filtering.StoreConfig{})
			require.Error(t, err)
			require.NotContains(t, err.Error(), secret)
		})
	}
	for _, malformed := range []string{`"` + secret, "old=/a\nother=/b"} {
		flags, config := filterStoreTestConfig(t, "tap", "")
		t.Setenv(filterStoreEnv("tap", "filter_store.read_keys"), malformed)
		_, err := ReadFilterStoreConfig(flags, config, "tap", filtering.StoreConfig{})
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
	}
}
