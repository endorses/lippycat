//go:build li

package cmdutil

import (
	"os"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func liKeyTestConfig(t *testing.T, role, yaml string) (*pflag.FlagSet, *viper.Viper) {
	t.Helper()
	for _, setting := range liStoreKeySettings {
		name := filterStoreEnv(role, "li."+setting.key)
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
	flags := pflag.NewFlagSet("keys", pflag.ContinueOnError)
	flags.String("li-state-file", "", "")
	flags.String("li-delivery-x2-spool-key-file", "", "")
	flags.String("li-delivery-x3-spool-key-file", "", "")
	config := viper.New()
	require.NoError(t, RegisterLIStoreKeyFlags(flags, config, role))
	config.SetConfigType("yaml")
	require.NoError(t, config.ReadConfig(strings.NewReader(yaml)))
	return flags, config
}

func TestLIStoreKeyPrecedenceAndEmptyValues(t *testing.T) {
	for _, role := range []string{"processor", "tap"} {
		t.Run(role, func(t *testing.T) {
			flags, config := liKeyTestConfig(t, role, role+`:
  li:
    state_file: /yaml/state.enc
    state_key_file: /yaml/state.key
    state_key_id: state-v1
    state_read_keys: [state-v0=/yaml/state-old.key]
    delivery_x2_spool_key_file: /yaml/x2.key
    delivery_x2_spool_key_id: x2-v1
    delivery_x2_spool_legacy_key_id: x2-v0
    delivery_x2_spool_read_keys: [x2-v0=/yaml/x2-old.key]
    delivery_x3_spool_key_file: /yaml/x3.key
    delivery_x3_spool_key_id: x3-v1
    delivery_x3_spool_read_keys: [x3-v0=/yaml/x3-old.key]
`)
			got, err := ReadLIStoreKeys(flags, config, role, LIStoreKeys{})
			require.NoError(t, err)
			require.Equal(t, "/yaml/state.enc", got.StateFile)
			require.Equal(t, securestore.KeyRef{ID: "state-v1", File: "/yaml/state.key"}, got.State.Active)
			require.Equal(t, []securestore.KeyRef{{ID: "x2-v0", File: "/yaml/x2-old.key"}}, got.X2.Prior)
			require.Equal(t, "x2-v0", got.X2.LegacyID)
			require.Equal(t, securestore.KeyRef{ID: "x3-v1", File: "/yaml/x3.key"}, got.X3.Active)
			require.Equal(t, []securestore.KeyRef{{ID: "x3-v0", File: "/yaml/x3-old.key"}}, got.X3.Prior)
			t.Setenv(filterStoreEnv(role, "li.state_file"), "/env/state.enc")
			t.Setenv(filterStoreEnv(role, "li.state_read_keys"), `"older=/env/path,with-comma"`)
			got, err = ReadLIStoreKeys(flags, config, role, LIStoreKeys{})
			require.NoError(t, err)
			require.Equal(t, "/env/state.enc", got.StateFile)
			require.Equal(t, []securestore.KeyRef{{ID: "older", File: "/env/path,with-comma"}}, got.State.Prior)
			require.NoError(t, flags.Parse([]string{"--li-state-file=/cli/state.enc", "--li-state-read-key=old=/cli/old", "--li-state-read-key=older=/cli/older"}))
			got, err = ReadLIStoreKeys(flags, config, role, LIStoreKeys{})
			require.NoError(t, err)
			require.Equal(t, "/cli/state.enc", got.StateFile)
			require.Len(t, got.State.Prior, 2)
			for _, setting := range liStoreKeySettings {
				t.Setenv(filterStoreEnv(role, "li."+setting.key), "")
				flag := flags.Lookup(setting.flag)
				flag.Changed = false
			}
			got, err = ReadLIStoreKeys(flags, config, role, LIStoreKeys{})
			require.NoError(t, err)
			require.Empty(t, got.State.Prior)
			require.Empty(t, got.X2.Prior)
			require.Empty(t, got.X3.Prior)
			got.State.Prior, got.X2.Prior, got.X3.Prior = nil, nil, nil
			require.Equal(t, LIStoreKeys{}, got, "empty environment must clear YAML values")
			for _, setting := range liStoreKeySettings {
				t.Setenv(filterStoreEnv(role, "li."+setting.key), "invalid-sensitive-reference")
				if setting.prior {
					require.NoError(t, flags.Lookup(setting.flag).Value.(pflag.SliceValue).Replace([]string{""}))
					flags.Lookup(setting.flag).Changed = true
				} else {
					require.NoError(t, flags.Set(setting.flag, ""))
				}
			}
			got, err = ReadLIStoreKeys(flags, config, role, LIStoreKeys{})
			require.NoError(t, err)
			require.Empty(t, got.State.Prior)
			require.Empty(t, got.X2.Prior)
			require.Empty(t, got.X3.Prior)
			got.State.Prior, got.X2.Prior, got.X3.Prior = nil, nil, nil
			require.Equal(t, LIStoreKeys{}, got, "empty CLI must clear environment values")
		})
	}
}

func TestLIStoreKeysMalformedAndDuplicateReferences(t *testing.T) {
	for _, fields := range []string{
		"state_read_keys: [invalid-sensitive-reference]",
		"state_read_keys: [1]",
		"state_read_keys: [same=/one, same=/two]",
		"state_key_id: active\n    state_read_keys: [active=/duplicate]",
		"delivery_x2_spool_read_keys: [same=/one, same=/two]",
		"delivery_x2_spool_key_id: active\n    delivery_x2_spool_read_keys: [active=/duplicate]",
		"delivery_x3_spool_read_keys: [same=/one, same=/two]",
		"delivery_x3_spool_key_id: active\n    delivery_x3_spool_read_keys: [active=/duplicate]",
		"delivery_x3_spool_key_id: null",
		"delivery_x3_spool_read_keys: null",
		"state_key_file: [wrong-type]",
		"state_read_keys: [a=/a, b=/b, c=/c, d=/d, e=/e]",
	} {
		t.Run(fields, func(t *testing.T) {
			flags, config := liKeyTestConfig(t, "processor", "processor:\n  li:\n    "+fields+"\n")
			_, err := ReadLIStoreKeys(flags, config, "processor", LIStoreKeys{})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "invalid-sensitive-reference")
		})
	}
}

func TestLIStoreKeysPreserveKeyFileOnlyCompatibility(t *testing.T) {
	flags, config := liKeyTestConfig(t, "processor", "{}")
	base := LIStoreKeys{X2: securestore.KeyConfig{Active: securestore.KeyRef{File: "/legacy/raw-key"}}}
	got, err := ReadLIStoreKeys(flags, config, "processor", base)
	require.NoError(t, err)
	require.Equal(t, base, got)
}
