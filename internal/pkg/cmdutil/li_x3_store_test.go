//go:build li

package cmdutil

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func x3SettingsTestConfig(t *testing.T, role, yaml string) (*pflag.FlagSet, *viper.Viper) {
	t.Helper()
	flags := pflag.NewFlagSet("x3", pflag.ContinueOnError)
	for _, suffix := range []string{"spool-dir", "spool-replay-manifest", "spool-export-manifest"} {
		flags.String("li-delivery-x3-"+suffix, "", "")
	}
	flags.String("li-delivery-x3-spool-replay-policy", "hold", "")
	flags.Int64("li-delivery-x3-spool-max-bytes", 0, "")
	flags.Duration("li-delivery-x3-max-age", 0, "")
	for _, suffix := range []string{"spool-dir", "spool-replay-policy", "spool-max-bytes", "spool-replay-manifest", "spool-export-manifest", "max-age"} {
		env := filterStoreEnv(role, "li.delivery_x3_"+replaceConfigSeparators(suffix))
		t.Setenv(env, "")
		require.NoError(t, os.Unsetenv(env))
	}
	config := viper.New()
	config.SetConfigType("yaml")
	require.NoError(t, config.ReadConfig(strings.NewReader(yaml)))
	return flags, config
}

func TestLIX3StoreSettingPrecedence(t *testing.T) {
	for _, role := range []string{"processor", "tap"} {
		t.Run(role, func(t *testing.T) {
			flags, config := x3SettingsTestConfig(t, role, role+`:
  li:
    delivery_x3_spool_dir: /yaml/store
    delivery_x3_spool_max_bytes: 134217728
    delivery_x3_max_age: 60s
    delivery_x3_spool_replay_manifest: /yaml/approve
    delivery_x3_spool_export_manifest: /yaml/export
`)
			got, err := ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{})
			require.NoError(t, err)
			require.Equal(t, LIX3StoreSettings{Dir: "/yaml/store", MaxBytes: 128 << 20, MaxAge: time.Minute, ReplayManifest: "/yaml/approve", ExportManifest: "/yaml/export"}, got)
			t.Setenv(filterStoreEnv(role, "li.delivery_x3_spool_dir"), "")
			t.Setenv(filterStoreEnv(role, "li.delivery_x3_spool_max_bytes"), "0")
			t.Setenv(filterStoreEnv(role, "li.delivery_x3_max_age"), "0")
			got, err = ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{})
			require.NoError(t, err)
			require.Empty(t, got.Dir)
			require.Zero(t, got.MaxBytes)
			require.Zero(t, got.MaxAge)
			require.NoError(t, flags.Parse([]string{"--li-delivery-x3-spool-dir=/cli/store", "--li-delivery-x3-spool-max-bytes=268435456", "--li-delivery-x3-max-age=2m", "--li-delivery-x3-spool-replay-manifest=", "--li-delivery-x3-spool-export-manifest="}))
			got, err = ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{})
			require.NoError(t, err)
			require.Equal(t, LIX3StoreSettings{Dir: "/cli/store", MaxBytes: 256 << 20, MaxAge: 2 * time.Minute}, got)
		})
	}
}

func TestLIX3StoreSettingsRejectMalformedBeforeRuntime(t *testing.T) {
	for _, field := range []string{
		"delivery_x3_spool_replay_policy: null", "delivery_x3_spool_replay_policy: invalid", "delivery_x3_spool_replay_policy: false",
		"delivery_x3_spool_dir: null", "delivery_x3_spool_dir: [secret-reference]",
		"delivery_x3_spool_max_bytes: 1.5", "delivery_x3_spool_max_bytes: true",
		"delivery_x3_spool_max_bytes: -1", "delivery_x3_spool_max_bytes: 9223372036854775808",
		"delivery_x3_max_age: null", "delivery_x3_max_age: 1", "delivery_x3_max_age: -1s",
		"delivery_x3_spool_replay_manifest: false", "delivery_x3_spool_export_manifest: [secret-reference]",
	} {
		t.Run(field, func(t *testing.T) {
			flags, config := x3SettingsTestConfig(t, "processor", "processor:\n  li:\n    "+field+"\n")
			_, err := ReadLIX3StoreSettings(flags, config, "processor", LIX3StoreSettings{})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret-reference")
		})
	}
	flags, config := x3SettingsTestConfig(t, "processor", "{}")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_DELIVERY_X3_SPOOL_MAX_BYTES", "")
	_, err := ReadLIX3StoreSettings(flags, config, "processor", LIX3StoreSettings{MaxBytes: 128 << 20})
	require.Error(t, err, "explicit empty numeric environment must not fall back")
}

func TestLIX3ReplayPolicyPrecedence(t *testing.T) {
	for _, role := range []string{"processor", "tap"} {
		t.Run(role, func(t *testing.T) {
			flags, config := x3SettingsTestConfig(t, role, role+":\n  li:\n    delivery_x3_spool_replay_policy: purge\n")
			got, err := ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{ReplayPolicy: "hold"})
			require.NoError(t, err)
			require.Equal(t, "purge", got.ReplayPolicy)
			t.Setenv(filterStoreEnv(role, "li.delivery_x3_spool_replay_policy"), "hold")
			got, err = ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{})
			require.NoError(t, err)
			require.Equal(t, "hold", got.ReplayPolicy)
			require.NoError(t, flags.Parse([]string{"--li-delivery-x3-spool-replay-policy=purge"}))
			got, err = ReadLIX3StoreSettings(flags, config, role, LIX3StoreSettings{})
			require.NoError(t, err)
			require.Equal(t, "purge", got.ReplayPolicy)
		})
	}
	flags, config := x3SettingsTestConfig(t, "processor", "{}")
	t.Setenv("LIPPYCAT_PROCESSOR_LI_DELIVERY_X3_SPOOL_REPLAY_POLICY", "")
	_, err := ReadLIX3StoreSettings(flags, config, "processor", LIX3StoreSettings{ReplayPolicy: "hold"})
	require.Error(t, err, "explicit empty policy must not silently select hold")
}
