package capture

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestIPv4DefragConfigDefaultsAndValidation(t *testing.T) {
	config, err := (IPv4DefragConfig{}).Resolve()
	require.NoError(t, err)
	require.Equal(t, 4096, config.MaxDatagrams)
	require.Equal(t, 16384, config.MaxFragments)
	require.Equal(t, 16<<20, config.MaxPayloadBytes)
	require.Equal(t, 128, config.MaxFragmentsPerDatagram)
	require.Equal(t, 30*time.Second, config.StaleAge)
	require.Equal(t, 5*time.Second, config.SweepInterval)
	for _, bad := range []IPv4DefragConfig{
		{MaxDatagrams: -1}, {MaxFragments: -1}, {MaxPayloadBytes: -1},
		{MaxFragmentsPerDatagram: -1}, {StaleAge: -1}, {SweepInterval: -1},
		{MaxDatagrams: 10, MaxFragments: 5}, {MaxFragmentsPerDatagram: IPv4MaximumFragmentListLen + 1},
	} {
		_, err := bad.Resolve()
		require.Error(t, err, "%+v", bad)
	}
}

func TestIPv4DefragConfigFromViper(t *testing.T) {
	for _, key := range []string{"max_datagrams", "max_fragments", "max_payload_bytes", "max_fragments_per_datagram", "stale_age", "sweep_interval"} {
		full := "ipv4_defrag." + key
		original := viper.Get(full)
		t.Cleanup(func() { viper.Set(full, original) })
		viper.Set(full, nil)
	}
	viper.Set("ipv4_defrag.max_datagrams", 4)
	viper.Set("ipv4_defrag.max_fragments", 8)
	viper.Set("ipv4_defrag.max_payload_bytes", 1024)
	viper.Set("ipv4_defrag.max_fragments_per_datagram", 2)
	viper.Set("ipv4_defrag.stale_age", "45s")
	viper.Set("ipv4_defrag.sweep_interval", "2s")
	config, err := IPv4DefragConfigFromViper()
	require.NoError(t, err)
	require.Equal(t, 4, config.MaxDatagrams)
	require.Equal(t, 45*time.Second, config.StaleAge)
	viper.Set("ipv4_defrag.sweep_interval", "bad")
	_, err = IPv4DefragConfigFromViper()
	require.ErrorContains(t, err, "ipv4_defrag.sweep_interval")
	viper.Set("ipv4_defrag.sweep_interval", nil)
	viper.Set("ipv4_defrag.max_datagrams", "not-an-integer")
	_, err = IPv4DefragConfigFromViper()
	require.ErrorContains(t, err, "ipv4_defrag.max_datagrams")
}

func TestIPv4DefragConfigNullAndEmptyEnvironment(t *testing.T) {
	key := "ipv4_defrag.max_datagrams"
	original := viper.Get(key)
	t.Cleanup(func() { viper.Set(key, original) })
	viper.Set(key, nil)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("ipv4_defrag:\n  max_datagrams: null\n")))
	t.Cleanup(func() { require.NoError(t, viper.ReadConfig(strings.NewReader("{}"))) })
	config, err := IPv4DefragConfigFromViper()
	require.NoError(t, err)
	require.Equal(t, 4096, config.MaxDatagrams) // Viper discards an authored YAML null.
	t.Setenv("LIPPYCAT_IPV4_DEFRAG_MAX_DATAGRAMS", "")
	_, err = IPv4DefragConfigFromViper()
	require.ErrorContains(t, err, "must not be empty")
}

func TestIPv4DefragConfigEnvironmentOverridesViper(t *testing.T) {
	key := "ipv4_defrag.max_datagrams"
	original := viper.Get(key)
	t.Cleanup(func() { viper.Set(key, original) })
	viper.Set(key, 100)
	t.Setenv("LIPPYCAT_IPV4_DEFRAG_MAX_DATAGRAMS", "2048")

	config, err := IPv4DefragConfigFromViper()
	require.NoError(t, err)
	require.Equal(t, 2048, config.MaxDatagrams)

	t.Setenv("LIPPYCAT_IPV4_DEFRAG_MAX_DATAGRAMS", "invalid")
	_, err = IPv4DefragConfigFromViper()
	require.ErrorContains(t, err, key)
}
