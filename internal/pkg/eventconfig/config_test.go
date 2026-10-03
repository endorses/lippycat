package eventconfig

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestDefaultsAndExplicitInvalidValues(t *testing.T) {
	v := viper.New()
	require.NoError(t, FromViper(v).Validate())
	for _, key := range []string{"events.dhcp.max_entries", "events.dhcp.max_bytes", "events.dhcp.timeout", "events.ntp.max_entries", "events.ntp.max_bytes", "events.ntp.timeout", "events.inventory.max_entries", "events.inventory.max_bytes", "events.inventory.max_entries_per_scope", "events.inventory.max_bytes_per_scope", "events.inventory.retention"} {
		for _, value := range []int{0, -1} {
			t.Run(key+string(rune('0'-value)), func(t *testing.T) {
				settings := viper.New()
				settings.Set(key, value)
				require.Error(t, FromViper(settings).Validate())
			})
		}
	}
	v.Set("events.inventory.enabled", true)
	require.ErrorContains(t, FromViper(v).Validate(), "local CIDRs")
	v.Set("events.inventory.local_cidrs", []string{"192.0.2.0/24", "2001:db8::/32"})
	require.NoError(t, FromViper(v).Validate())
	v.Set("events.inventory.local_cidrs", []string{"not-a-prefix"})
	require.ErrorContains(t, FromViper(v).Validate(), "local CIDR")
}

func TestPolicyFingerprintAndOwnership(t *testing.T) {
	a := Default()
	a.Inventory.Enabled = true
	a.Inventory.LocalCIDRs = []string{"192.0.2.44/24", "2001:db8::/32"}
	b := a.Clone()
	b.Inventory.LocalCIDRs = []string{"2001:db8::/32", "::ffff:192.0.2.0/120", "192.0.2.1/24"}
	require.Equal(t, a.Fingerprint(), b.Fingerprint())
	b.Inventory.Retention = time.Hour
	require.NotEqual(t, a.Fingerprint(), b.Fingerprint())
	b = a.Clone()
	b.DHCP.Timeout = time.Second
	require.NotEqual(t, a.Fingerprint(), b.Fingerprint())
	b = a.Clone()
	b.Inventory.LocalCIDRs[0] = "203.0.113.0/24"
	require.Equal(t, "192.0.2.44/24", a.Inventory.LocalCIDRs[0])
}

func TestSharedFlagsBindActiveCommand(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	first := pflag.NewFlagSet("first", pflag.ContinueOnError)
	Register(first)
	second := pflag.NewFlagSet("second", pflag.ContinueOnError)
	Register(second)
	require.NoError(t, first.Parse([]string{"--inventory", "--inventory-local-cidrs=192.0.2.0/24", "--ntp-association-timeout=4s"}))
	Bind(first)
	got := FromViper(viper.GetViper())
	require.True(t, got.Inventory.Enabled)
	require.Equal(t, 4*time.Second, got.NTP.Timeout)
	require.NoError(t, got.Validate())
	require.NoError(t, first.Set("dhcp-association-max-entries", "0"))
	require.Error(t, FromViper(viper.GetViper()).Validate())
}
