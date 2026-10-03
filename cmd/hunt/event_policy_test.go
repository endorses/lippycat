//go:build hunter || all

package hunt

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyHunterConfigSnapshot(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("events.inventory.enabled", true)
	viper.Set("events.inventory.local_cidrs", []string{"192.0.2.0/24"})
	viper.Set("events.ntp.timeout", 3*time.Second)
	config := buildHunterConfig(protocolHunterConfigSpec("generic", ""))
	require.NoError(t, config.EventAnalysis.Validate())
	viper.Set("events.ntp.timeout", 6*time.Second)
	viper.Set("events.inventory.local_cidrs", []string{"198.51.100.0/24"})
	require.Equal(t, 3*time.Second, config.EventAnalysis.NTP.Timeout)
	require.Equal(t, []string{"192.0.2.0/24"}, config.EventAnalysis.Inventory.LocalCIDRs)
}

func TestEventPolicyHunterDefaultAndExplicitOptOut(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	config := buildHunterConfig(protocolHunterConfigSpec("generic", ""))
	require.NoError(t, config.EventAnalysis.Validate())
	require.True(t, config.EventAnalysis.Inventory.Enabled)
	require.Empty(t, config.EventAnalysis.Inventory.LocalCIDRs)
	viper.Set("events.inventory.enabled", false)
	config = buildHunterConfig(protocolHunterConfigSpec("generic", ""))
	require.NoError(t, config.EventAnalysis.Validate())
	require.False(t, config.EventAnalysis.Inventory.Enabled)
}
