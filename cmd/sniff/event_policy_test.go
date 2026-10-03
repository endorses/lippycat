//go:build cli || all

package sniff

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventPolicySniffActiveFlagsAndEarlyValidation(t *testing.T) {
	oldEntries := viper.Get("events.ntp.max_entries")
	t.Cleanup(func() { viper.Set("events.ntp.max_entries", oldEntries); bindSniffEventFlags(SniffCmd) })
	flag := SniffCmd.PersistentFlags().Lookup("ntp-association-timeout")
	oldValue, oldChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(oldValue)); flag.Changed = oldChanged })
	require.NoError(t, SniffCmd.PersistentFlags().Set("ntp-association-timeout", "7s"))
	eventconfig.Register(pflag.NewFlagSet("other-role", pflag.ContinueOnError))
	require.NoError(t, validateLiveCaptureBufferConfig(SniffCmd, nil))
	require.Equal(t, 7*time.Second, eventconfig.FromViper(viper.GetViper()).NTP.Timeout)
	viper.Set("events.ntp.max_entries", 0)
	require.ErrorContains(t, validateLiveCaptureBufferConfig(SniffCmd, nil), "NTP")
}

func TestEventPolicySniffInventorySelectionRequiresLocalPolicy(t *testing.T) {
	for _, key := range []string{"logs.streams", "events.inventory.enabled", "events.inventory.local_cidrs", "events.inventory.retention"} {
		old := viper.Get(key)
		t.Cleanup(func() { viper.Set(key, old) })
	}
	viper.Set("logs.streams", []string{"known_hosts"})
	require.ErrorContains(t, validateSniffAnalysisPolicy(), "inventory")
	viper.Set("events.inventory.enabled", true)
	require.ErrorContains(t, validateSniffAnalysisPolicy(), "local CIDRs")
	viper.Set("events.inventory.local_cidrs", []string{"192.0.2.0/24"})
	require.NoError(t, validateSniffAnalysisPolicy())
	first := structuredLogAnalysisProfile("sniff", "")
	viper.Set("events.inventory.retention", time.Hour)
	require.NotEqual(t, first, structuredLogAnalysisProfile("sniff", ""))
}
