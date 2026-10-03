//go:build tui || all

package tui

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyFrozenForOfflineAndLive(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("events.inventory.enabled", true)
	viper.Set("events.inventory.local_cidrs", []string{"192.0.2.0/24"})
	viper.Set("events.ntp.timeout", 4*time.Second)
	first := FreezeOfflineOpen([]string{"capture.pcap"}, "udp", 10)
	live := localCaptureEventOptions("udp")
	viper.Set("events.inventory.local_cidrs", []string{"198.51.100.0/24"})
	viper.Set("events.ntp.timeout", 8*time.Second)
	second := FreezeOfflineOpen([]string{"capture.pcap"}, "udp", 10)
	require.Equal(t, []string{"192.0.2.0/24"}, first.Config.Analysis.Policy.Inventory.LocalCIDRs)
	require.Equal(t, 4*time.Second, live.Policy.NTP.Timeout)
	require.NotEqual(t, first.Config.Analysis.AnalysisProfile, second.Config.Analysis.AnalysisProfile)
	firstOptions, err := resolveLocalEventOptions(first.Config.Analysis)
	require.NoError(t, err)
	secondOptions, err := resolveLocalEventOptions(second.Config.Analysis)
	require.NoError(t, err)
	firstProducer, err := events.NewOfflineProducer("watch-local", events.OfflineSession{InputIdentity: "same-input", AnalysisProfile: firstOptions.AnalysisProfile})
	require.NoError(t, err)
	secondProducer, err := events.NewOfflineProducer("watch-local", events.OfflineSession{InputIdentity: "same-input", AnalysisProfile: secondOptions.AnalysisProfile})
	require.NoError(t, err)
	require.NotEqual(t, firstProducer.SessionID(), secondProducer.SessionID())
	firstOptions.Policy.Inventory.LocalCIDRs[0] = "203.0.113.0/24"
	require.Equal(t, "192.0.2.0/24", first.Config.Analysis.Policy.Inventory.LocalCIDRs[0])
}

func TestEventPolicyWorkerDefaultsIgnoreViper(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("events.inventory.enabled", true)
	viper.Set("events.ntp.max_entries", 0)
	options, err := resolveLocalEventOptions(selectLocalEventOptions("", nil))
	require.NoError(t, err)
	require.False(t, options.Policy.Inventory.Enabled)
	require.Equal(t, eventconfig.Default().NTP.MaxEntries, options.Policy.NTP.MaxEntries)
	policy := eventconfig.Default()
	policy.NTP.MaxEntries = 0
	_, err = resolveLocalEventOptions(LocalEventAnalysisOptions{Policy: &policy})
	require.Error(t, err)
}

func TestEventPolicyInvalidOfflineRejectedBeforeInputOpen(t *testing.T) {
	policy := eventconfig.Default()
	policy.Inventory.Enabled = true
	_, err := indexOfflineDataset(context.Background(), nil, 1, OfflineAnalysisConfig{Inputs: []string{"missing.pcap"}, Analysis: LocalEventAnalysisOptions{Policy: &policy}}, nil)
	require.ErrorContains(t, err, "local CIDRs")
}
