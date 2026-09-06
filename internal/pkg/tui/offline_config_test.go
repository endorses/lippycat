//go:build tui || all

package tui

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestFreezeOfflineOpenOwnsConfiguration(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	inputs := []string{"first.pcap", "second.pcap"}
	viper.Set("watch.offline.cache_bytes", uint64(32<<20))
	viper.Set("watch.tls_decryption_enabled", true)
	viper.Set("watch.tls_keylog", "first.keys")
	viper.Set("watch.offline.backing_policy", "snapshot")
	originalSIP := *voip.GetConfig()
	t.Cleanup(func() { voip.SetConfig(&originalSIP) })
	msg := FreezeOfflineOpen(inputs, "udp", 17)
	inputs[0] = "changed.pcap"
	viper.Set("watch.tls_keylog", "changed.keys")
	viper.Set("watch.offline.backing_policy", "source")
	changedSIP := originalSIP
	changedSIP.MaxStreams++
	voip.SetConfig(&changedSIP)
	require.Equal(t, []string{"first.pcap", "second.pcap"}, msg.Config.Inputs)
	require.Equal(t, msg.Config.Inputs, msg.Config.Analysis.SourceOrdering)
	require.Equal(t, "first.keys", msg.Config.TLSKeylog)
	require.Equal(t, offline.BackingSnapshot, msg.Config.BackingPolicy)
	require.Equal(t, originalSIP, msg.Config.SIPConfig)
	require.Equal(t, uint64(32<<20), msg.Limits.CacheBytes)
	require.Equal(t, uint64(4<<30), msg.Limits.DiskBytes)
	require.NoError(t, msg.Limits.Validate())
}

func TestOfflineBackingPolicyValidatedBeforeOpening(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	msg := FreezeOfflineOpen([]string{"nonexistent.pcap"}, "", 10)
	require.Equal(t, offline.BackingSource, msg.Config.BackingPolicy)
	viper.Set("watch.offline.backing_policy", "invalid")
	msg = FreezeOfflineOpen(msg.Config.Inputs, "", 10)
	// A nil storage is safe here: invalid policy must fail before building or opening input.
	session, err := indexOfflineDataset(context.Background(), nil, 1, msg.Config, nil)
	require.Nil(t, session)
	require.ErrorContains(t, err, "backing policy")
}

func TestFreezeOfflineOpenPreservesInvalidExplicitLimits(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("watch.offline.max_disk_bytes", 0)
	msg := FreezeOfflineOpen([]string{"input.pcap"}, "", 10)
	require.Error(t, msg.Limits.Validate(), "explicit zero must fail instead of silently restoring the default")
}
