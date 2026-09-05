//go:build tui || all

package tui

import (
	"testing"

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
	originalSIP := *voip.GetConfig()
	t.Cleanup(func() { voip.SetConfig(&originalSIP) })
	msg := FreezeOfflineOpen(inputs, "udp", 17)
	inputs[0] = "changed.pcap"
	viper.Set("watch.tls_keylog", "changed.keys")
	changedSIP := originalSIP
	changedSIP.MaxStreams++
	voip.SetConfig(&changedSIP)
	require.Equal(t, []string{"first.pcap", "second.pcap"}, msg.Config.Inputs)
	require.Equal(t, msg.Config.Inputs, msg.Config.Analysis.SourceOrdering)
	require.Equal(t, "first.keys", msg.Config.TLSKeylog)
	require.Equal(t, originalSIP, msg.Config.SIPConfig)
	require.Equal(t, uint64(32<<20), msg.Limits.CacheBytes)
	require.Equal(t, uint64(4<<30), msg.Limits.DiskBytes)
	require.NoError(t, msg.Limits.Validate())
}

func TestFreezeOfflineOpenPreservesInvalidExplicitLimits(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("watch.offline.max_disk_bytes", 0)
	msg := FreezeOfflineOpen([]string{"input.pcap"}, "", 10)
	require.Error(t, msg.Limits.Validate(), "explicit zero must fail instead of silently restoring the default")
}
