//go:build tui || all

package watch

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestEventPolicyWatchValidationAndLiveSnapshot(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	for _, cmd := range []*cobra.Command{WatchCmd, liveCmd, fileCmd, remoteCmd} {
		require.NoError(t, WatchCmd.PersistentPreRunE(cmd, nil))
	}
	viper.Set("events.ntp.timeout", 4*time.Second)
	options := localEventAnalysisOptions("udp")
	viper.Set("events.ntp.timeout", 8*time.Second)
	require.Equal(t, 4*time.Second, options.Policy.NTP.Timeout)
	viper.Set("events.dhcp.max_bytes", 0)
	for _, cmd := range []*cobra.Command{WatchCmd, liveCmd, fileCmd, remoteCmd} {
		require.ErrorContains(t, WatchCmd.PersistentPreRunE(cmd, nil), "DHCP")
	}
}
