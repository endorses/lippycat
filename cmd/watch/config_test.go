//go:build tui || all

package watch

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLiveCommandsRejectInvalidSIPCapacityBeforeRun(t *testing.T) {
	original := viper.Get("sip_buffer_size")
	t.Cleanup(func() { viper.Set("sip_buffer_size", original) })

	for _, command := range []struct {
		name string
		run  func() error
	}{
		{name: "default watch", run: func() error { return WatchCmd.PreRunE(WatchCmd, nil) }},
		{name: "watch live", run: func() error { return liveCmd.PreRunE(liveCmd, nil) }},
	} {
		t.Run(command.name, func(t *testing.T) {
			viper.Set("sip_buffer_size", -1)
			require.ErrorContains(t, command.run(), "sip_buffer_size")

			viper.Set("sip_buffer_size", "not-an-integer")
			require.ErrorContains(t, command.run(), "sip_buffer_size")
		})
	}
}
