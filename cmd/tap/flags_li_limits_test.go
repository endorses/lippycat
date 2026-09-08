//go:build (tap || all) && li

package tap

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestLIDeliveryBufferConfigurationPrecedence(t *testing.T) {
	previous := *viper.GetViper()
	t.Cleanup(func() { *viper.GetViper() = previous })
	viper.Reset()
	command := &cobra.Command{Use: "limits"}
	RegisterLIFlags(command)
	BindLIViperFlags(command)
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("tap:\n  li:\n    delivery_x2_queue_bytes: 1024\n    delivery_x3_max_age: 5m\n")))
	config := GetLIConfig()
	require.EqualValues(t, 1024, config.DeliveryX2QueueBytes)
	require.Equal(t, 5*time.Minute, config.DeliveryX3MaxAge)
	t.Setenv("LIPPYCAT_TAP_LI_DELIVERY_X2_QUEUE_BYTES", "2048")
	require.EqualValues(t, 2048, GetLIConfig().DeliveryX2QueueBytes)
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-x2-queue-bytes=4096", "--li-delivery-x3-max-age=0", "--li-delivery-x2-queue-size=123", "--li-delivery-x3-queue-size=456", "--li-delivery-x2-spool-replay-manifest=/secure/approved.json", "--li-delivery-x2-spool-export-manifest=/secure/held.json"}))
	require.EqualValues(t, 4096, GetLIConfig().DeliveryX2QueueBytes)
	require.Zero(t, GetLIConfig().DeliveryX3MaxAge)
	require.Equal(t, 123, GetLIConfig().DeliveryX2QueueSize)
	require.Equal(t, 456, GetLIConfig().DeliveryX3QueueSize)
	require.Equal(t, "/secure/approved.json", GetLIConfig().DeliveryX2SpoolReplayManifest)
	require.Equal(t, "/secure/held.json", GetLIConfig().DeliveryX2SpoolExportManifest)
}
