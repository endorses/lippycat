//go:build hunter || all

package hunt

import (
	"context"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestHuntTCPMaxStreamsConfig(t *testing.T) {
	flag := voipHuntCmd.Flags().Lookup("tcp-max-streams")
	require.NotNil(t, flag)
	require.Equal(t, "0", flag.DefValue)
	require.Contains(t, flag.Usage, "reject new streams")
	originalValue, originalChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(originalValue))
		flag.Changed = originalChanged
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	})
	require.NoError(t, flag.Value.Set("0"))
	flag.Changed = false
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	initial := *voip.GetConfig()
	config, err := huntSIPStreamConfig(voipHuntCmd)
	require.NoError(t, err)
	require.Zero(t, config.MaxStreams)

	require.NoError(t, viper.ReadConfig(strings.NewReader("voip:\n  max_streams: 23\n")))
	config, err = huntSIPStreamConfig(voipHuntCmd)
	require.NoError(t, err)
	require.Equal(t, 23, config.MaxStreams)
	require.Equal(t, initial.MaxStreams, voip.GetConfig().MaxStreams)

	require.NoError(t, flag.Value.Set("7"))
	flag.Changed = true
	config, err = huntSIPStreamConfig(voipHuntCmd)
	require.NoError(t, err)
	require.Equal(t, 7, config.MaxStreams)

	require.NoError(t, flag.Value.Set("0"))
	config, err = huntSIPStreamConfig(voipHuntCmd)
	require.NoError(t, err)
	require.Zero(t, config.MaxStreams, "an explicit zero overrides the config file")

	require.NoError(t, flag.Value.Set("-1"))
	_, err = huntSIPStreamConfig(voipHuntCmd)
	require.ErrorContains(t, err, "--tcp-max-streams")
	require.ErrorContains(t, err, "reject new TCP SIP streams")
	require.ErrorContains(t, runVoIPHunt(voipHuntCmd, nil), "--tcp-max-streams")

	flag.Changed = false
	require.NoError(t, viper.ReadConfig(strings.NewReader("voip:\n  max_streams: -2\n")))
	_, err = huntSIPStreamConfig(voipHuntCmd)
	require.ErrorContains(t, err, "voip.max_streams")
}

func TestHuntResolvedTCPMaxStreamsLimitsFactory(t *testing.T) {
	flag := voipHuntCmd.Flags().Lookup("tcp-max-streams")
	originalValue, originalChanged := flag.Value.String(), flag.Changed
	t.Cleanup(func() {
		require.NoError(t, flag.Value.Set(originalValue))
		flag.Changed = originalChanged
		require.NoError(t, viper.ReadConfig(strings.NewReader("{}")))
	})
	require.NoError(t, flag.Value.Set("1"))
	flag.Changed = true
	config, err := huntSIPStreamConfig(voipHuntCmd)
	require.NoError(t, err)
	tracker := voip.NewCallTracker()
	defer tracker.Shutdown()
	factory := voip.NewSipStreamFactoryWithConfig(context.Background(), voip.NewLocalFileHandler(tracker), config, nil)
	defer func() { require.NoError(t, factory.Shutdown()) }()
	active := factory.(interface{ GetActiveGoroutines() int64 })
	factory.New(gopacket.Flow{}, gopacket.Flow{}, &layers.TCP{}, nil)
	factory.New(gopacket.Flow{}, gopacket.Flow{}, &layers.TCP{}, nil)
	require.EqualValues(t, 1, active.GetActiveGoroutines())
}
