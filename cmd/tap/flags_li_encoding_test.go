//go:build all && li

package tap

import (
	"strings"
	"testing"

	othercmd "github.com/endorses/lippycat/cmd/process"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func encodingSettingsCommand(t *testing.T) *cobra.Command {
	t.Helper()
	previousTimestamp, previousTarget := liDeliveryTimestampFormat, liDeliveryMatchedTargetFormat
	t.Cleanup(func() { liDeliveryTimestampFormat, liDeliveryMatchedTargetFormat = previousTimestamp, previousTarget })
	t.Setenv("LIPPYCAT_LI_DELIVERY_TIMESTAMP_FORMAT", "")
	t.Setenv("LIPPYCAT_LI_DELIVERY_MATCHED_TARGET_FORMAT", "")
	return selectionSettingsCommand(t)
}

func TestLIDeliveryEncodingConfigurationPrecedence(t *testing.T) {
	command := encodingSettingsCommand(t)
	require.Equal(t, "legacy-12", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "bare", GetLIConfig().DeliveryMatchedTargetFormat)
	require.Equal(t, "legacy-12", command.PersistentFlags().Lookup("li-delivery-timestamp-format").DefValue)
	require.Equal(t, "bare", command.PersistentFlags().Lookup("li-delivery-matched-target-format").DefValue)

	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  delivery:\n    timestamp_format: etsi-8\n    matched_target_format: target-identifier\n")))
	require.Equal(t, "etsi-8", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "target-identifier", GetLIConfig().DeliveryMatchedTargetFormat)
	t.Setenv("LIPPYCAT_LI_DELIVERY_TIMESTAMP_FORMAT", "legacy-12")
	t.Setenv("LIPPYCAT_LI_DELIVERY_MATCHED_TARGET_FORMAT", "bare")
	require.Equal(t, "legacy-12", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "bare", GetLIConfig().DeliveryMatchedTargetFormat)
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=etsi-8", "--li-delivery-matched-target-format=target-identifier"}))
	require.Equal(t, "etsi-8", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "target-identifier", GetLIConfig().DeliveryMatchedTargetFormat)

	t.Setenv("LIPPYCAT_LI_DELIVERY_TIMESTAMP_FORMAT", "etsi-8")
	t.Setenv("LIPPYCAT_LI_DELIVERY_MATCHED_TARGET_FORMAT", "target-identifier")
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=legacy-12", "--li-delivery-matched-target-format=bare"}))
	require.Equal(t, "legacy-12", GetLIConfig().DeliveryTimestampFormat, "explicit compatibility output overrides YAML/environment")
	require.Equal(t, "bare", GetLIConfig().DeliveryMatchedTargetFormat)
}

func TestLIDeliveryEncodingSettingsAreIndependent(t *testing.T) {
	command := encodingSettingsCommand(t)
	for _, timestamp := range []string{"legacy-12", "etsi-8"} {
		for _, target := range []string{"bare", "target-identifier"} {
			require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=" + timestamp, "--li-delivery-matched-target-format=" + target}))
			require.Equal(t, timestamp, GetLIConfig().DeliveryTimestampFormat)
			require.Equal(t, target, GetLIConfig().DeliveryMatchedTargetFormat)
		}
	}
	// Resolution must retain unknown values for startup validation rather than
	// silently substituting a default or changing the other encoding setting.
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=unknown", "--li-delivery-matched-target-format=bare"}))
	require.Equal(t, "unknown", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "bare", GetLIConfig().DeliveryMatchedTargetFormat)
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=legacy-12", "--li-delivery-matched-target-format=unknown"}))
	require.Equal(t, "legacy-12", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "unknown", GetLIConfig().DeliveryMatchedTargetFormat)
}

func TestLIDeliveryEncodingIgnoresOtherCommandBindings(t *testing.T) {
	command := encodingSettingsCommand(t)
	foreign := othercmd.ProcessCmd
	for _, name := range []string{"li-delivery-timestamp-format", "li-delivery-matched-target-format"} {
		flag := foreign.Flags().Lookup(name)
		require.NotNil(t, flag)
		before, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() { require.NoError(t, flag.Value.Set(before)); flag.Changed = changed })
	}
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  delivery:\n    timestamp_format: etsi-8\n    matched_target_format: target-identifier\n")))
	require.NoError(t, foreign.ParseFlags([]string{"--li-delivery-timestamp-format=legacy-12", "--li-delivery-matched-target-format=bare"}))
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "etsi-8", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "target-identifier", GetLIConfig().DeliveryMatchedTargetFormat)
	require.NoError(t, command.ParseFlags([]string{"--li-delivery-timestamp-format=legacy-12", "--li-delivery-matched-target-format=bare"}))
	require.NoError(t, foreign.ParseFlags([]string{"--li-delivery-timestamp-format=etsi-8", "--li-delivery-matched-target-format=target-identifier"}))
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "legacy-12", GetLIConfig().DeliveryTimestampFormat)
	require.Equal(t, "bare", GetLIConfig().DeliveryMatchedTargetFormat)
}

func TestLIDeliveryEncodingInheritedByTapProtocol(t *testing.T) {
	parent := encodingSettingsCommand(t)
	child := &cobra.Command{Use: "voip"}
	parent.AddCommand(child)
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  delivery:\n    timestamp_format: etsi-8\n    matched_target_format: target-identifier\n")))
	require.NoError(t, child.ParseFlags([]string{"--li-delivery-timestamp-format=legacy-12", "--li-delivery-matched-target-format=bare"}))
	var config processor.Config
	applyLIDeliveryConfig(&config, GetLIConfig())
	require.Equal(t, "legacy-12", config.LIDeliveryTimestampFormat)
	require.Equal(t, "bare", config.LIDeliveryMatchedTargetFormat)
	require.NoError(t, child.ParseFlags([]string{"--li-delivery-timestamp-format=etsi-8", "--li-delivery-matched-target-format=target-identifier"}))
	applyLIDeliveryConfig(&config, GetLIConfig())
	require.Equal(t, "etsi-8", config.LIDeliveryTimestampFormat)
	require.Equal(t, "target-identifier", config.LIDeliveryMatchedTargetFormat)
}
