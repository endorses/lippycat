//go:build all && li

package process

import (
	"strings"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	othercmd "github.com/endorses/lippycat/cmd/tap"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// Both commands are imported deliberately: their package initializers bind the
// same root-level LI keys in a full binary, so registration order matters.
func selectionSettingsCommand(t *testing.T) *cobra.Command {
	t.Helper()
	previousViper := *viper.GetViper()
	previousCommand, previousFlags := liSelectionSettingsCommand, liStoreKeyFlags
	previousScope, previousSource := liTaskFilterDistributionScope, liDeliveryCaptureSourceMetadata
	t.Cleanup(func() {
		*viper.GetViper() = previousViper
		liSelectionSettingsCommand, liStoreKeyFlags = previousCommand, previousFlags
		liTaskFilterDistributionScope, liDeliveryCaptureSourceMetadata = previousScope, previousSource
	})
	t.Setenv("LIPPYCAT_LI_TASK_FILTER_DISTRIBUTION_SCOPE", "")
	t.Setenv("LIPPYCAT_LI_DELIVERY_CAPTURE_SOURCE_METADATA", "")
	viper.Reset()
	command := &cobra.Command{Use: "selection-settings"}
	RegisterLIFlags(command)
	BindLIViperFlags(command)
	viper.SetConfigType("yaml")
	return command
}

func TestLISelectionSettingsConfigurationPrecedence(t *testing.T) {
	command := selectionSettingsCommand(t)
	defaults := GetLIConfig()
	scope, err := filtering.ParseDistributionScope(defaults.TaskFilterDistributionScope)
	require.NoError(t, err)
	require.Equal(t, management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_DISTRIBUTED, scope)
	require.False(t, defaults.DeliveryCaptureSourceMetadata)
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  task_filter_distribution_scope: local_only\n  delivery:\n    capture_source_metadata: true\n")))
	require.Equal(t, "local_only", GetLIConfig().TaskFilterDistributionScope)
	require.True(t, GetLIConfig().DeliveryCaptureSourceMetadata)
	t.Setenv("LIPPYCAT_LI_TASK_FILTER_DISTRIBUTION_SCOPE", "distributed")
	t.Setenv("LIPPYCAT_LI_DELIVERY_CAPTURE_SOURCE_METADATA", "false")
	require.Equal(t, "distributed", GetLIConfig().TaskFilterDistributionScope)
	require.False(t, GetLIConfig().DeliveryCaptureSourceMetadata)
	require.NoError(t, command.ParseFlags([]string{"--li-task-filter-distribution-scope=local_only", "--li-delivery-capture-source-metadata=true"}))
	require.Equal(t, "local_only", GetLIConfig().TaskFilterDistributionScope)
	require.True(t, GetLIConfig().DeliveryCaptureSourceMetadata)
	t.Setenv("LIPPYCAT_LI_TASK_FILTER_DISTRIBUTION_SCOPE", "local_only")
	t.Setenv("LIPPYCAT_LI_DELIVERY_CAPTURE_SOURCE_METADATA", "true")
	require.NoError(t, command.ParseFlags([]string{"--li-task-filter-distribution-scope=distributed", "--li-delivery-capture-source-metadata=false"}))
	require.Equal(t, "distributed", GetLIConfig().TaskFilterDistributionScope, "explicit compatibility scope overrides YAML/environment")
	require.False(t, GetLIConfig().DeliveryCaptureSourceMetadata, "explicit false must override true YAML/environment")
}

func TestLISelectionSettingsIgnoreOtherCommandBindings(t *testing.T) {
	command := selectionSettingsCommand(t)
	require.NoError(t, viper.ReadConfig(strings.NewReader("li:\n  task_filter_distribution_scope: local_only\n  delivery:\n    capture_source_metadata: true\n")))
	foreign := othercmd.TapCmd
	for _, name := range []string{"li-task-filter-distribution-scope", "li-delivery-capture-source-metadata"} {
		flag := foreign.PersistentFlags().Lookup(name)
		require.NotNil(t, flag)
		before, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() { require.NoError(t, flag.Value.Set(before)); flag.Changed = changed })
	}
	// In an all build the other command can bind after this command. Its
	// defaults or explicit flags must not replace this command's root settings.
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "local_only", GetLIConfig().TaskFilterDistributionScope)
	require.True(t, GetLIConfig().DeliveryCaptureSourceMetadata)
	require.NoError(t, command.ParseFlags([]string{"--li-task-filter-distribution-scope=distributed", "--li-delivery-capture-source-metadata=false"}))
	require.NoError(t, foreign.ParseFlags([]string{"--li-task-filter-distribution-scope=local_only", "--li-delivery-capture-source-metadata=true"}))
	othercmd.BindLIViperFlags(foreign)
	require.Equal(t, "distributed", GetLIConfig().TaskFilterDistributionScope)
	require.False(t, GetLIConfig().DeliveryCaptureSourceMetadata)
}
