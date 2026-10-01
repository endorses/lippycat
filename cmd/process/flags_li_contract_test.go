//go:build (processor || all) && li

package process

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLICompleteTaskContractConfiguration(t *testing.T) {
	previousFlags, previousContract := liStoreKeyFlags, liADMFCompleteTaskContract
	previous := *viper.GetViper()
	t.Cleanup(func() {
		liStoreKeyFlags, liADMFCompleteTaskContract = previousFlags, previousContract
		*viper.GetViper() = previous
	})
	viper.Reset()
	command := &cobra.Command{Use: "contract"}
	RegisterLIFlags(command)
	BindLIViperFlags(command)
	require.False(t, GetLIConfig().ADMFCompleteTaskContract, "compatibility is the default")
	viper.SetConfigType("yaml")
	require.NoError(t, viper.ReadConfig(strings.NewReader("processor:\n  li:\n    admf_complete_task_contract: true\n")))
	require.True(t, GetLIConfig().ADMFCompleteTaskContract)
	t.Setenv("LIPPYCAT_PROCESSOR_LI_ADMF_COMPLETE_TASK_CONTRACT", "false")
	require.False(t, GetLIConfig().ADMFCompleteTaskContract, "environment overrides configuration")
	require.NoError(t, command.ParseFlags([]string{"--li-admf-complete-task-contract=true"}))
	require.True(t, GetLIConfig().ADMFCompleteTaskContract, "explicit flags override environment")
	require.NoError(t, command.ParseFlags([]string{"--li-admf-complete-task-contract=false"}))
	require.False(t, GetLIConfig().ADMFCompleteTaskContract, "explicit false retains compatibility")
}
