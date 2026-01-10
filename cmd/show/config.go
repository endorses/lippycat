//go:build cli || all
// +build cli all

package show

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display current configuration",
	Long:  `Show the current VoIP configuration including performance mode, thresholds, and optimization settings. Output is JSON.`,
	Run: func(cmd *cobra.Command, args []string) {
		config := voip.GetConfig()
		data, err := output.MarshalJSON(config)
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Println(string(data))
	},
}
