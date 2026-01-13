//go:build cli || all

package show

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display current configuration",
	Long:  `Show the current application configuration from config file and defaults. Output is JSON.`,
	Run: func(cmd *cobra.Command, args []string) {
		data, err := output.MarshalJSON(viper.AllSettings())
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Println(string(data))
	},
}
