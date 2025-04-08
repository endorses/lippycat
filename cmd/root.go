package cmd

import (
	"os"

	"github.com/endorses/lippycat/cmd/sniff"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lippycat",
	Short: "lippycat sniffs for you",
	Long:  `lippycat sniffs traffic for you, including voip traffic.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubCommandPalattes() {
	rootCmd.AddCommand(sniff.SniffCmd)
}

func init() {
	addSubCommandPalattes()
}
