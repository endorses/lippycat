//go:build tui || all
// +build tui all

package watch

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// WatchCmd is the base watch command that provides interactive TUI monitoring.
// If no subcommand is specified, it defaults to live mode.
var WatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor traffic (TUI)",
	Long: `Start lippycat with an interactive terminal user interface for monitoring.

Subcommands:
  live    - Live capture from network interface (default)
  file    - Analyze PCAP file
  remote  - Monitor remote hunter/processor nodes

Examples:
  lc watch              # Live capture (default)
  lc watch live -i eth0 # Live capture on eth0
  lc watch file -r capture.pcap
  lc watch remote --nodes-file nodes.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		// Default to live mode if no subcommand is specified
		runLive(cmd, args)
	},
}

// Shared flags across all watch modes
var (
	bufferSize int
)

func init() {
	// Add subcommands
	WatchCmd.AddCommand(liveCmd)
	WatchCmd.AddCommand(fileCmd)
	WatchCmd.AddCommand(remoteCmd)

	// Shared flags (inherited by subcommands)
	WatchCmd.PersistentFlags().IntVar(&bufferSize, "buffer-size", 10000, "maximum number of packets to keep in memory")

	_ = viper.BindPFlag("watch.buffer_size", WatchCmd.PersistentFlags().Lookup("buffer-size"))
}
