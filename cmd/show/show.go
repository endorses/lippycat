//go:build cli || all
// +build cli all

package show

import (
	"github.com/spf13/cobra"
)

// ShowCmd is the base show command for displaying information and diagnostics.
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display information and diagnostics",
	Long: `Display information and diagnostics for TCP SIP processing and remote resources.

Subcommands:
  health   - Show TCP assembler health status
  metrics  - Display comprehensive TCP metrics
  alerts   - Show active alerts and alert history
  buffers  - Inspect TCP buffer statistics
  streams  - Show TCP stream processing metrics
  config   - Display current configuration
  summary  - Show overall system status summary
  filter   - Show filter details from a remote processor

Examples:
  lc show health           # Show TCP assembler health status
  lc show metrics --json   # Display metrics in JSON format
  lc show alerts           # Show all alerts
  lc show summary          # Show overall system summary
  lc show filter --id myfilter -p localhost:50051  # Show a filter`,
	// No Run function - requires a subcommand
}

func init() {
	// Add subcommands
	ShowCmd.AddCommand(healthCmd)
	ShowCmd.AddCommand(metricsCmd)
	ShowCmd.AddCommand(alertsCmd)
	ShowCmd.AddCommand(buffersCmd)
	ShowCmd.AddCommand(streamsCmd)
	ShowCmd.AddCommand(configCmd)
	ShowCmd.AddCommand(summaryCmd)
}
