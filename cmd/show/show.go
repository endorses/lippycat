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
	Long: `Display information and diagnostics for processors and local configuration.

Subcommands:
  status   - Show processor status and statistics (requires -P)
  hunters  - Show connected hunter details (requires -P)
  topology - Show distributed topology (requires -P)
  filter   - Show filter details (requires -P)
  config   - Display local configuration

Examples:
  lc show status -P localhost:50051              # Show processor status
  lc show hunters -P localhost:50051             # List connected hunters
  lc show hunters -P localhost:50051 --hunter h1 # Show specific hunter
  lc show topology -P localhost:50051            # Show full topology
  lc show filter --id myfilter -P localhost:50051
  lc show config                                 # Show local config`,
	// No Run function - requires a subcommand
}

func init() {
	// Add subcommands
	// Note: filter is added via filter.go init()
	// Note: status, hunters, topology are added via their respective files
	ShowCmd.AddCommand(configCmd)
}
