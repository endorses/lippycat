//go:build cli || all

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

TLS is enabled by default for remote commands. Use --insecure for local testing.

Examples:
  lc show status -P proc:55555 --tls-ca ca.crt   # Show processor status
  lc show hunters -P proc:55555 --tls-ca ca.crt  # List connected hunters
  lc show topology -P proc:55555 --tls-ca ca.crt # Show full topology
  lc show filter --id myfilter -P proc:55555 --tls-ca ca.crt
  lc show status -P localhost:55555 --insecure   # Local testing
  lc show config                                 # Show local config`,
	// No Run function - requires a subcommand
}

func init() {
	// Add subcommands
	// Note: filter is added via filter.go init()
	// Note: status, hunters, topology are added via their respective files
	ShowCmd.AddCommand(configCmd)
}
