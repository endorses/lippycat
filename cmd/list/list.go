//go:build cli || tui || hunter || all

package list

import (
	"github.com/spf13/cobra"
)

// ListCmd is the base list command for listing resources.
var ListCmd = &cobra.Command{
	Use:   "list",
	Short: "List resources",
	Long: `List available resources such as network interfaces and filters.

Subcommands:
  interfaces  - List network interfaces available for monitoring
  filters     - List filters on a remote processor (TLS enabled by default)

Examples:
  lc list interfaces                              # List network interfaces
  lc list filters -P proc:50051 --tls-ca ca.crt   # List filters (TLS)
  lc list filters -P localhost:50051 --insecure   # Local testing`,
	// No Run function - requires a subcommand
}

func init() {
	// Add subcommands
	ListCmd.AddCommand(interfacesCmd)
}
