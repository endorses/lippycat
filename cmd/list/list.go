//go:build cli || tui || hunter || all
// +build cli tui hunter all

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
  filters     - List filters on a remote processor

Examples:
  lc list interfaces              # List available network interfaces
  lc list filters -p localhost:50051  # List filters on a processor`,
	// No Run function - requires a subcommand
}

func init() {
	// Add subcommands
	ListCmd.AddCommand(interfacesCmd)
}
