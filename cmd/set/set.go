//go:build cli || all

package set

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/spf13/cobra"
)

// SetCmd is the base set command for creating/updating resources.
var SetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create or update resources",
	Long: `Create or update resources on remote processors.

Subcommands:
  filter  - Create or update a filter

Examples:
  lc set filter --id myfilter --type sip_user --pattern alice@example.com
  lc set filter --file filters.yaml`,
	// No Run function - requires a subcommand
}

func init() {
	SetCmd.AddCommand(filter.SetFilterCmd)
}
