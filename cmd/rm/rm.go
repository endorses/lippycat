//go:build cli || all

package rm

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/spf13/cobra"
)

// RmCmd is the base rm command for removing resources.
var RmCmd = &cobra.Command{
	Use:   "rm",
	Short: "Remove resources",
	Long: `Remove resources from remote processors.

Subcommands:
  filter  - Remove a filter

Examples:
  lc rm filter --id myfilter
  lc rm filter --file filter-ids.txt`,
	// No Run function - requires a subcommand
}

func init() {
	RmCmd.AddCommand(filter.RmFilterCmd)
}
