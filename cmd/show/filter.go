//go:build cli || all

package show

import (
	"github.com/endorses/lippycat/cmd/filter"
)

func init() {
	// Add filter subcommand to show
	ShowCmd.AddCommand(filter.ShowFilterCmd)
}
