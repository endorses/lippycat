//go:build cli || all
// +build cli all

package list

import (
	"github.com/endorses/lippycat/cmd/filter"
)

func init() {
	// Add filters subcommand to list
	ListCmd.AddCommand(filter.ListFiltersCmd)
}
