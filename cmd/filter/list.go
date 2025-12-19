//go:build cli || all
// +build cli all

package filter

import (
	"github.com/endorses/lippycat/internal/pkg/filterclient"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/spf13/cobra"
)

var (
	listHunterID string
)

// ListFiltersCmd lists all filters on a processor
var ListFiltersCmd = &cobra.Command{
	Use:   "filters",
	Short: "List filters on a processor",
	Long: `List all filters configured on a remote processor.

The command connects to the processor via gRPC and retrieves the current
filter configuration. Output is JSON to stdout.

Examples:
  # List all filters
  lc list filters --processor localhost:50051

  # List filters for a specific hunter
  lc list filters --processor localhost:50051 --hunter hunter-1

  # With TLS
  lc list filters --processor processor.example.com:50051 --tls --tls-ca ca.crt`,
	Run: runListFilters,
}

func init() {
	AddConnectionFlags(ListFiltersCmd)
	ListFiltersCmd.Flags().StringVar(&listHunterID, "hunter", "", "Filter by hunter ID")
}

func runListFilters(cmd *cobra.Command, args []string) {
	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	filters, err := client.List(filterclient.ListOptions{
		HunterID: listHunterID,
	})
	if err != nil {
		OutputError(err, MapGRPCError(err))
		return
	}

	// Convert to JSON-friendly format using the filtering package
	jsonBytes, err := filtering.ProtoSliceToJSON(filters)
	if err != nil {
		OutputError(err, ExitGeneralError)
		return
	}

	// Output pretty-printed JSON
	cmd.Println(string(jsonBytes))
}
