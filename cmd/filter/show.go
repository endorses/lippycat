//go:build cli || all
// +build cli all

package filter

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/filterclient"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/spf13/cobra"
)

var (
	showFilterID string
)

// ShowFilterCmd shows details of a single filter
var ShowFilterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Show filter details",
	Long: `Show details of a single filter by ID.

The command connects to the processor via gRPC and retrieves the filter
with the specified ID. Output is JSON to stdout.

Examples:
  # Show a filter by ID
  lc show filter --id myfilter --processor localhost:50051

  # With TLS
  lc show filter --id myfilter --processor processor.example.com:50051 --tls --tls-ca ca.crt`,
	Run: runShowFilter,
}

func init() {
	AddConnectionFlags(ShowFilterCmd)
	ShowFilterCmd.Flags().StringVar(&showFilterID, "id", "", "Filter ID to show (required)")
	_ = ShowFilterCmd.MarkFlagRequired("id")
}

func runShowFilter(cmd *cobra.Command, args []string) {
	if showFilterID == "" {
		OutputError(fmt.Errorf("filter ID is required"), ExitValidationError)
		return
	}

	client, err := NewClient()
	if err != nil {
		OutputError(err, ExitConnectionError)
		return
	}
	defer client.Close()

	filter, err := client.Get(showFilterID)
	if err != nil {
		if filterclient.IsNotFound(err) {
			OutputError(err, ExitNotFoundError)
			return
		}
		OutputError(err, MapGRPCError(err))
		return
	}

	// Convert to JSON-friendly format
	jsonBytes, err := filtering.ProtoToJSON(filter)
	if err != nil {
		OutputError(err, ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}
