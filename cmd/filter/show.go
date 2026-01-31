//go:build cli || all

package filter

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/filterclient"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/output"
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

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Show a filter by ID (TLS with CA verification)
  lc show filter --id myfilter -P processor.example.com:55555 --tls-ca ca.crt

  # Local testing without TLS
  lc show filter --id myfilter -P localhost:55555 --insecure`,
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
	jsonBytes, err := filtering.ProtoToJSON(filter, output.IsTTY())
	if err != nil {
		OutputError(err, ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}
