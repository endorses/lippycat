//go:build cli || all

package show

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var (
	showHunterID string
)

var hunterCmd = &cobra.Command{
	Use:   "hunter",
	Short: "Show hunter details",
	Long: `Show details of a single connected hunter by ID.

Connects to a processor via gRPC and retrieves information about the specified
hunter including capture statistics, interfaces, and capabilities.
Output is JSON to stdout.

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Show a specific hunter (TLS with CA verification)
  lc show hunter --id edge-01 -P processor.example.com:55555 --tls-ca ca.crt

  # Local testing without TLS
  lc show hunter --id edge-01 -P localhost:55555 --insecure`,
	Run: runShowHunter,
}

func init() {
	filter.AddConnectionFlags(hunterCmd)
	hunterCmd.Flags().StringVar(&showHunterID, "id", "", "Hunter ID to show (required)")
	_ = hunterCmd.MarkFlagRequired("id")
	ShowCmd.AddCommand(hunterCmd)
}

func runShowHunter(cmd *cobra.Command, args []string) {
	client, err := newStatusClient()
	if err != nil {
		filter.OutputError(err, filter.ExitConnectionError)
		return
	}
	defer client.Close()

	hunters, err := client.GetHunters(showHunterID)
	if err != nil {
		filter.OutputError(err, filter.MapGRPCError(err))
		return
	}

	if len(hunters) == 0 {
		filter.OutputError(
			&notFoundError{resource: "hunter", id: showHunterID},
			filter.ExitNotFoundError,
		)
		return
	}

	pretty := output.IsTTY()
	jsonBytes, err := statusclient.HunterToJSON(hunters[0], pretty)
	if err != nil {
		filter.OutputError(err, filter.ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}

type notFoundError struct {
	resource string
	id       string
}

func (e *notFoundError) Error() string {
	return e.resource + " not found: " + e.id
}
