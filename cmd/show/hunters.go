//go:build cli || all
// +build cli all

package show

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var (
	huntersHunterID string
)

var huntersCmd = &cobra.Command{
	Use:   "hunters",
	Short: "Show connected hunters",
	Long: `Show connected hunter details and statistics.

Connects to a processor via gRPC and retrieves information about connected
hunters including capture statistics, interfaces, and capabilities.
Output is JSON to stdout.

Examples:
  # List all connected hunters
  lc show hunters -P localhost:50051

  # Show a specific hunter
  lc show hunters -P localhost:50051 --hunter edge-01

  # With TLS
  lc show hunters -P processor.example.com:50051 -T --tls-ca ca.crt`,
	Run: runShowHunters,
}

func init() {
	filter.AddConnectionFlags(huntersCmd)
	huntersCmd.Flags().StringVar(&huntersHunterID, "hunter", "", "Filter by hunter ID")
	ShowCmd.AddCommand(huntersCmd)
}

func runShowHunters(cmd *cobra.Command, args []string) {
	client, err := newStatusClient()
	if err != nil {
		filter.OutputError(err, filter.ExitConnectionError)
		return
	}
	defer client.Close()

	hunters, err := client.GetHunters(huntersHunterID)
	if err != nil {
		filter.OutputError(err, filter.MapGRPCError(err))
		return
	}

	// If a specific hunter was requested but not found
	if huntersHunterID != "" && len(hunters) == 0 {
		filter.OutputError(
			&notFoundError{resource: "hunter", id: huntersHunterID},
			filter.ExitNotFoundError,
		)
		return
	}

	var jsonBytes []byte
	if huntersHunterID != "" && len(hunters) == 1 {
		// Single hunter requested - output as object
		jsonBytes, err = statusclient.HunterToJSON(hunters[0])
	} else {
		// Multiple hunters - output as array
		jsonBytes, err = statusclient.HuntersToJSON(hunters)
	}

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
