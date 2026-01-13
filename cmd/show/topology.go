//go:build cli || all

package show

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var topologyCmd = &cobra.Command{
	Use:   "topology",
	Short: "Show distributed topology",
	Long: `Show the complete distributed topology.

Connects to a processor via gRPC and retrieves the full topology including
downstream processors and their connected hunters. Output is JSON to stdout.

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Show full topology (TLS with CA verification)
  lc show topology -P processor.example.com:50051 --tls-ca ca.crt

  # Local testing without TLS
  lc show topology -P localhost:50051 --insecure`,
	Run: runShowTopology,
}

func init() {
	filter.AddConnectionFlags(topologyCmd)
	ShowCmd.AddCommand(topologyCmd)
}

func runShowTopology(cmd *cobra.Command, args []string) {
	client, err := newStatusClient()
	if err != nil {
		filter.OutputError(err, filter.ExitConnectionError)
		return
	}
	defer client.Close()

	resp, err := client.GetTopology()
	if err != nil {
		filter.OutputError(err, filter.MapGRPCError(err))
		return
	}

	jsonBytes, err := statusclient.TopologyToJSON(resp, output.IsTTY())
	if err != nil {
		filter.OutputError(err, filter.ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}
