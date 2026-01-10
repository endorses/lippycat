//go:build cli || all
// +build cli all

package show

import (
	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show processor status",
	Long: `Show processor status and statistics.

Connects to a processor via gRPC and retrieves current status including
hunter counts, packet statistics, and overall health. Output is JSON to stdout.

Examples:
  # Show processor status
  lc show status -P localhost:50051

  # With TLS
  lc show status -P processor.example.com:50051 -T --tls-ca ca.crt`,
	Run: runShowStatus,
}

func init() {
	filter.AddConnectionFlags(statusCmd)
	ShowCmd.AddCommand(statusCmd)
}

func runShowStatus(cmd *cobra.Command, args []string) {
	client, err := newStatusClient()
	if err != nil {
		filter.OutputError(err, filter.ExitConnectionError)
		return
	}
	defer client.Close()

	resp, err := client.GetStatus()
	if err != nil {
		filter.OutputError(err, filter.MapGRPCError(err))
		return
	}

	jsonBytes, err := statusclient.StatusResponseToJSON(resp)
	if err != nil {
		filter.OutputError(err, filter.ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}

// newStatusClient creates a StatusClient using the shared connection config
func newStatusClient() (*statusclient.StatusClient, error) {
	cfg := filter.GetClientConfig()
	return statusclient.NewStatusClient(statusclient.ClientConfig{
		Address:       cfg.Address,
		TLSEnabled:    cfg.TLSEnabled,
		TLSCAFile:     cfg.TLSCAFile,
		TLSCertFile:   cfg.TLSCertFile,
		TLSKeyFile:    cfg.TLSKeyFile,
		TLSSkipVerify: cfg.TLSSkipVerify,
	})
}
