//go:build cli || all

package show

import (
	"fmt"

	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show processor status",
	Long: `Show processor status and statistics.

Connects to a processor via gRPC and retrieves current status including
hunter counts, packet statistics, and overall health. Output is JSON to stdout.

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Show processor status (TLS with CA verification)
  lc show status -P processor.example.com:50051 --tls-ca ca.crt

  # Local testing without TLS
  lc show status -P localhost:50051 --insecure`,
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

	jsonBytes, err := statusclient.StatusResponseToJSON(resp, output.IsTTY())
	if err != nil {
		filter.OutputError(err, filter.ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}

// newStatusClient creates a StatusClient using the shared connection config.
// Validates secure-by-default requirements before attempting connection.
func newStatusClient() (*statusclient.StatusClient, error) {
	cfg := filter.GetClientConfig()

	if cfg.Address == "" {
		return nil, fmt.Errorf("processor address is required (use --processor or set remote.processor in config)")
	}

	// Secure-by-default validation: TLS enabled requires CA cert (unless skip-verify)
	if cfg.TLSEnabled && cfg.TLSCAFile == "" && !cfg.TLSSkipVerify {
		return nil, fmt.Errorf("TLS is enabled but no CA certificate provided\n\n" +
			"To connect securely, use: --tls-ca=/path/to/ca.crt\n" +
			"To skip verification (INSECURE), use: --tls-skip-verify\n" +
			"To allow insecure connections (NOT RECOMMENDED), use: --insecure")
	}

	return statusclient.NewStatusClient(statusclient.ClientConfig{
		Address:       cfg.Address,
		TLSEnabled:    cfg.TLSEnabled,
		TLSCAFile:     cfg.TLSCAFile,
		TLSCertFile:   cfg.TLSCertFile,
		TLSKeyFile:    cfg.TLSKeyFile,
		TLSSkipVerify: cfg.TLSSkipVerify,
	})
}
