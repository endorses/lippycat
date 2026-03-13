//go:build cli || all

package list

import (
	"fmt"

	"github.com/endorses/lippycat/cmd/filter"
	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/statusclient"
	"github.com/spf13/cobra"
)

var huntersCmd = &cobra.Command{
	Use:   "hunters",
	Short: "List connected hunters on a processor",
	Long: `List all connected hunters on a remote processor.

Connects to a processor via gRPC and retrieves information about all connected
hunters including capture statistics, interfaces, and capabilities.
Output is a JSON array to stdout.

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # List all connected hunters (TLS with CA verification)
  lc list hunters -P processor.example.com:55555 --tls-ca ca.crt

  # Local testing without TLS
  lc list hunters -P localhost:55555 --insecure`,
	Run: runListHunters,
}

func init() {
	filter.AddConnectionFlags(huntersCmd)
	ListCmd.AddCommand(huntersCmd)
}

func runListHunters(cmd *cobra.Command, args []string) {
	client, err := newHunterStatusClient()
	if err != nil {
		filter.OutputError(err, filter.ExitConnectionError)
		return
	}
	defer client.Close()

	hunters, err := client.GetHunters("")
	if err != nil {
		filter.OutputError(err, filter.MapGRPCError(err))
		return
	}

	pretty := output.IsTTY()
	jsonBytes, err := statusclient.HuntersToJSON(hunters, pretty)
	if err != nil {
		filter.OutputError(err, filter.ExitGeneralError)
		return
	}

	cmd.Println(string(jsonBytes))
}

// newHunterStatusClient creates a StatusClient using the shared connection config.
func newHunterStatusClient() (*statusclient.StatusClient, error) {
	cfg := filter.GetClientConfig()

	if cfg.Address == "" {
		return nil, fmt.Errorf("processor address is required (use --processor or set remote.processor in config)")
	}

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
