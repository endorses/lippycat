//go:build tui || all

package watch

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Monitor remote hunter/processor nodes",
	Long: `Start the TUI in remote monitoring mode to connect to distributed
hunter and processor nodes.

TLS is enabled by default. Use --insecure for local testing without TLS.

The nodes configuration is loaded from a YAML file. Default locations:
  1. ./nodes.yaml
  2. ~/.config/lippycat/nodes.yaml

Examples:
  lc watch remote --tls-ca ca.crt
  lc watch remote -n /path/to/nodes.yaml --tls-ca ca.crt
  lc watch remote --tls-ca ca.crt --tls-cert client.crt --tls-key client.key
  lc watch remote --insecure  # Local testing only`,
	Run: runRemote,
}

var (
	remoteNodesFile string
)

func runRemote(cmd *cobra.Command, args []string) {
	// Check production mode
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode && insecureAllowed {
		fmt.Fprintln(os.Stderr, "Error: LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		os.Exit(1)
	}

	// Set TLS configuration in viper for use by TUI components
	configureTLSViper(cmd)

	// Validate TLS configuration when TLS is enabled (remote mode requires server connection)
	tlsEnabled := !insecureAllowed
	effectiveCAFile := viper.GetString("tui.tls.ca_file")
	effectiveSkipVerify := viper.GetBool("tui.tls.skip_verify")
	if tlsEnabled && effectiveCAFile == "" && !effectiveSkipVerify {
		fmt.Fprintln(os.Stderr, "Error: TLS is enabled but no CA certificate provided")
		fmt.Fprintln(os.Stderr, "For TLS connections, provide a CA certificate: --tls-ca=/path/to/ca.crt")
		fmt.Fprintln(os.Stderr, "Or skip verification (INSECURE - testing only): --tls-skip-verify")
		fmt.Fprintln(os.Stderr, "Or disable TLS entirely (NOT RECOMMENDED): --insecure")
		os.Exit(1)
	}

	// Disable logging to prevent corrupting TUI display
	logger.Disable()
	defer logger.Enable()

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("tui.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Load max calls from config, use flag value as fallback
	configMaxCalls := viper.GetInt("tui.max_calls")
	if configMaxCalls > 0 {
		maxCalls = configMaxCalls
	}

	// Create TUI model for remote monitoring mode
	model := tui.NewModel(
		bufferSize,
		maxCalls,
		"",              // interfaceName - not used for remote mode
		"",              // bpfFilter - not used for remote mode
		nil,             // pcapFiles - not used for remote mode
		false,           // promiscuous - not applicable
		true,            // startInRemoteMode
		remoteNodesFile, // nodesFilePath
		insecureAllowed, // insecure
	)

	// Start bubbletea program with mouse support
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())

	// Store program reference for event handlers
	tui.SetCurrentProgram(p)

	// Remote mode doesn't start local capture - connections are made via the Nodes view

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	remoteCmd.Flags().StringVarP(&remoteNodesFile, "nodes-file", "n", "", "path to nodes YAML file (default: ~/.config/lippycat/nodes.yaml or ./nodes.yaml)")
}
