//go:build tui || all
// +build tui all

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

The nodes configuration is loaded from a YAML file. Default locations:
  1. ./nodes.yaml
  2. ~/.config/lippycat/nodes.yaml

Examples:
  lc watch remote
  lc watch remote --nodes-file /path/to/nodes.yaml
  lc watch remote --tls --tls-ca ca.crt`,
	Run: runRemote,
}

var (
	remoteNodesFile string
	remoteInsecure  bool
	// TLS flags
	remoteTLSEnabled  bool
	remoteTLSCAFile   string
	remoteTLSCertFile string
	remoteTLSKeyFile  string
)

func runRemote(cmd *cobra.Command, args []string) {
	// Override TLS config with command-line flags ONLY if explicitly provided
	if cmd.Flags().Changed("insecure") && remoteInsecure {
		viper.Set("tui.tls.enabled", false)
	}
	if cmd.Flags().Changed("tls") {
		viper.Set("tui.tls.enabled", remoteTLSEnabled)
	}
	if cmd.Flags().Changed("tls-ca") {
		viper.Set("tui.tls.ca_file", remoteTLSCAFile)
	}
	if cmd.Flags().Changed("tls-cert") {
		viper.Set("tui.tls.cert_file", remoteTLSCertFile)
	}
	if cmd.Flags().Changed("tls-key") {
		viper.Set("tui.tls.key_file", remoteTLSKeyFile)
	}

	// Disable logging to prevent corrupting TUI display
	logger.Disable()
	defer logger.Enable()

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("watch.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Create TUI model for remote monitoring mode
	model := tui.NewModel(
		bufferSize,
		"",              // interfaceName - not used for remote mode
		"",              // bpfFilter - not used for remote mode
		"",              // pcapFile - not used for remote mode
		false,           // promiscuous - not applicable
		true,            // startInRemoteMode
		remoteNodesFile, // nodesFilePath
		remoteInsecure,  // insecure
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
	remoteCmd.Flags().BoolVar(&remoteInsecure, "insecure", false, "allow insecure connections (no TLS) for testing/development")

	// TLS configuration
	remoteCmd.Flags().BoolVarP(&remoteTLSEnabled, "tls", "T", false, "enable TLS encryption for remote connections")
	remoteCmd.Flags().StringVar(&remoteTLSCAFile, "tls-ca", "", "path to CA certificate for server verification")
	remoteCmd.Flags().StringVar(&remoteTLSCertFile, "tls-cert", "", "path to client TLS certificate (for mutual TLS)")
	remoteCmd.Flags().StringVar(&remoteTLSKeyFile, "tls-key", "", "path to client TLS key (for mutual TLS)")
}
