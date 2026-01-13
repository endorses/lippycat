//go:build tui || all

package watch

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// WatchCmd is the base watch command that provides interactive TUI monitoring.
// If no subcommand is specified, it defaults to live mode.
var WatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Monitor traffic (TUI)",
	Long: `Start lippycat with an interactive terminal user interface for monitoring.

TLS is enabled by default for remote connections. Use --insecure for local testing.

Subcommands:
  live    - Live capture from network interface (default)
  file    - Analyze PCAP file
  remote  - Monitor remote hunter/processor nodes

Examples:
  lc watch                          # Live capture (default)
  lc watch live -i eth0             # Live capture on eth0
  lc watch file -r capture.pcap
  lc watch remote -n nodes.yaml --tls-ca ca.crt
  lc watch remote -n nodes.yaml --insecure  # Local testing only`,
	Run: func(cmd *cobra.Command, args []string) {
		// Default to live mode if no subcommand is specified
		runLive(cmd, args)
	},
}

// Shared flags across all watch modes
var (
	bufferSize int

	// TLS flags (TLS is enabled by default unless --insecure is set)
	insecureAllowed   bool
	tlsCAFile         string
	tlsCertFile       string
	tlsKeyFile        string
	tlsSkipVerify     bool
	tlsServerOverride string
)

func init() {
	// Add subcommands
	WatchCmd.AddCommand(liveCmd)
	WatchCmd.AddCommand(fileCmd)
	WatchCmd.AddCommand(remoteCmd)

	// Shared flags (inherited by subcommands)
	WatchCmd.PersistentFlags().IntVar(&bufferSize, "buffer-size", 10000, "maximum number of packets to keep in memory")

	// TLS configuration (enabled by default unless --insecure)
	WatchCmd.PersistentFlags().BoolVar(&insecureAllowed, "insecure", false, "allow insecure connections without TLS (testing only)")
	WatchCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca", "", "path to CA certificate for server verification")
	WatchCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert", "", "path to client TLS certificate (for mutual TLS)")
	WatchCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key", "", "path to client TLS key (for mutual TLS)")
	WatchCmd.PersistentFlags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "skip TLS certificate verification (INSECURE - testing only)")
	WatchCmd.PersistentFlags().StringVar(&tlsServerOverride, "tls-server-name", "", "override server name for TLS verification")

	_ = viper.BindPFlag("tui.buffer_size", WatchCmd.PersistentFlags().Lookup("buffer-size"))

	// Bind TLS flags to viper for config file support
	_ = viper.BindPFlag("tui.tls.ca_file", WatchCmd.PersistentFlags().Lookup("tls-ca"))
	_ = viper.BindPFlag("tui.tls.cert_file", WatchCmd.PersistentFlags().Lookup("tls-cert"))
	_ = viper.BindPFlag("tui.tls.key_file", WatchCmd.PersistentFlags().Lookup("tls-key"))
	_ = viper.BindPFlag("tui.tls.skip_verify", WatchCmd.PersistentFlags().Lookup("tls-skip-verify"))
	_ = viper.BindPFlag("tui.tls.server_name_override", WatchCmd.PersistentFlags().Lookup("tls-server-name"))
}

// configureTLSViper sets TLS configuration in viper for use by TUI components.
// This allows switching to remote mode from within the TUI with proper TLS settings.
func configureTLSViper(cmd *cobra.Command) {
	// TLS is enabled by default unless --insecure is set
	tlsEnabled := !insecureAllowed
	viper.Set("tui.tls.enabled", tlsEnabled)

	if cmd.Flags().Changed("tls-ca") {
		viper.Set("tui.tls.ca_file", tlsCAFile)
	}
	if cmd.Flags().Changed("tls-cert") {
		viper.Set("tui.tls.cert_file", tlsCertFile)
	}
	if cmd.Flags().Changed("tls-key") {
		viper.Set("tui.tls.key_file", tlsKeyFile)
	}
	if cmd.Flags().Changed("tls-skip-verify") {
		viper.Set("tui.tls.skip_verify", tlsSkipVerify)
	}
	if cmd.Flags().Changed("tls-server-name") {
		viper.Set("tui.tls.server_name_override", tlsServerOverride)
	}
}
