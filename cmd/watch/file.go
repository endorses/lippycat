//go:build tui || all

package watch

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/tui"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var fileCmd = &cobra.Command{
	Use:   "file [files...]",
	Short: "Analyze PCAP file(s) in TUI",
	Long: `Open one or more PCAP files for interactive analysis in the TUI.

When multiple files are provided, packets are merged and displayed together.
Each packet shows its source file in the interface column.
Backward timestamps are ordered using temporary disk storage before analysis;
timestamps are preserved. Escape cancels opening. All accepted logical packets
remain available regardless of --buffer-size; event/call history is bounded.

TLS Decryption:
  Use --tls-keylog to provide an SSLKEYLOGFILE for decrypting HTTPS traffic.
  This enables viewing decrypted HTTP content from encrypted PCAP captures.

Examples:
  lc watch file capture.pcap
  lc watch file sip.pcap rtp.pcap                # Merge multiple files
  lc watch file capture.pcap -f "port 5060"      # With BPF filter
  lc watch file capture.pcap --tls-keylog keys.log  # With TLS decryption`,
	Args: cobra.MinimumNArgs(1),
	Run:  runFile,
}

var (
	fileFilter    string
	fileTLSKeylog string
)

func runFile(cmd *cobra.Command, args []string) {
	if _, err := offline.ParseBackingPolicy(viper.GetString("watch.offline.backing_policy")); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	// Validate all files exist
	for _, filePath := range args {
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: file not found: %s\n", filePath)
			os.Exit(1)
		}
	}

	// Set TLS configuration in viper for use by TUI components (if user switches to remote mode)
	configureTLSViper(cmd)

	// Validate TLS keylog if specified
	if fileTLSKeylog != "" {
		decryptConfig := tls.DecryptConfig{
			KeylogFile: fileTLSKeylog,
		}
		if err := decryptConfig.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid TLS keylog: %v\n", err)
			os.Exit(1)
		}
		viper.Set("watch.tls_keylog", fileTLSKeylog)
		viper.Set("watch.tls_decryption_enabled", true)
	}

	// Handle logging for TUI mode
	if logger.InitConsole() {
		// LOG_LEVEL=DEBUG - capture to in-memory console buffer for TUI display
		logger.EnableConsoleCapture()
	} else {
		// Normal mode - disable logging to prevent corrupting TUI display
		logger.Disable()
		defer logger.Enable()
	}

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("watch.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Load max calls from config, use flag value as fallback
	configMaxCalls := viper.GetInt("watch.max_calls")
	if configMaxCalls > 0 {
		maxCalls = configMaxCalls
	}

	// Create TUI model for offline file mode
	// Pass insecureAllowed so TLS settings work if user switches to remote mode in TUI
	model := tui.NewModel(
		bufferSize,
		maxCalls,
		"", // interfaceName - not used for file mode
		fileFilter,
		args,            // pcapFiles - all files from args
		false,           // promiscuous - not applicable
		false,           // startInRemoteMode
		"",              // nodesFilePath
		insecureAllowed, // insecure - passed for remote mode switching
	)

	failed := false
	defer func() {
		if err := model.CloseOffline(); err != nil {
			fmt.Fprintf(os.Stderr, "Error cleaning up offline dataset: %v\n", err)
			failed = true
		}
		model.Shutdown()
		if failed {
			os.Exit(1)
		}
	}()

	// Force color profile since termenv may have detected wrong profile during init
	lipgloss.SetColorProfile(termenv.TrueColor)

	// Start bubbletea program with mouse support
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())
	// Store program reference for packet bridge
	tui.SetCurrentProgram(p)

	// Offline indexing is owned by the model and starts from Model.Init.

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		failed = true
	}
}

func init() {
	fileCmd.Flags().StringVarP(&fileFilter, "filter", "f", "", "BPF filter to apply")
	fileCmd.Flags().StringVar(&fileTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("watch.tls_keylog", fileCmd.Flags().Lookup("tls-keylog"))
}
