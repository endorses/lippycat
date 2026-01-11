//go:build tui || all
// +build tui all

package watch

import (
	"context"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/tui"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Analyze PCAP file in TUI",
	Long: `Open a PCAP file for interactive analysis in the TUI.

TLS Decryption:
  Use --tls-keylog to provide an SSLKEYLOGFILE for decrypting HTTPS traffic.
  This enables viewing decrypted HTTP content from encrypted PCAP captures.

Examples:
  lc watch file -r capture.pcap
  lc watch file -r capture.pcap -f "port 5060"  # With BPF filter
  lc watch file -r capture.pcap --tls-keylog keys.log  # With TLS decryption`,
	Run: runFile,
}

var (
	fileReadFile  string
	fileFilter    string
	fileTLSKeylog string
)

func runFile(cmd *cobra.Command, args []string) {
	if fileReadFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --read-file/-r is required for file mode")
		os.Exit(1)
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
		viper.Set("tui.tls_keylog", fileTLSKeylog)
		viper.Set("tui.tls_decryption_enabled", true)
	}

	// Disable logging to prevent corrupting TUI display
	logger.Disable()
	defer logger.Enable()

	// Initialize TLS decryptor if enabled
	if tui.InitTLSDecryptorFromConfig() {
		defer tui.ClearTLSDecryptor()
	}

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("watch.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Create TUI model for offline file mode
	// Pass insecureAllowed so TLS settings work if user switches to remote mode in TUI
	model := tui.NewModel(
		bufferSize,
		"", // interfaceName - not used for file mode
		fileFilter,
		fileReadFile,    // pcapFile
		false,           // promiscuous - not applicable
		false,           // startInRemoteMode
		"",              // nodesFilePath
		insecureAllowed, // insecure - passed for remote mode switching
	)

	// Start bubbletea program with mouse support
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())

	// Store program reference for packet bridge
	tui.SetCurrentProgram(p)

	// Start packet capture in background
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	tui.SetCaptureHandle(cancel, done)

	go func() {
		defer close(done)
		capture.StartOfflineSniffer(fileReadFile, fileFilter, func(devices []pcaptypes.PcapInterface, filter string) {
			startFileSniffer(ctx, devices, filter, p)
		})
	}()

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func startFileSniffer(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		tui.StartPacketBridge(ch, program)
	}
	capture.InitWithContext(ctx, devices, filter, processor, nil)
}

func init() {
	fileCmd.Flags().StringVarP(&fileReadFile, "read-file", "r", "", "PCAP file to analyze (required)")
	fileCmd.Flags().StringVarP(&fileFilter, "filter", "f", "", "BPF filter to apply")
	fileCmd.Flags().StringVar(&fileTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")

	_ = fileCmd.MarkFlagRequired("read-file")

	// Bind to viper for config file support
	_ = viper.BindPFlag("watch.file.tls_keylog", fileCmd.Flags().Lookup("tls-keylog"))
}
