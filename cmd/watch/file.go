//go:build tui || all

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
	Use:   "file [files...]",
	Short: "Analyze PCAP file(s) in TUI",
	Long: `Open one or more PCAP files for interactive analysis in the TUI.

When multiple files are provided, packets are merged and displayed together.
Each packet shows its source file in the interface column.

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
	configBufferSize := viper.GetInt("tui.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Create TUI model for offline file mode
	// Pass insecureAllowed so TLS settings work if user switches to remote mode in TUI
	model := tui.NewModel(
		bufferSize,
		"", // interfaceName - not used for file mode
		fileFilter,
		args,            // pcapFiles - all files from args
		false,           // promiscuous - not applicable
		false,           // startInRemoteMode
		"",              // nodesFilePath
		insecureAllowed, // insecure - passed for remote mode switching
	)

	// Start bubbletea program with mouse support
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())

	// Store program reference for packet bridge
	tui.SetCurrentProgram(p)

	// Initialize offline call tracker for RTP-to-CallID mapping BEFORE starting capture
	// This is critical - the bridge needs the tracker available when processing SIP packets
	offlineTracker := tui.NewOfflineCallTracker()
	tui.SetOfflineCallTracker(offlineTracker)

	// Start packet capture in background using timestamp-ordered processing
	// This ensures SIP packets are processed before their corresponding RTP packets,
	// which is essential for proper call tracking
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	tui.SetCaptureHandle(cancel, done)

	go func() {
		defer close(done)
		capture.StartOfflineSnifferOrdered(args, fileFilter, func(devices []pcaptypes.PcapInterface, filter string) {
			startFileSnifferOrdered(ctx, devices, filter, p)
		})
	}()

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

// startFileSnifferOrdered initializes timestamp-ordered packet capture for offline VoIP analysis.
// This ensures SIP packets are processed before their corresponding RTP packets,
// which is essential for proper call tracking and RTP-to-CallID mapping.
func startFileSnifferOrdered(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		tui.StartPacketBridge(ch, program)
	}
	// Use RunOfflineOrdered which reads all packets, sorts by timestamp, then processes
	capture.RunOfflineOrdered(devices, filter, processor, nil)
}

func init() {
	fileCmd.Flags().StringVarP(&fileFilter, "filter", "f", "", "BPF filter to apply")
	fileCmd.Flags().StringVar(&fileTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("tui.tls_keylog", fileCmd.Flags().Lookup("tls-keylog"))
}
