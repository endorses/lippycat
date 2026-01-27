//go:build tui || all

package watch

import (
	"context"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui"
	"github.com/google/gopacket/tcpassembly"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var liveCmd = &cobra.Command{
	Use:   "live",
	Short: "Live capture from network interface",
	Long: `Start live packet capture with an interactive TUI.

This is the default mode when running 'lc watch' without a subcommand.

Examples:
  lc watch live                   # Capture on default interface
  lc watch live -i eth0           # Capture on eth0
  lc watch live -i eth0 -f "port 5060"  # With BPF filter`,
	Run: runLive,
}

var (
	liveInterfaces   string
	liveFilter       string
	livePromiscuous  bool
	liveEnableGPU    bool
	liveGPUBackend   string
	liveGPUBatchSize int
	liveDebugLog     string
)

func runLive(cmd *cobra.Command, args []string) {
	// Set TLS configuration in viper for use by TUI components (if user switches to remote mode)
	configureTLSViper(cmd)

	// Handle debug logging - if specified, write logs to file instead of disabling
	if liveDebugLog != "" {
		f, err := os.OpenFile(liveDebugLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening debug log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		logger.UseFile(f)
	} else {
		// Disable logging to prevent corrupting TUI display
		logger.Disable()
		defer logger.Enable()
	}

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

	// Create TUI model for live capture mode
	// Live mode: no pcapFiles, not remote, no nodesFile
	// Pass insecureAllowed so TLS settings work if user switches to remote mode in TUI
	model := tui.NewModel(
		bufferSize,
		maxCalls,
		liveInterfaces,
		liveFilter,
		nil, // pcapFiles - nil for live mode
		livePromiscuous,
		false,           // startInRemoteMode
		"",              // nodesFilePath
		insecureAllowed, // insecure - passed for remote mode switching
	)

	// Full terminal reset (RIS) to clear any corrupted state including color palette
	fmt.Print("\033c")

	// Force color profile since termenv may have detected wrong profile during init
	lipgloss.SetColorProfile(termenv.TrueColor)

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
		capture.StartLiveSniffer(liveInterfaces, liveFilter, func(devices []pcaptypes.PcapInterface, filter string) {
			startLiveSniffer(ctx, devices, filter, p)
		})
	}()

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func startLiveSniffer(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	pauseSignal := tui.GetGlobalPauseSignal()
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		tui.StartPacketBridge(ch, program, pauseSignal)
	}
	// Pass pause function to drop packets at source when paused (reduces CPU)
	capture.InitWithContext(ctx, devices, filter, processor, nil, pauseSignal.IsPaused)
}

func init() {
	liveCmd.Flags().StringVarP(&liveInterfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	liveCmd.Flags().StringVarP(&liveFilter, "filter", "f", "", "BPF filter to apply")
	liveCmd.Flags().BoolVarP(&livePromiscuous, "promiscuous", "p", false, "use promiscuous mode")
	liveCmd.Flags().BoolVar(&liveEnableGPU, "enable-gpu", false, "enable GPU-accelerated VoIP parsing")
	liveCmd.Flags().StringVarP(&liveGPUBackend, "gpu-backend", "g", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd'")
	liveCmd.Flags().IntVar(&liveGPUBatchSize, "gpu-batch-size", 100, "batch size for GPU processing")
	liveCmd.Flags().StringVar(&liveDebugLog, "debug-log", "", "write debug logs to file (helps diagnose capture issues)")

	_ = viper.BindPFlag("promiscuous", liveCmd.Flags().Lookup("promiscuous"))
	_ = viper.BindPFlag("tui.gpu.enabled", liveCmd.Flags().Lookup("enable-gpu"))
	_ = viper.BindPFlag("tui.gpu.backend", liveCmd.Flags().Lookup("gpu-backend"))
	_ = viper.BindPFlag("tui.gpu.batch_size", liveCmd.Flags().Lookup("gpu-batch-size"))
}
