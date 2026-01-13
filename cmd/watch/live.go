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
	"github.com/endorses/lippycat/internal/pkg/tui"
	"github.com/google/gopacket/tcpassembly"
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
)

func runLive(cmd *cobra.Command, args []string) {
	// Set TLS configuration in viper for use by TUI components (if user switches to remote mode)
	configureTLSViper(cmd)

	// Disable logging to prevent corrupting TUI display
	logger.Disable()
	defer logger.Enable()

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("tui.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Create TUI model for live capture mode
	// Live mode: no pcapFile, not remote, no nodesFile
	// Pass insecureAllowed so TLS settings work if user switches to remote mode in TUI
	model := tui.NewModel(
		bufferSize,
		liveInterfaces,
		liveFilter,
		"", // pcapFile - empty for live mode
		livePromiscuous,
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
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		tui.StartPacketBridge(ch, program)
	}
	capture.InitWithContext(ctx, devices, filter, processor, nil)
}

func init() {
	liveCmd.Flags().StringVarP(&liveInterfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	liveCmd.Flags().StringVarP(&liveFilter, "filter", "f", "", "BPF filter to apply")
	liveCmd.Flags().BoolVarP(&livePromiscuous, "promiscuous", "p", false, "use promiscuous mode")
	liveCmd.Flags().BoolVar(&liveEnableGPU, "enable-gpu", false, "enable GPU-accelerated VoIP parsing")
	liveCmd.Flags().StringVarP(&liveGPUBackend, "gpu-backend", "g", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd'")
	liveCmd.Flags().IntVar(&liveGPUBatchSize, "gpu-batch-size", 100, "batch size for GPU processing")

	_ = viper.BindPFlag("promiscuous", liveCmd.Flags().Lookup("promiscuous"))
	_ = viper.BindPFlag("watch.gpu.enabled", liveCmd.Flags().Lookup("enable-gpu"))
	_ = viper.BindPFlag("watch.gpu.backend", liveCmd.Flags().Lookup("gpu-backend"))
	_ = viper.BindPFlag("watch.gpu.batch_size", liveCmd.Flags().Lookup("gpu-batch-size"))
}
