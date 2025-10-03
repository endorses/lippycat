package tui

import (
	"context"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var TuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Start lippycat in TUI mode",
	Long:  `Start lippycat with an interactive terminal user interface for live packet monitoring.`,
	Run:   runTUI,
}

var (
	interfaces    string
	filter        string
	readFile      string
	bufferSize    int
	promiscuous   bool
	themeName     string
	remoteMode    bool
	nodesFile     string
	enableGPU     bool
	gpuBackend    string
	gpuBatchSize  int
)

func runTUI(cmd *cobra.Command, args []string) {
	// Disable logging to prevent stdout pollution in TUI mode
	logger.Disable()

	// Re-enable logging on exit
	defer logger.Enable()

	// Load buffer size from config, use flag value as fallback
	configBufferSize := viper.GetInt("tui.buffer_size")
	if configBufferSize > 0 {
		bufferSize = configBufferSize
	}

	// Create TUI model
	model := NewModel(bufferSize, interfaces, filter, readFile, promiscuous, remoteMode, nodesFile)

	// Start bubbletea program with mouse support
	// Use WithMouseAllMotion for better mouse support that survives suspend/resume
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())

	// Store program reference globally
	currentProgram = p

	// Start packet capture in background (skip if starting in remote mode)
	if !remoteMode {
		ctx, cancel := context.WithCancel(context.Background())
		currentCaptureCancel = cancel

		go func() {
			if readFile != "" {
				capture.StartOfflineSniffer(readFile, filter, func(devices []pcaptypes.PcapInterface, filter string) {
					startTUISniffer(ctx, devices, filter, p)
				})
			} else {
				capture.StartLiveSniffer(interfaces, filter, func(devices []pcaptypes.PcapInterface, filter string) {
					startTUISniffer(ctx, devices, filter, p)
				})
			}
		}()
	}

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func startTUISniffer(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		// Don't use goroutine - block here so capture.Init doesn't exit early
		StartPacketBridge(ch, program)
	}

	capture.InitWithContext(ctx, devices, filter, processor, nil)
}

func init() {
	TuiCmd.Flags().StringVarP(&interfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	TuiCmd.Flags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
	TuiCmd.Flags().StringVarP(&readFile, "read-file", "r", "", "read from pcap file")
	TuiCmd.Flags().IntVar(&bufferSize, "buffer-size", 10000, "maximum number of packets to keep in memory")
	TuiCmd.Flags().BoolVarP(&promiscuous, "promiscuous", "p", false, "use promiscuous mode")
	TuiCmd.Flags().StringVar(&themeName, "theme", "", "color theme: 'dark', 'light', 'solarized-dark', 'solarized-light' (default: saved preference or dark)")
	TuiCmd.Flags().BoolVar(&remoteMode, "remote", false, "start in remote capture mode")
	TuiCmd.Flags().StringVar(&nodesFile, "nodes-file", "", "path to nodes YAML file (default: ~/.config/lippycat/nodes.yaml or ./nodes.yaml)")
	TuiCmd.Flags().BoolVar(&enableGPU, "enable-gpu", false, "enable GPU-accelerated VoIP parsing")
	TuiCmd.Flags().StringVar(&gpuBackend, "gpu-backend", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd'")
	TuiCmd.Flags().IntVar(&gpuBatchSize, "gpu-batch-size", 100, "batch size for GPU processing")

	viper.BindPFlag("promiscuous", TuiCmd.Flags().Lookup("promiscuous"))
	viper.BindPFlag("tui.theme", TuiCmd.Flags().Lookup("theme"))
	viper.BindPFlag("tui.gpu.enabled", TuiCmd.Flags().Lookup("enable-gpu"))
	viper.BindPFlag("tui.gpu.backend", TuiCmd.Flags().Lookup("gpu-backend"))
	viper.BindPFlag("tui.gpu.batch_size", TuiCmd.Flags().Lookup("gpu-batch-size"))
}