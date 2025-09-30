package tui

import (
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
	interfaces  string
	filter      string
	readFile    string
	bufferSize  int
	promiscuous bool
	themeName   string
)

func runTUI(cmd *cobra.Command, args []string) {
	// Disable logging to prevent stdout pollution in TUI mode
	logger.Disable()

	// Re-enable logging on exit
	defer logger.Enable()

	// Create TUI model
	model := NewModel(bufferSize)
	model.interfaceName = interfaces

	// Create packet channel
	packetChan := make(chan capture.PacketInfo, 1000)

	// Start bubbletea program
	p := tea.NewProgram(model, tea.WithAltScreen())

	// Start packet capture in background
	go func() {
		if readFile != "" {
			capture.StartOfflineSniffer(readFile, filter, func(devices []pcaptypes.PcapInterface, filter string) {
				startTUISniffer(devices, filter, packetChan, p)
			})
		} else {
			capture.StartLiveSniffer(interfaces, filter, func(devices []pcaptypes.PcapInterface, filter string) {
				startTUISniffer(devices, filter, packetChan, p)
			})
		}
	}()

	// Run TUI
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func startTUISniffer(devices []pcaptypes.PcapInterface, filter string, packetChan chan<- capture.PacketInfo, program *tea.Program) {
	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		// Don't use goroutine - block here so capture.Init doesn't exit early
		StartPacketBridge(ch, program)
	}

	capture.Init(devices, filter, processor, nil)
}

func init() {
	TuiCmd.Flags().StringVarP(&interfaces, "interface", "i", "any", "interface(s) to monitor, comma separated")
	TuiCmd.Flags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
	TuiCmd.Flags().StringVarP(&readFile, "read-file", "r", "", "read from pcap file")
	TuiCmd.Flags().IntVar(&bufferSize, "buffer-size", 10000, "maximum number of packets to keep in memory")
	TuiCmd.Flags().BoolVarP(&promiscuous, "promiscuous", "p", false, "use promiscuous mode")
	TuiCmd.Flags().StringVar(&themeName, "theme", "", "color theme: 'dark', 'light', 'solarized-dark', 'solarized-light' (default: saved preference or dark)")

	viper.BindPFlag("promiscuous", TuiCmd.Flags().Lookup("promiscuous"))
	viper.BindPFlag("tui.theme", TuiCmd.Flags().Lookup("theme"))
}