package hunt

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var HuntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Run as hunter node (edge packet capture)",
	Long: `Run lippycat in hunter mode.

Hunter nodes capture packets at the network edge and forward
matched packets to a central processor node via gRPC.

Hunters apply local filters to reduce bandwidth and only send
relevant packets upstream.

Example:
  lippycat hunt --processor processor.example.com:50051
  lippycat hunt --processor 192.168.1.100:50051 --interface eth0
  lippycat hunt --processor processor:50051 --hunter-id edge-01`,
	RunE: runHunt,
}

var (
	processorAddr string
	hunterID      string
	interfaces    []string
	bpfFilter     string
	bufferSize    int
	batchSize     int
	batchTimeout  int
	promiscuous   bool
)

func init() {
	// Required flags
	HuntCmd.Flags().StringVar(&processorAddr, "processor", "", "Processor address (host:port)")
	HuntCmd.MarkFlagRequired("processor")

	// Hunter configuration
	HuntCmd.Flags().StringVarP(&hunterID, "hunter-id", "", "", "Unique hunter identifier (default: hostname)")
	HuntCmd.Flags().StringSliceVarP(&interfaces, "interface", "i", []string{"any"}, "Network interfaces to capture (comma-separated)")
	HuntCmd.Flags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
	HuntCmd.Flags().BoolVarP(&promiscuous, "promisc", "p", false, "Enable promiscuous mode")

	// Performance tuning
	HuntCmd.Flags().IntVarP(&bufferSize, "buffer-size", "b", 10000, "Packet buffer size")
	HuntCmd.Flags().IntVarP(&batchSize, "batch-size", "", 64, "Packets per batch sent to processor")
	HuntCmd.Flags().IntVarP(&batchTimeout, "batch-timeout", "", 100, "Batch timeout in milliseconds")

	// Bind to viper for config file support
	viper.BindPFlag("hunter.processor_addr", HuntCmd.Flags().Lookup("processor"))
	viper.BindPFlag("hunter.hunter_id", HuntCmd.Flags().Lookup("hunter-id"))
	viper.BindPFlag("hunter.interfaces", HuntCmd.Flags().Lookup("interface"))
	viper.BindPFlag("hunter.bpf_filter", HuntCmd.Flags().Lookup("filter"))
	viper.BindPFlag("hunter.buffer_size", HuntCmd.Flags().Lookup("buffer-size"))
	viper.BindPFlag("hunter.batch_size", HuntCmd.Flags().Lookup("batch-size"))
	viper.BindPFlag("hunter.batch_timeout_ms", HuntCmd.Flags().Lookup("batch-timeout"))
	viper.BindPFlag("promiscuous", HuntCmd.Flags().Lookup("promisc"))
}

func runHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in hunter mode")

	// Get configuration (flags override config file)
	config := hunter.Config{
		ProcessorAddr: getStringConfig("hunter.processor_addr", processorAddr),
		HunterID:      getStringConfig("hunter.hunter_id", hunterID),
		Interfaces:    getStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:     getStringConfig("hunter.bpf_filter", bpfFilter),
		BufferSize:    getIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:     getIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:  time.Duration(getIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
	}

	// Set default hunter ID to hostname if not specified
	if config.HunterID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		config.HunterID = hostname
	}

	// Validate configuration
	if config.ProcessorAddr == "" {
		return fmt.Errorf("processor address is required (use --processor flag)")
	}

	logger.Info("Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"buffer_size", config.BufferSize,
		"batch_size", config.BatchSize)

	// Create hunter instance
	h, err := hunter.New(config)
	if err != nil {
		return fmt.Errorf("failed to create hunter: %w", err)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start hunter in background
	errChan := make(chan error, 1)
	go func() {
		if err := h.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	logger.Info("Hunter started successfully",
		"processor", config.ProcessorAddr,
		"hunter_id", config.HunterID)

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", "signal", sig)
		cancel()
		// Give some time for graceful shutdown
		time.Sleep(2 * time.Second)
	case err := <-errChan:
		logger.Error("Hunter failed", "error", err)
		return err
	}

	logger.Info("Hunter stopped")
	return nil
}

// Helper functions to get config values with fallback to flags
func getStringConfig(key, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return viper.GetString(key)
}

func getStringSliceConfig(key string, flagValue []string) []string {
	if len(flagValue) > 0 && flagValue[0] != "any" {
		return flagValue
	}
	if viper.IsSet(key) {
		return viper.GetStringSlice(key)
	}
	return flagValue
}

func getIntConfig(key string, flagValue int) int {
	// Simplified version without circular reference
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return flagValue
}
