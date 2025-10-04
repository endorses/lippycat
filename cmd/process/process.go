package process

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Run as processor node (central aggregation)",
	Long: `Run lippycat in processor mode.

Processor nodes receive packets from multiple hunter nodes via gRPC,
aggregate them, and optionally forward filtered traffic upstream to
another processor (hierarchical mode).

Processors manage filter distribution to connected hunters and
provide monitoring APIs for TUI clients.

Example:
  lippycat process --listen :50051
  lippycat process --listen 0.0.0.0:50051 --upstream parent:50051
  lippycat process --listen :50051 --max-hunters 100`,
	RunE: runProcess,
}

var (
	listenAddr      string
	upstreamAddr    string
	maxHunters      int
	writeFile       string
	displayStats    bool
	enableDetection bool
)

func init() {
	// Required flags
	ProcessCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":50051", "Listen address for hunter connections (host:port)")

	// Processor configuration
	ProcessCmd.Flags().StringVarP(&upstreamAddr, "upstream", "u", "", "Upstream processor address for hierarchical mode (host:port)")
	ProcessCmd.Flags().IntVarP(&maxHunters, "max-hunters", "m", 100, "Maximum number of concurrent hunter connections")
	ProcessCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "Write received packets to PCAP file")
	ProcessCmd.Flags().BoolVarP(&displayStats, "stats", "s", true, "Display statistics")
	ProcessCmd.Flags().BoolVarP(&enableDetection, "enable-detection", "d", true, "Enable centralized protocol detection (default: true)")

	// Bind to viper for config file support
	viper.BindPFlag("processor.listen_addr", ProcessCmd.Flags().Lookup("listen"))
	viper.BindPFlag("processor.upstream_addr", ProcessCmd.Flags().Lookup("upstream"))
	viper.BindPFlag("processor.max_hunters", ProcessCmd.Flags().Lookup("max-hunters"))
	viper.BindPFlag("processor.write_file", ProcessCmd.Flags().Lookup("write-file"))
	viper.BindPFlag("processor.display_stats", ProcessCmd.Flags().Lookup("stats"))
	viper.BindPFlag("processor.enable_detection", ProcessCmd.Flags().Lookup("enable-detection"))
}

func runProcess(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in processor mode")

	// Get configuration (flags override config file)
	config := processor.Config{
		ListenAddr:      getStringConfig("processor.listen_addr", listenAddr),
		UpstreamAddr:    getStringConfig("processor.upstream_addr", upstreamAddr),
		MaxHunters:      getIntConfig("processor.max_hunters", maxHunters),
		WriteFile:       getStringConfig("processor.write_file", writeFile),
		DisplayStats:    getBoolConfig("processor.display_stats", displayStats),
		EnableDetection: getBoolConfig("processor.enable_detection", enableDetection),
	}

	// Validate configuration
	if config.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("Processor configuration",
		"mode", mode,
		"listen", config.ListenAddr,
		"upstream", config.UpstreamAddr,
		"max_hunters", config.MaxHunters,
		"write_file", config.WriteFile,
		"enable_detection", config.EnableDetection)

	// Create processor instance
	p, err := processor.New(config)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start processor in background
	errChan := make(chan error, 1)
	go func() {
		if err := p.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	logger.Info("Processor started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Optionally start stats display
	var statsTicker *time.Ticker
	if config.DisplayStats {
		statsTicker = time.NewTicker(5 * time.Second)
		defer statsTicker.Stop()

		go func() {
			for range statsTicker.C {
				stats := p.GetStats()
				logger.Info("Processor stats",
					"hunters_connected", stats.TotalHunters,
					"packets_received", stats.TotalPacketsReceived,
					"packets_forwarded", stats.TotalPacketsForwarded,
					"active_filters", stats.TotalFilters)
			}
		}()
	}

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("Received shutdown signal", "signal", sig)
		cancel()
		// Give some time for graceful shutdown
		time.Sleep(2 * time.Second)
	case err := <-errChan:
		logger.Error("Processor failed", "error", err)
		return err
	}

	logger.Info("Processor stopped")
	return nil
}

// Helper functions to get config values with fallback to flags
func getStringConfig(key, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return viper.GetString(key)
}

func getIntConfig(key string, flagValue int) int {
	// Simplified version without circular reference
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return flagValue
}

func getBoolConfig(key string, flagValue bool) bool {
	// Simplified version without circular reference
	if viper.IsSet(key) {
		return viper.GetBool(key)
	}
	return flagValue
}
