//go:build hunter || all
// +build hunter all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
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
	processorAddr    string
	hunterID         string
	interfaces       []string
	bpfFilter        string
	bufferSize       int
	batchSize        int
	batchTimeout     int
	promiscuous      bool
	enableVoIPFilter bool
	gpuBackend       string
	gpuBatchSize     int
	// TLS flags
	tlsEnabled      bool
	tlsCertFile     string
	tlsKeyFile      string
	tlsCAFile       string
	tlsSkipVerify   bool
	insecureAllowed bool
)

func init() {
	// Required flags (persistent so subcommands inherit them)
	HuntCmd.PersistentFlags().StringVar(&processorAddr, "processor", "", "Processor address (host:port)")
	_ = HuntCmd.MarkPersistentFlagRequired("processor") // Error only occurs with invalid flag name (hard-coded string)

	// Hunter configuration (persistent for subcommands)
	HuntCmd.PersistentFlags().StringVarP(&hunterID, "hunter-id", "", "", "Unique hunter identifier (default: hostname)")
	HuntCmd.PersistentFlags().StringSliceVarP(&interfaces, "interface", "i", []string{"any"}, "Network interfaces to capture (comma-separated)")
	HuntCmd.PersistentFlags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
	HuntCmd.PersistentFlags().BoolVarP(&promiscuous, "promisc", "p", false, "Enable promiscuous mode")

	// Performance tuning (persistent for subcommands)
	HuntCmd.PersistentFlags().IntVarP(&bufferSize, "buffer-size", "b", 10000, "Packet buffer size")
	HuntCmd.PersistentFlags().IntVarP(&batchSize, "batch-size", "", 64, "Packets per batch sent to processor")
	HuntCmd.PersistentFlags().IntVarP(&batchTimeout, "batch-timeout", "", 100, "Batch timeout in milliseconds")

	// VoIP filtering with GPU acceleration (persistent for subcommands)
	HuntCmd.PersistentFlags().BoolVar(&enableVoIPFilter, "enable-voip-filter", false, "Enable GPU-accelerated VoIP filtering")
	HuntCmd.PersistentFlags().StringVar(&gpuBackend, "gpu-backend", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd'")
	HuntCmd.PersistentFlags().IntVar(&gpuBatchSize, "gpu-batch-size", 100, "Batch size for GPU processing")

	// TLS configuration (security) - persistent for subcommands
	HuntCmd.PersistentFlags().BoolVar(&tlsEnabled, "tls", false, "Enable TLS encryption (recommended for production)")
	HuntCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert", "", "Path to client TLS certificate (for mutual TLS)")
	HuntCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key", "", "Path to client TLS key (for mutual TLS)")
	HuntCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for server verification")
	HuntCmd.PersistentFlags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (INSECURE - testing only)")
	HuntCmd.PersistentFlags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS (must be explicitly set)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("hunter.processor_addr", HuntCmd.PersistentFlags().Lookup("processor"))
	_ = viper.BindPFlag("hunter.hunter_id", HuntCmd.PersistentFlags().Lookup("hunter-id"))
	_ = viper.BindPFlag("hunter.interfaces", HuntCmd.PersistentFlags().Lookup("interface"))
	_ = viper.BindPFlag("hunter.bpf_filter", HuntCmd.PersistentFlags().Lookup("filter"))
	_ = viper.BindPFlag("hunter.buffer_size", HuntCmd.PersistentFlags().Lookup("buffer-size"))
	_ = viper.BindPFlag("hunter.batch_size", HuntCmd.PersistentFlags().Lookup("batch-size"))
	_ = viper.BindPFlag("hunter.batch_timeout_ms", HuntCmd.PersistentFlags().Lookup("batch-timeout"))
	_ = viper.BindPFlag("promiscuous", HuntCmd.PersistentFlags().Lookup("promisc"))
	_ = viper.BindPFlag("hunter.voip_filter.enabled", HuntCmd.PersistentFlags().Lookup("enable-voip-filter"))
	_ = viper.BindPFlag("hunter.voip_filter.gpu_backend", HuntCmd.PersistentFlags().Lookup("gpu-backend"))
	_ = viper.BindPFlag("hunter.voip_filter.gpu_batch_size", HuntCmd.PersistentFlags().Lookup("gpu-batch-size"))
	_ = viper.BindPFlag("hunter.tls.enabled", HuntCmd.PersistentFlags().Lookup("tls"))
	_ = viper.BindPFlag("hunter.tls.cert_file", HuntCmd.PersistentFlags().Lookup("tls-cert"))
	_ = viper.BindPFlag("hunter.tls.key_file", HuntCmd.PersistentFlags().Lookup("tls-key"))
	_ = viper.BindPFlag("hunter.tls.ca_file", HuntCmd.PersistentFlags().Lookup("tls-ca"))
	_ = viper.BindPFlag("hunter.tls.skip_verify", HuntCmd.PersistentFlags().Lookup("tls-skip-verify"))
}

func runHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in hunter mode")

	// Production mode enforcement: check early before creating config
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Get configuration (flags override config file)
	config := hunter.Config{
		ProcessorAddr:    getStringConfig("hunter.processor_addr", processorAddr),
		HunterID:         getStringConfig("hunter.hunter_id", hunterID),
		Interfaces:       getStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:        getStringConfig("hunter.bpf_filter", bpfFilter),
		BufferSize:       getIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:        getIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:     time.Duration(getIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		EnableVoIPFilter: getBoolConfig("hunter.voip_filter.enabled", enableVoIPFilter),
		GPUBackend:       getStringConfig("hunter.voip_filter.gpu_backend", gpuBackend),
		GPUBatchSize:     getIntConfig("hunter.voip_filter.gpu_batch_size", gpuBatchSize),
		// TLS configuration
		TLSEnabled:    getBoolConfig("hunter.tls.enabled", tlsEnabled),
		TLSCertFile:   getStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify: getBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
	}

	// Security check: require explicit opt-in to insecure mode
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-ca=/path/to/ca.crt\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure\n\n" +
			"WARNING: Insecure mode transmits network traffic in cleartext!")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Packet data will be transmitted in CLEARTEXT")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("  Enable TLS for production: --tls --tls-ca=/path/to/ca.crt")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED ✓")
		logger.Info("  All traffic to processor will be encrypted")
		logger.Info("═══════════════════════════════════════════════════════════")
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
	cleanup := signals.SetupHandler(ctx, cancel)
	defer cleanup()

	// Start hunter in background
	errChan := make(chan error, constants.ErrorChannelBuffer)
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
	case <-ctx.Done():
		// Signal received, give some time for graceful shutdown
		time.Sleep(constants.GracefulShutdownTimeout)
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
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return flagValue
}

func getBoolConfig(key string, flagValue bool) bool {
	if viper.IsSet(key) {
		return viper.GetBool(key)
	}
	return flagValue
}
