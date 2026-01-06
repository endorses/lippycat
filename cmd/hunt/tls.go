//go:build hunter || all

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
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// TLS-specific flags for hunter mode
	hunterTLSPorts string
)

var tlsHuntCmd = &cobra.Command{
	Use:   "tls",
	Short: "Run as TLS hunter with fingerprint filtering",
	Long: `Run lippycat in TLS hunter mode with packet forwarding.

TLS hunter mode captures TLS handshakes and forwards them to the processor
for analysis, including JA3/JA3S/JA4 fingerprinting.

Features:
- TLS ClientHello/ServerHello capture
- Port filtering (default: 443)
- JA3/JA3S/JA4 fingerprint extraction
- Efficient forwarding to processor

Note: SNI and fingerprint filtering is managed by the processor and pushed to hunters.

Example:
  lc hunt tls --processor processor:50051
  lc hunt tls --processor 192.168.1.100:50051 --interface eth0
  lc hunt tls --processor processor:50051 --tls-port 443,8443`,
	RunE: runTLSHunt,
}

func init() {
	HuntCmd.AddCommand(tlsHuntCmd)

	// TLS-specific flags (BPF-level filtering only)
	// Note: SNI and fingerprint filtering is managed by the processor and pushed to hunters
	tlsHuntCmd.Flags().StringVar(&hunterTLSPorts, "tls-port", "443", "TLS port(s) to capture, comma-separated (default: 443)")

	// Bind to viper
	_ = viper.BindPFlag("hunter.tls.ports", tlsHuntCmd.Flags().Lookup("tls-port"))
}

func runTLSHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in TLS hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build TLS filter
	filterBuilder := tls.NewFilterBuilder()
	ports, err := tls.ParsePorts(hunterTLSPorts)
	if err != nil {
		return fmt.Errorf("invalid --tls-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := tls.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("TLS BPF filter configured",
		"ports", hunterTLSPorts,
		"effective_filter", effectiveBPFFilter)

	// Get configuration (reuse flags from parent command)
	config := hunter.Config{
		ProcessorAddr:  getStringConfig("hunter.processor_addr", processorAddr),
		HunterID:       getStringConfig("hunter.hunter_id", hunterID),
		Interfaces:     getStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:      effectiveBPFFilter,
		BufferSize:     getIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:      getIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:   time.Duration(getIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize: getIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:       false, // Not VoIP mode
		// TLS hunter supports BPF, IP, and TLS-specific filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"},
		// TLS configuration
		TLSEnabled:    getBoolConfig("hunter.tls.enabled", tlsEnabled),
		TLSCertFile:   getStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify: getBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
	}

	// Security check
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-ca=/path/to/ca.crt\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Packet data will be transmitted in CLEARTEXT")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED")
		logger.Info("  All traffic to processor will be encrypted")
		logger.Info("═══════════════════════════════════════════════════════════")
	}

	// Set default hunter ID
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

	logger.Info("TLS Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"tls_ports", hunterTLSPorts)

	// Create hunter instance
	// Note: SNI and fingerprint filtering is managed by the processor and pushed to hunters via gRPC
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

	// Wait for error or context cancellation
	select {
	case err := <-errChan:
		return fmt.Errorf("hunter error: %w", err)
	case <-ctx.Done():
		logger.Info("Shutdown signal received, stopping TLS hunter...")
		return nil
	}
}
