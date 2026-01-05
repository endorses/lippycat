//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Email-specific flags for hunter mode
	hunterEmailPorts string
)

var emailHuntCmd = &cobra.Command{
	Use:   "email",
	Short: "Run as Email hunter with SMTP filtering",
	Long: `Run lippycat in Email hunter mode with packet forwarding.

Email hunter mode captures SMTP traffic and forwards it to the
processor for analysis and correlation.

Features:
- SMTP command/response capture
- Port filtering (default: 25, 587, 465)
- Efficient forwarding to processor

Note: Email address filtering is managed by the processor and pushed to hunters.

Example:
  lc hunt email --processor processor:50051
  lc hunt email --processor 192.168.1.100:50051 --interface eth0
  lc hunt email --processor processor:50051 --smtp-port 25,587,2525`,
	RunE: runEmailHunt,
}

func init() {
	HuntCmd.AddCommand(emailHuntCmd)

	// Email-specific flags (BPF-level filtering only)
	// Note: Application-level email filtering is managed by the processor and pushed to hunters
	emailHuntCmd.Flags().StringVar(&hunterEmailPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")

	// Bind to viper
	_ = viper.BindPFlag("hunter.email.ports", emailHuntCmd.Flags().Lookup("smtp-port"))
}

func runEmailHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in Email hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build email filter
	filterBuilder := email.NewFilterBuilder()
	ports, err := email.ParsePorts(hunterEmailPorts)
	if err != nil {
		return fmt.Errorf("invalid --smtp-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := email.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("Email BPF filter configured",
		"ports", hunterEmailPorts,
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
		// Email hunter supports BPF, IP, email address, and email subject filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"},
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
		logger.Info("  Security: TLS ENABLED ✓")
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

	logger.Info("Email Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"smtp_ports", hunterEmailPorts)

	// Create hunter instance
	// Note: Email address filtering is managed by the processor and pushed to hunters via gRPC
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
		logger.Info("Shutdown signal received, stopping Email hunter...")
		return nil
	}
}
