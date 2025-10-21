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
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var voipHuntCmd = &cobra.Command{
	Use:   "voip",
	Short: "Run as VoIP hunter with call buffering",
	Long: `Run lippycat in VoIP hunter mode with packet buffering and call filtering.

VoIP hunter mode captures SIP/RTP packets, buffers them until the call can be
identified, then applies filters received from the processor. Only matched calls
are forwarded, reducing bandwidth and storage.

Features:
- SIP header extraction (From, To, P-Asserted-Identity)
- SDP parsing for RTP port discovery
- Per-call packet buffering (SIP + RTP)
- Filter matching using processor-provided filters
- Selective forwarding (only matched calls)

Filters are managed centrally by the processor and pushed to hunters via
the filter subscription mechanism. Use the processor's management API or
filter file to configure which SIP users to track.

Example:
  lc hunt voip --processor processor:50051
  lc hunt voip --processor 192.168.1.100:50051 --interface eth0`,
	RunE: runVoIPHunt,
}

func init() {
	HuntCmd.AddCommand(voipHuntCmd)
	// No voip-specific flags - filters come from processor
}

func runVoIPHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in VoIP hunter mode")
	logger.Info("VoIP filters will be received from processor via filter subscription")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Get configuration (reuse flags from parent command)
	config := hunter.Config{
		ProcessorAddr:    getStringConfig("hunter.processor_addr", processorAddr),
		HunterID:         getStringConfig("hunter.hunter_id", hunterID),
		Interfaces:       getStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:        getStringConfig("hunter.bpf_filter", bpfFilter),
		BufferSize:       getIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:        getIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:     time.Duration(getIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize:   getIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:         true, // VoIP hunter mode (with call buffering)
		EnableVoIPFilter: true, // Always enable VoIP filtering in voip mode
		GPUBackend:       getStringConfig("hunter.voip_filter.gpu_backend", gpuBackend),
		GPUBatchSize:     getIntConfig("hunter.voip_filter.gpu_batch_size", gpuBatchSize),
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

	logger.Info("VoIP Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces)

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

	// Initialize VoIP buffer manager
	bufferMgr := voip.NewBufferManager(5*time.Second, 200)
	defer bufferMgr.Close()

	logger.Info("VoIP buffer manager initialized", "max_age", "5s", "max_size", 200)

	// Start hunter in background with VoIP buffering wrapper
	errChan := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		if err := runVoIPHunterWithBuffering(ctx, h, bufferMgr); err != nil {
			errChan <- err
		}
	}()

	// Wait for error or context cancellation
	select {
	case err := <-errChan:
		return fmt.Errorf("hunter error: %w", err)
	case <-ctx.Done():
		logger.Info("Shutdown signal received, stopping VoIP hunter...")
		return nil
	}
}

// runVoIPHunterWithBuffering wraps hunter packet processing with VoIP buffering and TCP reassembly
func runVoIPHunterWithBuffering(ctx context.Context, h *hunter.Hunter, bufferMgr *voip.BufferManager) error {
	// Create TCP SIP handler for hunter mode
	tcpHandler := voip.NewHunterForwardHandler(h, bufferMgr)

	// Create TCP stream factory with hunter handler
	// The factory will be automatically cleaned up when context is cancelled
	_ = voip.NewSipStreamFactory(ctx, tcpHandler)

	// Create VoIP packet processor for UDP buffering
	// This handles UDP SIP/RTP packets with buffering and filtering
	processor := voip.NewVoIPPacketProcessor(h, bufferMgr)
	h.SetPacketProcessor(processor)

	logger.Info("VoIP hunter initialized with complete buffering support",
		"tcp_handler", "HunterForwardHandler",
		"udp_handler", "UDPPacketHandler",
		"buffer_manager", "enabled",
		"features", "TCP SIP reassembly, UDP SIP buffering, UDP RTP buffering")

	// Start the hunter's normal operation
	// The hunter will capture packets and forward them via its existing pipeline:
	// - TCP SIP packets: reassembled by tcpassembly, filtered by HunterForwardHandler
	// - UDP SIP packets: buffered by UDPPacketHandler until filter decision
	// - UDP RTP packets: buffered by UDPPacketHandler, associated with SIP calls
	if err := h.Start(ctx); err != nil {
		return fmt.Errorf("failed to start hunter: %w", err)
	}

	// Block until context is done
	<-ctx.Done()
	return nil
}
