//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// DNS-specific flags for hunter mode
	hunterDNSPorts           string
	hunterDNSUDPOnly         bool
	hunterDNSDetectTunneling bool
)

var dnsHuntCmd = &cobra.Command{
	Use:   "dns",
	Short: "Run as DNS hunter with query filtering",
	Long: `Run lippycat in DNS hunter mode with packet forwarding.

DNS hunter mode captures DNS queries and responses and forwards
them to the processor for analysis and correlation.

Features:
- DNS query/response capture
- Port filtering (default: 53)
- UDP-only mode option
- Efficient forwarding to processor

Note: Domain filtering is managed by the processor and pushed to hunters.

Example:
  lc hunt dns --processor processor:50051
  lc hunt dns --processor 192.168.1.100:50051 --interface eth0
  lc hunt dns --processor processor:50051 --dns-port 53,5353`,
	RunE: runDNSHunt,
}

func init() {
	HuntCmd.AddCommand(dnsHuntCmd)

	// DNS-specific flags (BPF-level filtering only)
	// Note: Application-level domain filtering is managed by the processor and pushed to hunters
	dnsHuntCmd.Flags().StringVar(&hunterDNSPorts, "dns-port", "53", "DNS port(s) to capture, comma-separated (default: 53)")
	dnsHuntCmd.Flags().BoolVar(&hunterDNSUDPOnly, "udp-only", false, "Capture UDP DNS only (ignore TCP DNS)")
	dnsHuntCmd.Flags().BoolVar(&hunterDNSDetectTunneling, "detect-tunneling", true, "Enable DNS tunneling detection at edge")

	// Bind to viper
	_ = viper.BindPFlag("hunter.dns.ports", dnsHuntCmd.Flags().Lookup("dns-port"))
	_ = viper.BindPFlag("hunter.dns.udp_only", dnsHuntCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("dns.detect_tunneling", dnsHuntCmd.Flags().Lookup("detect-tunneling"))
}

func runDNSHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in DNS hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build DNS filter
	filterBuilder := dns.NewFilterBuilder()
	ports, err := dns.ParsePorts(hunterDNSPorts)
	if err != nil {
		return fmt.Errorf("invalid --dns-port value: %w", err)
	}

	baseBPFFilter := cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := dns.FilterConfig{
		Ports:      ports,
		UDPOnly:    hunterDNSUDPOnly,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	// Set tunneling detection config for hunter-side DNS analysis
	detectTunneling := cmdutil.GetBoolConfig("dns.detect_tunneling", hunterDNSDetectTunneling)
	viper.Set("dns.detect_tunneling", detectTunneling)

	logger.Info("DNS BPF filter configured",
		"udp_only", hunterDNSUDPOnly,
		"ports", hunterDNSPorts,
		"detect_tunneling", detectTunneling,
		"effective_filter", effectiveBPFFilter)

	// Get configuration (reuse flags from parent command)
	config := hunter.Config{
		ProcessorAddr:  cmdutil.GetStringConfig("hunter.processor_addr", processorAddr),
		HunterID:       cmdutil.GetStringConfig("hunter.hunter_id", hunterID),
		Interfaces:     cmdutil.GetStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:      effectiveBPFFilter,
		BufferSize:     cmdutil.GetIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:      cmdutil.GetIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:   time.Duration(cmdutil.GetIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize: cmdutil.GetIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:       false, // Not VoIP mode
		// DNS hunter supports BPF, IP, and DNS domain filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "dns_domain"},
		// TLS configuration (enabled by default unless --insecure is set)
		TLSEnabled:    !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:   cmdutil.GetStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:    cmdutil.GetStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:     cmdutil.GetStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify: cmdutil.GetBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
	}

	// Validate TLS configuration: CA file required when TLS is enabled
	if config.TLSEnabled && config.TLSCAFile == "" && !config.TLSSkipVerify {
		return fmt.Errorf("TLS enabled but no CA certificate provided\n\n" +
			"For TLS connections, provide a CA certificate: --tls-ca=/path/to/ca.crt\n" +
			"Or skip verification (INSECURE - testing only): --tls-skip-verify\n" +
			"Or disable TLS entirely (NOT RECOMMENDED): --insecure")
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

	logger.Info("DNS Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"dns_ports", hunterDNSPorts,
		"udp_only", hunterDNSUDPOnly)

	// Create hunter instance
	// Note: Domain filtering is managed by the processor and pushed to hunters via gRPC
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
		logger.Info("Shutdown signal received, stopping DNS hunter...")
		return nil
	}
}
