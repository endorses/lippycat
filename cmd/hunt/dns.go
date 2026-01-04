//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

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
	hunterDNSPorts         string
	hunterDNSUDPOnly       bool
	hunterDNSDomainPattern string
	hunterDNSDomainsFile   string
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

Example:
  lc hunt dns --processor processor:50051
  lc hunt dns --processor 192.168.1.100:50051 --interface eth0
  lc hunt dns --processor processor:50051 --dns-port 53,5353`,
	RunE: runDNSHunt,
}

func init() {
	HuntCmd.AddCommand(dnsHuntCmd)

	// DNS-specific flags
	dnsHuntCmd.Flags().StringVar(&hunterDNSPorts, "dns-port", "53", "DNS port(s) to capture, comma-separated (default: 53)")
	dnsHuntCmd.Flags().BoolVar(&hunterDNSUDPOnly, "udp-only", false, "Capture UDP DNS only (ignore TCP DNS)")
	dnsHuntCmd.Flags().StringVar(&hunterDNSDomainPattern, "domain", "", "Filter by domain pattern (glob-style, e.g., '*.example.com')")
	dnsHuntCmd.Flags().StringVar(&hunterDNSDomainsFile, "domains-file", "", "Load domain patterns from file (one per line, # for comments)")

	// Bind to viper
	_ = viper.BindPFlag("hunter.dns.ports", dnsHuntCmd.Flags().Lookup("dns-port"))
	_ = viper.BindPFlag("hunter.dns.udp_only", dnsHuntCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("hunter.dns.domain_pattern", dnsHuntCmd.Flags().Lookup("domain"))
	_ = viper.BindPFlag("hunter.dns.domains_file", dnsHuntCmd.Flags().Lookup("domains-file"))
}

func runDNSHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in DNS hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build DNS filter
	filterBuilder := dns.NewFilterBuilder()
	ports, err := dns.ParsePorts(hunterDNSPorts)
	if err != nil {
		return fmt.Errorf("invalid --dns-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := dns.FilterConfig{
		Ports:      ports,
		UDPOnly:    hunterDNSUDPOnly,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("DNS BPF filter configured",
		"udp_only", hunterDNSUDPOnly,
		"ports", hunterDNSPorts,
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

	// Get domain patterns for filtering
	var domainPatterns []string
	if pattern := getStringConfig("hunter.dns.domain_pattern", hunterDNSDomainPattern); pattern != "" {
		domainPatterns = []string{pattern}
	}

	// Load additional patterns from file if specified
	domainsFile := getStringConfig("hunter.dns.domains_file", hunterDNSDomainsFile)
	if domainsFile != "" {
		filePatterns, err := dns.LoadDomainsFromFile(domainsFile)
		if err != nil {
			return fmt.Errorf("failed to load domains file: %w", err)
		}
		domainPatterns = append(domainPatterns, filePatterns...)
		logger.Info("Loaded domain patterns from file", "count", len(filePatterns), "file", domainsFile)
	}

	logger.Info("DNS Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"dns_ports", hunterDNSPorts,
		"udp_only", hunterDNSUDPOnly,
		"domain_pattern", hunterDNSDomainPattern)

	// Create hunter instance
	h, err := hunter.New(config)
	if err != nil {
		return fmt.Errorf("failed to create hunter: %w", err)
	}

	// Create DNS processor for domain filtering (if patterns configured)
	if len(domainPatterns) > 0 {
		processorConfig := dns.ProcessorConfig{
			DomainPatterns:  domainPatterns,
			TrackQueries:    true,
			DetectTunneling: false, // Disable for hunter mode (processor does this)
		}
		dnsProcessor := dns.NewProcessor(nil, processorConfig) // nil forwarder - hunter handles forwarding
		h.SetPacketProcessor(dnsProcessor)
		logger.Info("DNS domain filtering enabled",
			"patterns", domainPatterns)
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
