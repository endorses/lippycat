//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// DNS-specific flags
	dnsTapPorts         string
	dnsTapUDPOnly       bool
	dnsTapDomainPattern string
	dnsTapDomainsFile   string
)

var dnsTapCmd = &cobra.Command{
	Use:   "dns",
	Short: "Standalone DNS capture with full processor capabilities",
	Long: `Run lippycat in standalone DNS tap mode.

DNS tap mode combines local DNS-optimized capture with full processor capabilities:
- Captures and analyzes DNS queries and responses from local interfaces
- Provides auto-rotating PCAP writing
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode
- DNS tunneling detection

This is ideal for single-machine DNS capture where you want:
- Real-time DNS monitoring via TUI
- Auto-rotating PCAP files for continuous capture
- DNS tunneling detection

Example:
  lc tap dns --interface eth0 --insecure
  lc tap dns -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/dns/pcaps
  lc tap dns -i eth0 --dns-port 53,5353 --udp-only`,
	RunE: runDNSTap,
}

func init() {
	TapCmd.AddCommand(dnsTapCmd)

	// DNS-specific flags
	dnsTapCmd.Flags().StringVar(&dnsTapPorts, "dns-port", "53", "DNS port(s) to capture, comma-separated (default: 53)")
	dnsTapCmd.Flags().BoolVar(&dnsTapUDPOnly, "udp-only", false, "Capture UDP DNS only (ignore TCP DNS)")
	dnsTapCmd.Flags().StringVar(&dnsTapDomainPattern, "domain", "", "Filter by domain pattern (glob-style, e.g., '*.example.com')")
	dnsTapCmd.Flags().StringVar(&dnsTapDomainsFile, "domains-file", "", "Load domain patterns from file (one per line, # for comments)")

	// Bind DNS-specific flags to viper
	_ = viper.BindPFlag("tap.dns.ports", dnsTapCmd.Flags().Lookup("dns-port"))
	_ = viper.BindPFlag("tap.dns.udp_only", dnsTapCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("tap.dns.domain_pattern", dnsTapCmd.Flags().Lookup("domain"))
	_ = viper.BindPFlag("tap.dns.domains_file", dnsTapCmd.Flags().Lookup("domains-file"))
}

func runDNSTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone DNS tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("tap.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build DNS filter
	filterBuilder := dns.NewFilterBuilder()
	ports, err := dns.ParsePorts(dnsTapPorts)
	if err != nil {
		return fmt.Errorf("invalid --dns-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
	filterConfig := dns.FilterConfig{
		Ports:      ports,
		UDPOnly:    dnsTapUDPOnly,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	// Get domain pattern for filtering
	domainPattern := getStringConfig("tap.dns.domain_pattern", dnsTapDomainPattern)
	domainsFile := getStringConfig("tap.dns.domains_file", dnsTapDomainsFile)

	// Store domain pattern in viper for processor-level DNS filtering
	if domainPattern != "" {
		viper.Set("dns.domain_pattern", domainPattern)
	}

	// Load additional patterns from file if specified
	if domainsFile != "" {
		filePatterns, err := dns.LoadDomainsFromFile(domainsFile)
		if err != nil {
			return fmt.Errorf("failed to load domains file: %w", err)
		}
		viper.Set("dns.domain_patterns", filePatterns)
		logger.Info("Loaded domain patterns from file", "count", len(filePatterns), "file", domainsFile)
	}

	logger.Info("DNS BPF filter configured",
		"udp_only", dnsTapUDPOnly,
		"ports", dnsTapPorts,
		"domain_pattern", domainPattern,
		"domains_file", domainsFile,
		"effective_filter", effectiveBPFFilter)

	// Build auto-rotate PCAP config - default for DNS mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := getBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// DNS mode should default to auto-rotate PCAP enabled
		effectiveAutoRotate = true
	}

	if effectiveAutoRotate {
		idleTimeoutStr := getStringConfig("tap.auto_rotate_pcap.idle_timeout", autoRotatePcapIdleTimeout)
		idleTimeout, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			idleTimeout = 5 * time.Minute
		}

		maxSizeStr := getStringConfig("tap.auto_rotate_pcap.max_size", autoRotatePcapMaxSize)
		maxSize, err := parseSizeString(maxSizeStr)
		if err != nil {
			maxSize = 100 * 1024 * 1024 // 100MB default
		}

		autoRotateConfig = &processor.AutoRotateConfig{
			Enabled:      true,
			OutputDir:    getStringConfig("tap.auto_rotate_pcap.output_dir", autoRotatePcapDir),
			FilePattern:  getStringConfig("tap.auto_rotate_pcap.file_pattern", autoRotatePcapPattern),
			MaxIdleTime:  idleTimeout,
			MaxFileSize:  maxSize,
			MaxDuration:  1 * time.Hour,
			MinDuration:  10 * time.Second,
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		}
	}

	// Build auth config if enabled
	var authConfig *auth.Config
	if getBoolConfig("security.api_keys.enabled", apiKeyAuthEnabled) {
		var apiKeys []auth.APIKey
		if err := viper.UnmarshalKey("security.api_keys.keys", &apiKeys); err != nil {
			return fmt.Errorf("failed to load API keys from config: %w", err)
		}

		if len(apiKeys) == 0 {
			return fmt.Errorf("API key authentication enabled but no keys configured")
		}

		authConfig = &auth.Config{
			Enabled: true,
			APIKeys: apiKeys,
		}
	}

	// Set default tap ID
	effectiveTapID := getStringConfig("tap.tap_id", tapID)
	if effectiveTapID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		effectiveTapID = hostname + "-dns-tap"
	}

	// Build processor configuration
	config := processor.Config{
		ListenAddr:            getStringConfig("tap.listen_addr", listenAddr),
		ProcessorID:           effectiveTapID,
		UpstreamAddr:          getStringConfig("tap.upstream_addr", upstreamAddr),
		MaxHunters:            0,
		MaxSubscribers:        getIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             getStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		AutoRotateConfig:      autoRotateConfig,
		EnableDetection:       true, // Enable protocol detection for DNS
		TLSEnabled:            getBoolConfig("tap.tls.enabled", tlsEnabled),
		TLSCertFile:           getStringConfig("tap.tls.cert_file", tlsCertFile),
		TLSKeyFile:            getStringConfig("tap.tls.key_file", tlsKeyFile),
		TLSCAFile:             getStringConfig("tap.tls.ca_file", tlsCAFile),
		TLSClientAuth:         getBoolConfig("tap.tls.client_auth", tlsClientAuth),
		AuthConfig:            authConfig,
		VirtualInterface:      getBoolConfig("tap.virtual_interface", virtualInterface),
		VirtualInterfaceName:  getStringConfig("tap.vif_name", virtualInterfaceName),
		VirtualInterfaceType:  getStringConfig("tap.vif_type", vifType),
		VifBufferSize:         getIntConfig("tap.vif_buffer_size", vifBufferSize),
		VifNetNS:              getStringConfig("tap.vif_netns", vifNetNS),
		VifDropPrivilegesUser: getStringConfig("tap.vif_drop_privileges", vifDropPrivileges),
	}

	// Security check
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Management interface will accept UNENCRYPTED connections")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		authMode := "Server TLS"
		if config.TLSClientAuth {
			authMode = "Mutual TLS (client certs required)"
		}
		logger.Info("Security: TLS ENABLED, Mode: " + authMode)
	}

	// Create processor instance
	p, err := processor.New(config)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	// Create LocalSource for local packet capture with DNS filter
	localSourceConfig := source.LocalSourceConfig{
		Interfaces:   getStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    effectiveBPFFilter,
		BatchSize:    getIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(getIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   getIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
	}
	localSource := source.NewLocalSource(localSourceConfig)

	// Create LocalTarget for local filtering
	localTargetConfig := filtering.LocalTargetConfig{
		BaseBPF: effectiveBPFFilter,
	}
	localTarget := filtering.NewLocalTarget(localTargetConfig)

	// Wire LocalTarget to LocalSource for BPF filter updates
	localTarget.SetBPFUpdater(localSource)

	// Set the local source and target on the processor
	p.SetPacketSource(localSource)
	p.SetFilterTarget(localTarget)

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("DNS Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"dns_ports", dnsTapPorts,
		"udp_only", dnsTapUDPOnly,
		"domain_pattern", domainPattern,
		"auto_rotate_pcap", effectiveAutoRotate,
		"listen", config.ListenAddr)

	// Set up context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	cleanup := signals.SetupHandler(ctx, cancel)
	defer cleanup()

	// Start processor in background
	errChan := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		if err := p.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	logger.Info("DNS Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("DNS Tap node failed", "error", err)
		return err
	}

	logger.Info("DNS Tap node stopped")
	return nil
}
