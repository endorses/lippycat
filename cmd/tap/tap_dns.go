//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
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
	dnsTapPorts           string
	dnsTapUDPOnly         bool
	dnsTapDomainPattern   string
	dnsTapDomainsFile     string
	dnsTapDetectTunneling bool
	// DNS tunneling detection command hook flags
	dnsTunnelingCommand   string
	dnsTunnelingThreshold float64
	dnsTunnelingDebounce  string
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
	dnsTapCmd.Flags().BoolVar(&dnsTapDetectTunneling, "detect-tunneling", true, "Enable DNS tunneling detection")

	// DNS tunneling detection command hook
	dnsTapCmd.Flags().StringVar(&dnsTunnelingCommand, "tunneling-command", "", "Command to execute when DNS tunneling detected (supports %domain%, %score%, %entropy%, %queries%, %srcips%, %hunter%, %timestamp%)")
	dnsTapCmd.Flags().Float64Var(&dnsTunnelingThreshold, "tunneling-threshold", 0.7, "DNS tunneling score threshold for triggering command (0.0-1.0)")
	dnsTapCmd.Flags().StringVar(&dnsTunnelingDebounce, "tunneling-debounce", "5m", "Minimum time between alerts per domain (e.g., 5m, 30s)")

	// Bind DNS-specific flags to viper
	_ = viper.BindPFlag("tap.dns.ports", dnsTapCmd.Flags().Lookup("dns-port"))
	_ = viper.BindPFlag("tap.dns.udp_only", dnsTapCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("tap.dns.domain_pattern", dnsTapCmd.Flags().Lookup("domain"))
	_ = viper.BindPFlag("tap.dns.domains_file", dnsTapCmd.Flags().Lookup("domains-file"))
	_ = viper.BindPFlag("dns.detect_tunneling", dnsTapCmd.Flags().Lookup("detect-tunneling"))
	// DNS tunneling detection viper bindings
	_ = viper.BindPFlag("processor.tunneling_command", dnsTapCmd.Flags().Lookup("tunneling-command"))
	_ = viper.BindPFlag("processor.tunneling_threshold", dnsTapCmd.Flags().Lookup("tunneling-threshold"))
	_ = viper.BindPFlag("processor.tunneling_debounce", dnsTapCmd.Flags().Lookup("tunneling-debounce"))
}

func runDNSTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone DNS tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build DNS filter
	filterBuilder := dns.NewFilterBuilder()
	ports, err := dns.ParsePorts(dnsTapPorts)
	if err != nil {
		return fmt.Errorf("invalid --dns-port value: %w", err)
	}

	baseBPFFilter := cmdutil.GetStringConfig("tap.bpf_filter", bpfFilter)
	filterConfig := dns.FilterConfig{
		Ports:      ports,
		UDPOnly:    dnsTapUDPOnly,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	// Get domain pattern for filtering
	domainPattern := cmdutil.GetStringConfig("tap.dns.domain_pattern", dnsTapDomainPattern)
	domainsFile := cmdutil.GetStringConfig("tap.dns.domains_file", dnsTapDomainsFile)

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

	// Set tunneling detection config for processor-level DNS analysis
	detectTunneling := cmdutil.GetBoolConfig("dns.detect_tunneling", dnsTapDetectTunneling)
	viper.Set("dns.detect_tunneling", detectTunneling)

	logger.Info("DNS BPF filter configured",
		"udp_only", dnsTapUDPOnly,
		"ports", dnsTapPorts,
		"domain_pattern", domainPattern,
		"domains_file", domainsFile,
		"detect_tunneling", detectTunneling,
		"effective_filter", effectiveBPFFilter)

	// Build auto-rotate PCAP config - default for DNS mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := cmdutil.GetBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// DNS mode should default to auto-rotate PCAP enabled
		effectiveAutoRotate = true
	}

	if effectiveAutoRotate {
		idleTimeoutStr := cmdutil.GetStringConfig("tap.auto_rotate_pcap.idle_timeout", autoRotatePcapIdleTimeout)
		idleTimeout, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			idleTimeout = 5 * time.Minute
		}

		maxSizeStr := cmdutil.GetStringConfig("tap.auto_rotate_pcap.max_size", autoRotatePcapMaxSize)
		maxSize, err := cmdutil.ParseSizeString(maxSizeStr)
		if err != nil {
			maxSize = 100 * 1024 * 1024 // 100MB default
		}

		autoRotateConfig = &processor.AutoRotateConfig{
			Enabled:      true,
			OutputDir:    cmdutil.GetStringConfig("tap.auto_rotate_pcap.output_dir", autoRotatePcapDir),
			FilePattern:  cmdutil.GetStringConfig("tap.auto_rotate_pcap.file_pattern", autoRotatePcapPattern),
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
	if cmdutil.GetBoolConfig("security.api_keys.enabled", apiKeyAuthEnabled) {
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
	effectiveTapID := cmdutil.GetStringConfig("tap.tap_id", tapID)
	if effectiveTapID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		effectiveTapID = hostname + "-dns-tap"
	}

	// Build command executor config if tunneling command is configured
	var commandExecutorConfig *processor.CommandExecutorConfig
	tunnelingCmd := cmdutil.GetStringConfig("processor.tunneling_command", dnsTunnelingCommand)
	if tunnelingCmd != "" {
		commandExecutorConfig = &processor.CommandExecutorConfig{
			TunnelingCommand: tunnelingCmd,
			Timeout:          30 * time.Second,
			Concurrency:      10,
		}
	}

	// Parse tunneling debounce duration
	var tunnelingDebounceDuration time.Duration
	tunnelingDebounceStr := cmdutil.GetStringConfig("processor.tunneling_debounce", dnsTunnelingDebounce)
	if tunnelingDebounceStr != "" {
		var err error
		tunnelingDebounceDuration, err = time.ParseDuration(tunnelingDebounceStr)
		if err != nil {
			return fmt.Errorf("invalid tunneling-debounce: %w", err)
		}
	}

	// Build processor configuration
	config := processor.Config{
		ListenAddr:            cmdutil.GetStringConfig("tap.listen_addr", listenAddr),
		ProcessorID:           effectiveTapID,
		UpstreamAddr:          cmdutil.GetStringConfig("tap.processor_addr", processorAddr),
		MaxHunters:            0,
		MaxSubscribers:        cmdutil.GetIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             cmdutil.GetStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		AutoRotateConfig:      autoRotateConfig,
		CommandExecutorConfig: commandExecutorConfig,
		TunnelingThreshold:    cmdutil.GetFloat64Config("processor.tunneling_threshold", dnsTunnelingThreshold),
		TunnelingDebounce:     tunnelingDebounceDuration,
		EnableDetection:       true, // Enable protocol detection for DNS
		FilterFile:            cmdutil.GetStringConfig("tap.filter_file", filterFile),
		TLSEnabled:            !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:           cmdutil.GetStringConfig("tap.tls.cert_file", tlsCertFile),
		TLSKeyFile:            cmdutil.GetStringConfig("tap.tls.key_file", tlsKeyFile),
		TLSCAFile:             cmdutil.GetStringConfig("tap.tls.ca_file", tlsCAFile),
		TLSClientAuth:         cmdutil.GetBoolConfig("tap.tls.client_auth", tlsClientAuth),
		AuthConfig:            authConfig,
		VirtualInterface:      cmdutil.GetBoolConfig("tap.virtual_interface", virtualInterface),
		VirtualInterfaceName:  cmdutil.GetStringConfig("tap.vif_name", virtualInterfaceName),
		VirtualInterfaceType:  cmdutil.GetStringConfig("tap.vif_type", vifType),
		VifBufferSize:         cmdutil.GetIntConfig("tap.vif_buffer_size", vifBufferSize),
		VifNetNS:              cmdutil.GetStringConfig("tap.vif_netns", vifNetNS),
		VifDropPrivilegesUser: cmdutil.GetStringConfig("tap.vif_drop_privileges", vifDropPrivileges),
	}

	// Security check: TLS is enabled by default, require cert/key when enabled
	if config.TLSEnabled && (config.TLSCertFile == "" || config.TLSKeyFile == "") {
		return fmt.Errorf("TLS is enabled by default but certificate/key not provided\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
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

	// Apply own-traffic BPF exclusion
	exclusionFilter := buildOwnTrafficExclusionFilter(config.ListenAddr, config.UpstreamAddr)
	effectiveBPFFilter = combineFiltersWithExclusion(effectiveBPFFilter, exclusionFilter)

	if exclusionFilter != "" {
		logger.Info("Own-traffic BPF exclusion applied",
			"exclusion", exclusionFilter,
			"effective_filter", effectiveBPFFilter)
	}

	// Create LocalSource for local packet capture with DNS filter
	localSourceConfig := source.LocalSourceConfig{
		Interfaces:   cmdutil.GetStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    effectiveBPFFilter,
		BatchSize:    cmdutil.GetIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(cmdutil.GetIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   cmdutil.GetIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
		ProcessorID:  effectiveTapID, // For virtual hunter ID generation
		ProtocolMode: "dns",
	}
	localSource := source.NewLocalSource(localSourceConfig)

	// Create LocalTarget for local filtering
	localTargetConfig := filtering.LocalTargetConfig{
		BaseBPF: effectiveBPFFilter,
	}
	localTarget := filtering.NewLocalTarget(localTargetConfig)

	// Wire LocalTarget to LocalSource for BPF filter updates
	localTarget.SetBPFUpdater(localSource)

	// Create ApplicationFilter for content filtering (same as hunt mode)
	appFilter, err := createApplicationFilter()
	if err != nil {
		return err
	}

	// Wire ApplicationFilter to both LocalSource and LocalTarget
	// - LocalSource uses it to filter packets before batching (like hunt does)
	// - LocalTarget uses it to update filters when management API changes them
	localSource.SetApplicationFilter(appFilter)
	localTarget.SetApplicationFilter(appFilter)

	// Wire DNS processor for DNS parsing and tunneling detection
	// dns.detect_tunneling is already set in viper above
	dnsProcessor := source.NewDNSProcessorFromViper()
	localSource.SetDNSProcessor(dnsProcessor)

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
