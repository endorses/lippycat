//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// TLS-specific flags
	tlsTapPorts      string
	tlsTapSNIPattern string
	tlsTapSNIFile    string
)

var tlsTapCmd = &cobra.Command{
	Use:   "tls",
	Short: "Standalone TLS capture with full processor capabilities",
	Long: `Run lippycat in standalone TLS tap mode.

TLS tap mode combines local TLS-optimized capture with full processor capabilities:
- Captures and analyzes TLS handshakes from local interfaces
- JA3/JA3S/JA4 fingerprint calculation
- SNI extraction and filtering
- Provides auto-rotating PCAP writing
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode

This is ideal for single-machine TLS capture where you want:
- Real-time TLS monitoring via TUI
- Auto-rotating PCAP files for continuous capture
- Fingerprint-based analysis

Example:
  lc tap tls --interface eth0 --insecure
  lc tap tls -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/tls/pcaps
  lc tap tls -i eth0 --tls-port 443,8443 --sni "*.example.com"`,
	RunE: runTLSTap,
}

func init() {
	TapCmd.AddCommand(tlsTapCmd)

	// TLS-specific flags
	tlsTapCmd.Flags().StringVar(&tlsTapPorts, "tls-port", "443", "TLS port(s) to capture, comma-separated (default: 443)")
	tlsTapCmd.Flags().StringVar(&tlsTapSNIPattern, "sni", "", "Filter by SNI pattern (glob-style, e.g., '*.example.com')")
	tlsTapCmd.Flags().StringVar(&tlsTapSNIFile, "sni-file", "", "Load SNI patterns from file (one per line)")

	// Bind TLS-specific flags to viper
	_ = viper.BindPFlag("tap.tls.ports", tlsTapCmd.Flags().Lookup("tls-port"))
	_ = viper.BindPFlag("tap.tls.sni_pattern", tlsTapCmd.Flags().Lookup("sni"))
	_ = viper.BindPFlag("tap.tls.sni_file", tlsTapCmd.Flags().Lookup("sni-file"))
}

func runTLSTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone TLS tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("tap.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build TLS filter
	filterBuilder := tls.NewFilterBuilder()
	ports, err := tls.ParsePorts(tlsTapPorts)
	if err != nil {
		return fmt.Errorf("invalid --tls-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
	filterConfig := tls.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	// Get SNI pattern for filtering
	sniPattern := getStringConfig("tap.tls.sni_pattern", tlsTapSNIPattern)
	sniFile := getStringConfig("tap.tls.sni_file", tlsTapSNIFile)

	// Store SNI pattern in viper for processor-level TLS filtering
	if sniPattern != "" {
		viper.Set("tls.sni_pattern", sniPattern)
	}

	// Load additional patterns from file if specified
	if sniFile != "" {
		filePatterns, err := tls.LoadSNIPatternsFromFile(sniFile)
		if err != nil {
			return fmt.Errorf("failed to load SNI file: %w", err)
		}
		viper.Set("tls.sni_patterns", filePatterns)
		logger.Info("Loaded SNI patterns from file", "count", len(filePatterns), "file", sniFile)
	}

	logger.Info("TLS BPF filter configured",
		"ports", tlsTapPorts,
		"sni_pattern", sniPattern,
		"sni_file", sniFile,
		"effective_filter", effectiveBPFFilter)

	// Build auto-rotate PCAP config - default for TLS mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := getBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// TLS mode should default to auto-rotate PCAP enabled
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
		effectiveTapID = hostname + "-tls-tap"
	}

	// Build processor configuration
	config := processor.Config{
		ListenAddr:            getStringConfig("tap.listen_addr", listenAddr),
		ProcessorID:           effectiveTapID,
		UpstreamAddr:          getStringConfig("tap.processor_addr", processorAddr),
		MaxHunters:            0,
		MaxSubscribers:        getIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             getStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		AutoRotateConfig:      autoRotateConfig,
		EnableDetection:       true, // Enable protocol detection for TLS
		FilterFile:            getStringConfig("tap.filter_file", filterFile),
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

	// Create LocalSource for local packet capture with TLS filter
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

	// Create ApplicationFilter for content filtering (same as hunt mode)
	appFilter, err := hunter.NewApplicationFilter(nil)
	if err != nil {
		return fmt.Errorf("failed to create application filter: %w", err)
	}

	// Wire ApplicationFilter to both LocalSource and LocalTarget
	// - LocalSource uses it to filter packets before batching (like hunt does)
	// - LocalTarget uses it to update filters when management API changes them
	localSource.SetApplicationFilter(appFilter)
	localTarget.SetApplicationFilter(appFilter)

	// Set the local source and target on the processor
	p.SetPacketSource(localSource)
	p.SetFilterTarget(localTarget)

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("TLS Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"tls_ports", tlsTapPorts,
		"sni_pattern", sniPattern,
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

	logger.Info("TLS Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("TLS Tap node failed", "error", err)
		return err
	}

	logger.Info("TLS Tap node stopped")
	return nil
}
