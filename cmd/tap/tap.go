//go:build tap || all
// +build tap all

// Package tap implements the standalone capture command that combines local packet capture
// with full processor capabilities (PCAP writing, TUI serving, upstream forwarding).
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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TapCmd is the root command for standalone tap mode.
var TapCmd = &cobra.Command{
	Use:   "tap",
	Short: "Standalone capture with full processor capabilities",
	Long: `Run lippycat in standalone tap mode.

Tap mode combines local packet capture with full processor capabilities:
- Captures packets from local network interfaces (like hunters)
- Provides management gRPC API for TUI connections (like processors)
- Writes PCAP files (unified, per-call, auto-rotating)
- Supports upstream forwarding in hierarchical mode
- No separate hunter/processor required

This is ideal for single-machine deployments where you want the full
power of the processor without the distributed architecture.

TLS is enabled by default. Use --insecure for local testing without TLS.

Examples:
  # Basic tap (insecure, local testing only)
  lc tap --interface eth0 --insecure

  # Tap with auto-rotating PCAP (insecure, local testing)
  lc tap -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/pcaps --insecure

  # Tap with upstream forwarding (hierarchical mode)
  lc tap -i eth0 --processor central-processor:50051 --tls-ca ca.crt

  # Tap with TUI serving (secure)
  lc tap -i eth0 --listen 0.0.0.0:50051 --tls-cert server.crt --tls-key server.key

  # VoIP capture with per-call PCAP (use 'tap voip' subcommand)
  lc tap voip -i eth0 --per-call-pcap --per-call-pcap-dir /var/pcaps --insecure

  # Lawful Interception (requires -tags li build)
  lc tap -i eth0 --tls-cert server.crt --tls-key server.key \
    --li-enabled \
    --li-x1-listen :8443 \
    --li-x1-tls-cert x1-server.crt --li-x1-tls-key x1-server.key \
    --li-delivery-tls-cert delivery.crt --li-delivery-tls-key delivery.key`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Handle deprecated --tap-id flag migration to --id
		if cmd.Flags().Changed("tap-id") {
			if cmd.Flags().Changed("id") {
				return fmt.Errorf("cannot use both --tap-id (deprecated) and --id; use --id only")
			}
			tapID = tapIDDeprecated
			logger.Warn("--tap-id is deprecated, use --id instead")
		}
		// Handle deprecated --upstream flag migration to --processor
		if cmd.Flags().Changed("upstream") {
			if cmd.Flags().Changed("processor") {
				return fmt.Errorf("cannot use both --upstream (deprecated) and --processor; use --processor only")
			}
			processorAddr = upstreamAddrDeprecated
			logger.Warn("--upstream is deprecated, use --processor instead")
		}
		return nil
	},
	RunE: runTap,
}

var (
	// Capture flags (from hunter)
	interfaces     []string
	bpfFilter      string
	promiscuous    bool
	pcapBufferSize int
	bufferSize     int
	batchSize      int
	batchTimeout   int

	// Management interface flags
	listenAddr      string
	tapID           string // renamed from tap-id, now --id
	tapIDDeprecated string // deprecated, use tapID
	maxSubscribers  int

	// Upstream forwarding (renamed from --upstream to --processor)
	processorAddr          string
	upstreamAddrDeprecated string // deprecated, use processorAddr

	// PCAP flags
	writeFile string

	// Auto-rotate PCAP flags
	autoRotatePcapEnabled     bool
	autoRotatePcapDir         string
	autoRotatePcapPattern     string
	autoRotatePcapIdleTimeout string
	autoRotatePcapMaxSize     string

	// Virtual interface flags
	virtualInterface     bool
	virtualInterfaceName string
	vifType              string
	vifBufferSize        int
	vifNetNS             string
	vifDropPrivileges    string

	// Command hook flags (general)
	pcapCommand        string
	commandTimeout     string
	commandConcurrency int

	// Protocol detection
	enableDetection bool

	// Filter persistence
	filterFile string

	// TLS flags (for management interface)
	// Note: TLS is enabled by default unless --insecure is set
	tlsCertFile   string
	tlsKeyFile    string
	tlsCAFile     string
	tlsClientAuth bool

	// API Key Authentication
	apiKeyAuthEnabled bool

	// Security flags
	insecureAllowed bool

	// Filter policy
	noFilterPolicy string
)

func init() {
	// ============================================================
	// Capture Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringSliceVarP(&interfaces, "interface", "i", []string{"any"}, "Network interfaces to capture (comma-separated)")
	TapCmd.PersistentFlags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
	TapCmd.PersistentFlags().BoolVarP(&promiscuous, "promisc", "p", false, "Enable promiscuous mode")
	TapCmd.PersistentFlags().IntVar(&pcapBufferSize, "pcap-buffer-size", 16*1024*1024, "Kernel pcap buffer size in bytes (default 16MB, increase for high-traffic interfaces)")
	TapCmd.PersistentFlags().IntVarP(&bufferSize, "buffer-size", "b", 10000, "Packet buffer size")
	TapCmd.PersistentFlags().IntVar(&batchSize, "batch-size", 100, "Packets per batch")
	TapCmd.PersistentFlags().IntVar(&batchTimeout, "batch-timeout", 100, "Batch timeout in milliseconds")

	// ============================================================
	// Management Interface Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringVarP(&listenAddr, "listen", "l", fmt.Sprintf(":%d", constants.DefaultGRPCPort), "Listen address for TUI connections (host:port)")
	// --id is the new flag, --tap-id is deprecated
	TapCmd.PersistentFlags().StringVarP(&tapID, "id", "I", "", "Unique tap identifier (default: hostname)")
	TapCmd.PersistentFlags().StringVar(&tapIDDeprecated, "tap-id", "", "")
	TapCmd.PersistentFlags().Lookup("tap-id").Deprecated = "use --id instead"
	TapCmd.PersistentFlags().Lookup("tap-id").Hidden = true
	TapCmd.PersistentFlags().IntVar(&maxSubscribers, "max-subscribers", constants.DefaultMaxSubscribers, "Maximum concurrent TUI subscribers (0 = unlimited)")

	// Upstream forwarding (--processor is the new name, --upstream is deprecated)
	TapCmd.PersistentFlags().StringVarP(&processorAddr, "processor", "P", "", "Upstream processor address for hierarchical mode (host:port)")
	TapCmd.PersistentFlags().StringVar(&upstreamAddrDeprecated, "upstream", "", "")
	TapCmd.PersistentFlags().Lookup("upstream").Deprecated = "use --processor instead"
	TapCmd.PersistentFlags().Lookup("upstream").Hidden = true

	// ============================================================
	// PCAP Writing Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringVarP(&writeFile, "write-file", "w", "", "Write received packets to PCAP file")

	// Auto-rotate PCAP (non-VoIP)
	TapCmd.PersistentFlags().BoolVar(&autoRotatePcapEnabled, "auto-rotate-pcap", false, "Enable auto-rotating PCAP writing for non-VoIP traffic")
	TapCmd.PersistentFlags().StringVar(&autoRotatePcapDir, "auto-rotate-pcap-dir", "./auto-rotate-pcaps", "Directory for auto-rotating PCAP files")
	TapCmd.PersistentFlags().StringVar(&autoRotatePcapPattern, "auto-rotate-pcap-pattern", "{timestamp}.pcap", "Filename pattern for auto-rotating PCAP files")
	TapCmd.PersistentFlags().StringVar(&autoRotatePcapIdleTimeout, "auto-rotate-idle-timeout", "30s", "Close PCAP file after this idle time")
	TapCmd.PersistentFlags().StringVar(&autoRotatePcapMaxSize, "auto-rotate-max-size", "100M", "Maximum PCAP file size before rotation")

	// ============================================================
	// Virtual Interface Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().BoolVarP(&virtualInterface, "virtual-interface", "V", false, "Enable virtual network interface for packet injection")
	TapCmd.PersistentFlags().StringVar(&virtualInterfaceName, "vif-name", "lc0", "Virtual interface name")
	TapCmd.PersistentFlags().StringVar(&vifType, "vif-type", "tap", "Virtual interface type: tap or tun")
	TapCmd.PersistentFlags().IntVar(&vifBufferSize, "vif-buffer-size", 65536, "Injection queue buffer size")
	TapCmd.PersistentFlags().StringVar(&vifNetNS, "vif-netns", "", "Network namespace for interface isolation")
	TapCmd.PersistentFlags().StringVar(&vifDropPrivileges, "vif-drop-privileges", "", "Drop privileges to specified user after interface creation")

	// ============================================================
	// Command Hooks Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringVar(&pcapCommand, "pcap-command", "", "Command to execute when PCAP file closes (supports %pcap% placeholder)")
	TapCmd.PersistentFlags().StringVar(&commandTimeout, "command-timeout", "30s", "Timeout for command execution")
	TapCmd.PersistentFlags().IntVar(&commandConcurrency, "command-concurrency", 10, "Maximum concurrent command executions")

	// ============================================================
	// Protocol Detection (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().BoolVarP(&enableDetection, "detect", "d", true, "Enable protocol detection")

	// ============================================================
	// Filter Persistence (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringVar(&filterFile, "filter-file", "", "Path to filter persistence file (YAML, default: ~/.config/lippycat/filters.yaml)")

	// ============================================================
	// TLS Configuration (persistent for voip subcommand)
	// TLS is enabled by default unless --insecure is set
	// ============================================================
	TapCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert", "", "Path to server TLS certificate")
	TapCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key", "", "Path to server TLS key")
	TapCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for client verification")
	TapCmd.PersistentFlags().BoolVar(&tlsClientAuth, "tls-client-auth", false, "Require client certificate authentication")

	// API Key Authentication (persistent for voip subcommand)
	TapCmd.PersistentFlags().BoolVar(&apiKeyAuthEnabled, "api-key-auth", false, "Enable API key authentication")

	// Security (persistent for voip subcommand)
	TapCmd.PersistentFlags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS")

	// ============================================================
	// Filter Policy Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringVar(&noFilterPolicy, "no-filter-policy", "allow", "Behavior when no filters are configured: 'allow' (match all) or 'deny' (match none)")

	// ============================================================
	// Viper Bindings
	// ============================================================
	// Capture configuration
	_ = viper.BindPFlag("tap.interfaces", TapCmd.PersistentFlags().Lookup("interface"))
	_ = viper.BindPFlag("tap.bpf_filter", TapCmd.PersistentFlags().Lookup("filter"))
	_ = viper.BindPFlag("tap.promiscuous", TapCmd.PersistentFlags().Lookup("promisc"))
	// Also bind to "promiscuous" for pcaptypes/live.go which reads this key
	_ = viper.BindPFlag("promiscuous", TapCmd.PersistentFlags().Lookup("promisc"))
	// Bind pcap buffer size for pcaptypes/live.go which reads this key
	_ = viper.BindPFlag("pcap_buffer_size", TapCmd.PersistentFlags().Lookup("pcap-buffer-size"))
	_ = viper.BindPFlag("tap.buffer_size", TapCmd.PersistentFlags().Lookup("buffer-size"))
	_ = viper.BindPFlag("tap.batch_size", TapCmd.PersistentFlags().Lookup("batch-size"))
	_ = viper.BindPFlag("tap.batch_timeout_ms", TapCmd.PersistentFlags().Lookup("batch-timeout"))

	// Management interface
	_ = viper.BindPFlag("tap.listen_addr", TapCmd.PersistentFlags().Lookup("listen"))
	_ = viper.BindPFlag("tap.id", TapCmd.PersistentFlags().Lookup("id"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("tap.tap_id", TapCmd.PersistentFlags().Lookup("id"))
	_ = viper.BindPFlag("tap.max_subscribers", TapCmd.PersistentFlags().Lookup("max-subscribers"))
	_ = viper.BindPFlag("tap.processor_addr", TapCmd.PersistentFlags().Lookup("processor"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("tap.upstream_addr", TapCmd.PersistentFlags().Lookup("processor"))

	// PCAP configuration
	_ = viper.BindPFlag("tap.write_file", TapCmd.PersistentFlags().Lookup("write-file"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.enabled", TapCmd.PersistentFlags().Lookup("auto-rotate-pcap"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.output_dir", TapCmd.PersistentFlags().Lookup("auto-rotate-pcap-dir"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.file_pattern", TapCmd.PersistentFlags().Lookup("auto-rotate-pcap-pattern"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.idle_timeout", TapCmd.PersistentFlags().Lookup("auto-rotate-idle-timeout"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.max_size", TapCmd.PersistentFlags().Lookup("auto-rotate-max-size"))

	// Virtual interface
	_ = viper.BindPFlag("tap.virtual_interface", TapCmd.PersistentFlags().Lookup("virtual-interface"))
	_ = viper.BindPFlag("tap.vif_name", TapCmd.PersistentFlags().Lookup("vif-name"))
	_ = viper.BindPFlag("tap.vif_type", TapCmd.PersistentFlags().Lookup("vif-type"))
	_ = viper.BindPFlag("tap.vif_buffer_size", TapCmd.PersistentFlags().Lookup("vif-buffer-size"))
	_ = viper.BindPFlag("tap.vif_netns", TapCmd.PersistentFlags().Lookup("vif-netns"))
	_ = viper.BindPFlag("tap.vif_drop_privileges", TapCmd.PersistentFlags().Lookup("vif-drop-privileges"))

	// Command hooks
	_ = viper.BindPFlag("tap.pcap_command", TapCmd.PersistentFlags().Lookup("pcap-command"))
	_ = viper.BindPFlag("tap.command_timeout", TapCmd.PersistentFlags().Lookup("command-timeout"))
	_ = viper.BindPFlag("tap.command_concurrency", TapCmd.PersistentFlags().Lookup("command-concurrency"))

	// Detection
	_ = viper.BindPFlag("tap.enable_detection", TapCmd.PersistentFlags().Lookup("detect"))

	// Filter persistence
	_ = viper.BindPFlag("tap.filter_file", TapCmd.PersistentFlags().Lookup("filter-file"))

	// TLS
	_ = viper.BindPFlag("tap.tls.cert_file", TapCmd.PersistentFlags().Lookup("tls-cert"))
	_ = viper.BindPFlag("tap.tls.key_file", TapCmd.PersistentFlags().Lookup("tls-key"))
	_ = viper.BindPFlag("tap.tls.ca_file", TapCmd.PersistentFlags().Lookup("tls-ca"))
	_ = viper.BindPFlag("tap.tls.client_auth", TapCmd.PersistentFlags().Lookup("tls-client-auth"))
	_ = viper.BindPFlag("tap.insecure", TapCmd.PersistentFlags().Lookup("insecure"))
	_ = viper.BindPFlag("security.api_keys.enabled", TapCmd.PersistentFlags().Lookup("api-key-auth"))

	// Filter policy
	_ = viper.BindPFlag("tap.no_filter_policy", TapCmd.PersistentFlags().Lookup("no-filter-policy"))
}

func runTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if getBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build auto-rotate PCAP config if enabled
	var autoRotateConfig *processor.AutoRotateConfig
	if getBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled) {
		idleTimeoutStr := getStringConfig("tap.auto_rotate_pcap.idle_timeout", autoRotatePcapIdleTimeout)
		idleTimeout, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid auto-rotate-idle-timeout: %w", err)
		}

		maxSizeStr := getStringConfig("tap.auto_rotate_pcap.max_size", autoRotatePcapMaxSize)
		maxSize, err := parseSizeString(maxSizeStr)
		if err != nil {
			return fmt.Errorf("invalid auto-rotate-max-size: %w", err)
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

	// Build command executor config if configured
	var commandExecutorConfig *processor.CommandExecutorConfig
	pcapCmd := getStringConfig("tap.pcap_command", pcapCommand)
	if pcapCmd != "" {
		timeoutStr := getStringConfig("tap.command_timeout", commandTimeout)
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("invalid command-timeout: %w", err)
		}

		commandExecutorConfig = &processor.CommandExecutorConfig{
			PcapCommand: pcapCmd,
			Timeout:     timeout,
			Concurrency: getIntConfig("tap.command_concurrency", commandConcurrency),
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

		logger.Info("API key authentication configured", "num_keys", len(apiKeys))
	}

	// Set default tap ID to hostname if not specified
	effectiveTapID := getStringConfig("tap.tap_id", tapID)
	if effectiveTapID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		effectiveTapID = hostname + "-tap"
	}

	// Build processor configuration
	config := processor.Config{
		ListenAddr:            getStringConfig("tap.listen_addr", listenAddr),
		ProcessorID:           effectiveTapID,
		UpstreamAddr:          getStringConfig("tap.processor_addr", processorAddr),
		MaxHunters:            0, // Not accepting hunters in tap mode
		MaxSubscribers:        getIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             getStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		PcapWriterConfig:      nil, // Per-call PCAP is VoIP-specific, use tap voip
		AutoRotateConfig:      autoRotateConfig,
		CommandExecutorConfig: commandExecutorConfig,
		EnableDetection:       getBoolConfig("tap.enable_detection", enableDetection),
		FilterFile:            getStringConfig("tap.filter_file", filterFile),
		// TLS configuration (TLS enabled by default unless --insecure is set)
		TLSEnabled:    !getBoolConfig("insecure", insecureAllowed),
		TLSCertFile:   getStringConfig("tap.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("tap.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("tap.tls.ca_file", tlsCAFile),
		TLSClientAuth: getBoolConfig("tap.tls.client_auth", tlsClientAuth),
		// API Key Authentication
		AuthConfig: authConfig,
		// Virtual interface configuration
		VirtualInterface:      getBoolConfig("tap.virtual_interface", virtualInterface),
		VirtualInterfaceName:  getStringConfig("tap.vif_name", virtualInterfaceName),
		VirtualInterfaceType:  getStringConfig("tap.vif_type", vifType),
		VifBufferSize:         getIntConfig("tap.vif_buffer_size", vifBufferSize),
		VifNetNS:              getStringConfig("tap.vif_netns", vifNetNS),
		VifDropPrivilegesUser: getStringConfig("tap.vif_drop_privileges", vifDropPrivileges),
	}

	// Security check: TLS is enabled by default, require cert/key when enabled
	if config.TLSEnabled && (config.TLSCertFile == "" || config.TLSKeyFile == "") {
		return fmt.Errorf("TLS is enabled by default but certificate/key not provided\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure\n\n" +
			"WARNING: Insecure mode accepts unencrypted TUI connections!")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Management interface will accept UNENCRYPTED connections")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		authMode := "Server TLS"
		if config.TLSClientAuth {
			authMode = "Mutual TLS (client certs required)"
		}
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED")
		logger.Info("  Authentication mode: " + authMode)
		logger.Info("═══════════════════════════════════════════════════════════")
	}

	// Validate configuration
	if config.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	// Create processor instance
	p, err := processor.New(config)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

	// Create LocalSource for local packet capture
	localSourceConfig := source.LocalSourceConfig{
		Interfaces:   getStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    getStringConfig("tap.bpf_filter", bpfFilter),
		BatchSize:    getIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(getIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   getIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
		ProcessorID:  effectiveTapID, // For virtual hunter ID generation
	}
	localSource := source.NewLocalSource(localSourceConfig)

	// Create LocalTarget for local BPF filtering
	localTargetConfig := filtering.LocalTargetConfig{
		BaseBPF: localSourceConfig.BPFFilter,
	}
	localTarget := filtering.NewLocalTarget(localTargetConfig)

	// Wire LocalTarget to LocalSource for BPF filter updates
	localTarget.SetBPFUpdater(localSource)

	// Create ApplicationFilter for VoIP/content filtering (same as hunt mode)
	appFilter, err := createApplicationFilter()
	if err != nil {
		return err
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

	logger.Info("Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"listen", config.ListenAddr,
		"upstream", config.UpstreamAddr,
		"enable_detection", config.EnableDetection)

	// Set up context with cancellation
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

	logger.Info("Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		// Signal received, give some time for graceful shutdown
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("Tap node failed", "error", err)
		return err
	}

	logger.Info("Tap node stopped")
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
	// Check actual config value instead of viper.IsSet() which returns true
	// for bound flags even when config file doesn't define them
	if configValue := viper.GetStringSlice(key); len(configValue) > 0 {
		return configValue
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

func getFloat64Config(key string, flagValue float64) float64 {
	if viper.IsSet(key) {
		return viper.GetFloat64(key)
	}
	return flagValue
}

// createApplicationFilter creates an ApplicationFilter with the no-filter policy applied.
// This is a shared helper for all tap subcommands to avoid duplication.
func createApplicationFilter() (*hunter.ApplicationFilter, error) {
	appFilter, err := hunter.NewApplicationFilter(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create application filter: %w", err)
	}

	// Apply no-filter policy if configured
	effectiveNoFilterPolicy := getStringConfig("tap.no_filter_policy", noFilterPolicy)
	if effectiveNoFilterPolicy == "deny" {
		appFilter.SetNoFilterPolicy(hunter.NoFilterPolicyDeny)
	}

	return appFilter, nil
}

// parseSizeString parses a size string (e.g., "100M", "1G", "500K") and returns bytes
func parseSizeString(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	lastChar := s[len(s)-1]
	var multiplier int64 = 1

	switch lastChar {
	case 'K', 'k':
		multiplier = 1024
		s = s[:len(s)-1]
	case 'M', 'm':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	case 'T', 't':
		multiplier = 1024 * 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}

	var value int64
	_, err := fmt.Sscanf(s, "%d", &value)
	if err != nil {
		return 0, fmt.Errorf("invalid size value: %w", err)
	}

	return value * multiplier, nil
}
