//go:build processor || all

package process

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ProcessCmd = &cobra.Command{
	Use:   "process",
	Short: "Run as processor node (central aggregation)",
	Long: `Run lippycat in processor mode.

Processor nodes receive packets from multiple hunter nodes via gRPC,
aggregate them, and optionally forward filtered traffic upstream to
another processor (hierarchical mode).

Processors manage filter distribution to connected hunters and
provide monitoring APIs for TUI clients.

Examples:
  # Basic processor with TLS (default, requires certs)
  lc process --listen :50051 --tls-cert server.crt --tls-key server.key

  # Hierarchical mode (forward to upstream processor)
  lc process --listen :50051 --processor parent:50051 --tls-cert server.crt --tls-key server.key

  # With per-call PCAP and command hooks
  lc process --listen :50051 \
    --per-call-pcap --per-call-pcap-dir /var/voip/calls \
    --pcap-command 'gzip %pcap%'

  # Lawful Interception (requires -tags li build)
  lc process --listen :50051 --tls-cert server.crt --tls-key server.key \
    --li-enabled \
    --li-x1-listen :8443 \
    --li-x1-tls-cert x1-server.crt --li-x1-tls-key x1-server.key \
    --li-x1-tls-ca admf-ca.crt \
    --li-delivery-tls-cert delivery.crt --li-delivery-tls-key delivery.key \
    --li-delivery-tls-ca mdf-ca.crt`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Handle deprecated --processor-id flag migration to --id
		if cmd.Flags().Changed("processor-id") {
			if cmd.Flags().Changed("id") {
				return fmt.Errorf("cannot use both --processor-id (deprecated) and --id; use --id only")
			}
			processorID = processorIDDeprecated
			logger.Warn("--processor-id is deprecated, use --id instead")
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
	RunE: runProcess,
}

var (
	listenAddr             string
	processorID            string // renamed from processor-id, now --id
	processorIDDeprecated  string // deprecated, use processorID
	processorAddr          string // renamed from upstreamAddr
	upstreamAddrDeprecated string // deprecated, use processorAddr
	maxHunters             int
	maxSubscribers         int
	writeFile              string
	displayStats           bool
	enableDetection        bool
	filterFile             string
	// TLS flags (TLS is enabled by default unless --insecure is set)
	tlsCertFile     string
	tlsKeyFile      string
	tlsCAFile       string
	tlsClientAuth   bool
	insecureAllowed bool
	// API Key Authentication flags
	apiKeyAuthEnabled bool
	// Per-call PCAP flags
	perCallPcapEnabled bool
	perCallPcapDir     string
	perCallPcapPattern string
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
	// Command hook flags
	pcapCommand        string
	voipCommand        string
	commandTimeout     string
	commandConcurrency int
	// DNS tunneling detection command hook flags
	tunnelingCommand   string
	tunnelingThreshold float64
	tunnelingDebounce  string
	// TLS keylog flags (for decryption support)
	tlsKeylogDir string
)

func init() {
	// Required flags
	ProcessCmd.Flags().StringVarP(&listenAddr, "listen", "l", fmt.Sprintf(":%d", constants.DefaultGRPCPort), "Listen address for hunter connections (host:port)")

	// Processor configuration
	// --id is the new flag, --processor-id is deprecated
	ProcessCmd.Flags().StringVarP(&processorID, "id", "I", "", "Unique processor identifier (default: hostname)")
	ProcessCmd.Flags().StringVar(&processorIDDeprecated, "processor-id", "", "")
	ProcessCmd.Flags().Lookup("processor-id").Deprecated = "use --id instead"
	ProcessCmd.Flags().Lookup("processor-id").Hidden = true
	// Upstream forwarding (--processor is the new name, --upstream is deprecated)
	ProcessCmd.Flags().StringVarP(&processorAddr, "processor", "P", "", "Upstream processor address for hierarchical mode (host:port)")
	ProcessCmd.Flags().StringVar(&upstreamAddrDeprecated, "upstream", "", "")
	ProcessCmd.Flags().Lookup("upstream").Deprecated = "use --processor instead"
	ProcessCmd.Flags().Lookup("upstream").Hidden = true
	ProcessCmd.Flags().IntVarP(&maxHunters, "max-hunters", "m", constants.DefaultMaxHunters, "Maximum number of concurrent hunter connections")
	ProcessCmd.Flags().IntVarP(&maxSubscribers, "max-subscribers", "", constants.DefaultMaxSubscribers, "Maximum number of concurrent TUI/monitoring subscribers (0 = unlimited)")
	ProcessCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "Write received packets to PCAP file")
	ProcessCmd.Flags().BoolVarP(&displayStats, "stats", "s", true, "Display statistics")
	ProcessCmd.Flags().BoolVarP(&enableDetection, "enable-detection", "d", true, "Enable centralized protocol detection (default: true)")
	ProcessCmd.Flags().StringVarP(&filterFile, "filter-file", "f", "", "Path to filter persistence file (YAML, default: ~/.config/lippycat/filters.yaml)")

	// TLS configuration (security)
	// TLS is enabled by default unless --insecure is explicitly set
	ProcessCmd.Flags().StringVar(&tlsCertFile, "tls-cert", "", "Path to server TLS certificate")
	ProcessCmd.Flags().StringVar(&tlsKeyFile, "tls-key", "", "Path to server TLS key")
	ProcessCmd.Flags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for client verification (mutual TLS)")
	ProcessCmd.Flags().BoolVar(&tlsClientAuth, "tls-client-auth", false, "Require client certificate authentication (mutual TLS)")
	ProcessCmd.Flags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS (must be explicitly set)")

	// API Key Authentication
	ProcessCmd.Flags().BoolVar(&apiKeyAuthEnabled, "api-key-auth", false, "Enable API key authentication (config file required for keys)")

	// Per-call PCAP writing
	ProcessCmd.Flags().BoolVar(&perCallPcapEnabled, "per-call-pcap", false, "Enable per-call PCAP writing for VoIP traffic")
	ProcessCmd.Flags().StringVar(&perCallPcapDir, "per-call-pcap-dir", "./pcaps", "Directory for per-call PCAP files")
	ProcessCmd.Flags().StringVar(&perCallPcapPattern, "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "Filename pattern for per-call PCAP files (supports {callid}, {from}, {to}, {timestamp})")

	// Auto-rotate PCAP writing
	ProcessCmd.Flags().BoolVar(&autoRotatePcapEnabled, "auto-rotate-pcap", false, "Enable auto-rotating PCAP writing for non-VoIP traffic")
	ProcessCmd.Flags().StringVar(&autoRotatePcapDir, "auto-rotate-pcap-dir", "./auto-rotate-pcaps", "Directory for auto-rotating PCAP files")
	ProcessCmd.Flags().StringVar(&autoRotatePcapPattern, "auto-rotate-pcap-pattern", "{timestamp}.pcap", "Filename pattern for auto-rotating PCAP files (supports {timestamp})")
	ProcessCmd.Flags().StringVar(&autoRotatePcapIdleTimeout, "auto-rotate-idle-timeout", "30s", "Close PCAP file after this idle time (e.g., 30s, 1m)")
	ProcessCmd.Flags().StringVar(&autoRotatePcapMaxSize, "auto-rotate-max-size", "100M", "Maximum PCAP file size before rotation (e.g., 100M, 1G)")

	// Virtual Interface flags
	ProcessCmd.Flags().BoolVarP(&virtualInterface, "virtual-interface", "V", false, "Enable virtual network interface for packet injection")
	ProcessCmd.Flags().StringVar(&virtualInterfaceName, "vif-name", "lc0", "Virtual interface name (default: lc0)")
	ProcessCmd.Flags().StringVar(&vifType, "vif-type", "tap", "Virtual interface type: tap (Layer 2) or tun (Layer 3)")
	ProcessCmd.Flags().IntVar(&vifBufferSize, "vif-buffer-size", 65536, "Injection queue buffer size (packets)")
	ProcessCmd.Flags().StringVar(&vifNetNS, "vif-netns", "", "Network namespace for interface isolation (requires CAP_SYS_ADMIN)")
	ProcessCmd.Flags().StringVar(&vifDropPrivileges, "vif-drop-privileges", "", "Drop privileges to specified user after interface creation (requires running as root)")

	// Command hook flags (PCAP file events)
	ProcessCmd.Flags().StringVar(&pcapCommand, "pcap-command", "", "Command to execute when PCAP file closes (supports %pcap% placeholder)")
	ProcessCmd.Flags().StringVar(&voipCommand, "voip-command", "", "Command to execute when VoIP call completes (supports %callid%, %dirname%, %caller%, %called%, %calldate%)")
	ProcessCmd.Flags().StringVar(&commandTimeout, "command-timeout", "30s", "Timeout for command execution (e.g., 30s, 1m)")
	ProcessCmd.Flags().IntVar(&commandConcurrency, "command-concurrency", 10, "Maximum concurrent command executions")

	// DNS tunneling detection command hook
	ProcessCmd.Flags().StringVar(&tunnelingCommand, "tunneling-command", "", "Command to execute when DNS tunneling detected (supports %domain%, %score%, %entropy%, %queries%, %srcips%, %hunter%, %timestamp%)")
	ProcessCmd.Flags().Float64Var(&tunnelingThreshold, "tunneling-threshold", 0.7, "DNS tunneling score threshold for triggering command (0.0-1.0)")
	ProcessCmd.Flags().StringVar(&tunnelingDebounce, "tunneling-debounce", "5m", "Minimum time between alerts per domain (e.g., 5m, 30s)")

	// LI (Lawful Interception) flags - requires build with -tags li
	RegisterLIFlags(ProcessCmd)

	// TLS keylog flags (for decryption support)
	ProcessCmd.Flags().StringVar(&tlsKeylogDir, "tls-keylog-dir", "", "Directory to write TLS session keys (NSS keylog format, Wireshark-compatible)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("processor.listen_addr", ProcessCmd.Flags().Lookup("listen"))
	_ = viper.BindPFlag("processor.id", ProcessCmd.Flags().Lookup("id"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("processor.processor_id", ProcessCmd.Flags().Lookup("id"))
	_ = viper.BindPFlag("processor.processor_addr", ProcessCmd.Flags().Lookup("processor"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("processor.upstream_addr", ProcessCmd.Flags().Lookup("processor"))
	_ = viper.BindPFlag("processor.max_hunters", ProcessCmd.Flags().Lookup("max-hunters"))
	_ = viper.BindPFlag("processor.max_subscribers", ProcessCmd.Flags().Lookup("max-subscribers"))
	_ = viper.BindPFlag("processor.write_file", ProcessCmd.Flags().Lookup("write-file"))
	_ = viper.BindPFlag("processor.display_stats", ProcessCmd.Flags().Lookup("stats"))
	_ = viper.BindPFlag("processor.enable_detection", ProcessCmd.Flags().Lookup("enable-detection"))
	_ = viper.BindPFlag("processor.filter_file", ProcessCmd.Flags().Lookup("filter-file"))
	_ = viper.BindPFlag("processor.tls.cert_file", ProcessCmd.Flags().Lookup("tls-cert"))
	_ = viper.BindPFlag("processor.tls.key_file", ProcessCmd.Flags().Lookup("tls-key"))
	_ = viper.BindPFlag("processor.tls.ca_file", ProcessCmd.Flags().Lookup("tls-ca"))
	_ = viper.BindPFlag("processor.tls.client_auth", ProcessCmd.Flags().Lookup("tls-client-auth"))
	_ = viper.BindPFlag("processor.insecure", ProcessCmd.Flags().Lookup("insecure"))
	_ = viper.BindPFlag("security.api_keys.enabled", ProcessCmd.Flags().Lookup("api-key-auth"))
	_ = viper.BindPFlag("processor.per_call_pcap.enabled", ProcessCmd.Flags().Lookup("per-call-pcap"))
	_ = viper.BindPFlag("processor.per_call_pcap.output_dir", ProcessCmd.Flags().Lookup("per-call-pcap-dir"))
	_ = viper.BindPFlag("processor.per_call_pcap.file_pattern", ProcessCmd.Flags().Lookup("per-call-pcap-pattern"))
	_ = viper.BindPFlag("processor.auto_rotate_pcap.enabled", ProcessCmd.Flags().Lookup("auto-rotate-pcap"))
	_ = viper.BindPFlag("processor.auto_rotate_pcap.output_dir", ProcessCmd.Flags().Lookup("auto-rotate-pcap-dir"))
	_ = viper.BindPFlag("processor.auto_rotate_pcap.file_pattern", ProcessCmd.Flags().Lookup("auto-rotate-pcap-pattern"))
	_ = viper.BindPFlag("processor.auto_rotate_pcap.idle_timeout", ProcessCmd.Flags().Lookup("auto-rotate-idle-timeout"))
	_ = viper.BindPFlag("processor.auto_rotate_pcap.max_size", ProcessCmd.Flags().Lookup("auto-rotate-max-size"))
	_ = viper.BindPFlag("processor.virtual_interface", ProcessCmd.Flags().Lookup("virtual-interface"))
	_ = viper.BindPFlag("processor.vif_name", ProcessCmd.Flags().Lookup("vif-name"))
	_ = viper.BindPFlag("processor.vif_type", ProcessCmd.Flags().Lookup("vif-type"))
	_ = viper.BindPFlag("processor.vif_buffer_size", ProcessCmd.Flags().Lookup("vif-buffer-size"))
	_ = viper.BindPFlag("processor.vif_netns", ProcessCmd.Flags().Lookup("vif-netns"))
	_ = viper.BindPFlag("processor.vif_drop_privileges", ProcessCmd.Flags().Lookup("vif-drop-privileges"))
	_ = viper.BindPFlag("processor.pcap_command", ProcessCmd.Flags().Lookup("pcap-command"))
	_ = viper.BindPFlag("processor.voip_command", ProcessCmd.Flags().Lookup("voip-command"))
	_ = viper.BindPFlag("processor.command_timeout", ProcessCmd.Flags().Lookup("command-timeout"))
	_ = viper.BindPFlag("processor.command_concurrency", ProcessCmd.Flags().Lookup("command-concurrency"))
	// DNS tunneling detection viper bindings
	_ = viper.BindPFlag("processor.tunneling_command", ProcessCmd.Flags().Lookup("tunneling-command"))
	_ = viper.BindPFlag("processor.tunneling_threshold", ProcessCmd.Flags().Lookup("tunneling-threshold"))
	_ = viper.BindPFlag("processor.tunneling_debounce", ProcessCmd.Flags().Lookup("tunneling-debounce"))
	// LI viper bindings - requires build with -tags li
	BindLIViperFlags(ProcessCmd)
	// TLS keylog viper bindings
	_ = viper.BindPFlag("processor.tls_keylog.output_dir", ProcessCmd.Flags().Lookup("tls-keylog-dir"))
}

func runProcess(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in processor mode")

	// Production mode enforcement: check early before creating config
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if getBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		if !tlsClientAuth && !viper.GetBool("processor.tls.client_auth") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires mutual TLS (--tls-client-auth)")
		}
		logger.Info("Production mode: TLS mutual authentication enforced")
	}

	// Build per-call PCAP config if enabled
	var pcapWriterConfig *processor.PcapWriterConfig
	if getBoolConfig("processor.per_call_pcap.enabled", perCallPcapEnabled) {
		pcapWriterConfig = &processor.PcapWriterConfig{
			Enabled:         true,
			OutputDir:       getStringConfig("processor.per_call_pcap.output_dir", perCallPcapDir),
			FilePattern:     getStringConfig("processor.per_call_pcap.file_pattern", perCallPcapPattern),
			MaxFileSize:     100 * 1024 * 1024, // 100MB default
			MaxFilesPerCall: 10,
			BufferSize:      4096,
			SyncInterval:    5 * time.Second,
		}
	}

	// Build auto-rotate PCAP config if enabled
	var autoRotateConfig *processor.AutoRotateConfig
	if getBoolConfig("processor.auto_rotate_pcap.enabled", autoRotatePcapEnabled) {
		// Parse idle timeout
		idleTimeoutStr := getStringConfig("processor.auto_rotate_pcap.idle_timeout", autoRotatePcapIdleTimeout)
		idleTimeout, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			return fmt.Errorf("invalid auto-rotate-idle-timeout: %w", err)
		}

		// Parse max size (supports K, M, G suffixes)
		maxSizeStr := getStringConfig("processor.auto_rotate_pcap.max_size", autoRotatePcapMaxSize)
		maxSize, err := parseSizeString(maxSizeStr)
		if err != nil {
			return fmt.Errorf("invalid auto-rotate-max-size: %w", err)
		}

		autoRotateConfig = &processor.AutoRotateConfig{
			Enabled:      true,
			OutputDir:    getStringConfig("processor.auto_rotate_pcap.output_dir", autoRotatePcapDir),
			FilePattern:  getStringConfig("processor.auto_rotate_pcap.file_pattern", autoRotatePcapPattern),
			MaxIdleTime:  idleTimeout,
			MaxFileSize:  maxSize,
			MaxDuration:  1 * time.Hour,    // Fixed: 1 hour max per file
			MinDuration:  10 * time.Second, // Fixed: 10 second minimum
			BufferSize:   4096,
			SyncInterval: 5 * time.Second,
		}
	}

	// Build command executor config if commands are configured
	var commandExecutorConfig *processor.CommandExecutorConfig
	pcapCmd := getStringConfig("processor.pcap_command", pcapCommand)
	voipCmd := getStringConfig("processor.voip_command", voipCommand)
	tunnelingCmd := getStringConfig("processor.tunneling_command", tunnelingCommand)
	if pcapCmd != "" || voipCmd != "" || tunnelingCmd != "" {
		// Parse command timeout
		timeoutStr := getStringConfig("processor.command_timeout", commandTimeout)
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("invalid command-timeout: %w", err)
		}

		commandExecutorConfig = &processor.CommandExecutorConfig{
			PcapCommand:      pcapCmd,
			VoipCommand:      voipCmd,
			TunnelingCommand: tunnelingCmd,
			Timeout:          timeout,
			Concurrency:      getIntConfig("processor.command_concurrency", commandConcurrency),
		}
	}

	// Parse tunneling debounce duration
	var tunnelingDebounceDuration time.Duration
	tunnelingDebounceStr := getStringConfig("processor.tunneling_debounce", tunnelingDebounce)
	if tunnelingDebounceStr != "" {
		var err error
		tunnelingDebounceDuration, err = time.ParseDuration(tunnelingDebounceStr)
		if err != nil {
			return fmt.Errorf("invalid tunneling-debounce: %w", err)
		}
	}

	// Build auth config if enabled
	var authConfig *auth.Config
	if getBoolConfig("security.api_keys.enabled", apiKeyAuthEnabled) {
		// Load API keys from config file
		var apiKeys []auth.APIKey
		if err := viper.UnmarshalKey("security.api_keys.keys", &apiKeys); err != nil {
			return fmt.Errorf("failed to load API keys from config: %w", err)
		}

		if len(apiKeys) == 0 {
			return fmt.Errorf("API key authentication enabled but no keys configured (add security.api_keys.keys to config file)")
		}

		authConfig = &auth.Config{
			Enabled: true,
			APIKeys: apiKeys,
		}

		logger.Info("API key authentication configured",
			"num_keys", len(apiKeys),
			"source", "config file")
	}

	// Build TLS keylog config if output directory is specified
	var tlsKeylogConfig *processor.TLSKeylogWriterConfig
	keylogDir := getStringConfig("processor.tls_keylog.output_dir", tlsKeylogDir)
	if keylogDir != "" {
		tlsKeylogConfig = &processor.TLSKeylogWriterConfig{
			OutputDir:   keylogDir,
			FilePattern: "session_{timestamp}.keys",
			MaxEntries:  10000,
			SessionTTL:  time.Hour,
		}
		logger.Info("TLS keylog writing enabled", "output_dir", keylogDir)
	}

	// Get configuration (flags override config file)
	config := processor.Config{
		ListenAddr:            getStringConfig("processor.listen_addr", listenAddr),
		ProcessorID:           getStringConfig("processor.processor_id", processorID),
		UpstreamAddr:          getStringConfig("processor.processor_addr", processorAddr),
		MaxHunters:            getIntConfig("processor.max_hunters", maxHunters),
		MaxSubscribers:        getIntConfig("processor.max_subscribers", maxSubscribers),
		WriteFile:             getStringConfig("processor.write_file", writeFile),
		DisplayStats:          getBoolConfig("processor.display_stats", displayStats),
		PcapWriterConfig:      pcapWriterConfig,
		AutoRotateConfig:      autoRotateConfig,
		CommandExecutorConfig: commandExecutorConfig,
		TunnelingThreshold:    getFloat64Config("processor.tunneling_threshold", tunnelingThreshold),
		TunnelingDebounce:     tunnelingDebounceDuration,
		EnableDetection:       getBoolConfig("processor.enable_detection", enableDetection),
		FilterFile:            getStringConfig("processor.filter_file", filterFile),
		// TLS configuration (enabled by default unless --insecure is set)
		TLSEnabled:    !getBoolConfig("insecure", insecureAllowed),
		TLSCertFile:   getStringConfig("processor.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("processor.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("processor.tls.ca_file", tlsCAFile),
		TLSClientAuth: getBoolConfig("processor.tls.client_auth", tlsClientAuth),
		// API Key Authentication
		AuthConfig: authConfig,
		// Virtual interface configuration
		VirtualInterface:      getBoolConfig("processor.virtual_interface", virtualInterface),
		VirtualInterfaceName:  getStringConfig("processor.vif_name", virtualInterfaceName),
		VirtualInterfaceType:  getStringConfig("processor.vif_type", vifType),
		VifBufferSize:         getIntConfig("processor.vif_buffer_size", vifBufferSize),
		VifNetNS:              getStringConfig("processor.vif_netns", vifNetNS),
		VifDropPrivilegesUser: getStringConfig("processor.vif_drop_privileges", vifDropPrivileges),
		// TLS keylog configuration (for decryption support)
		TLSKeylogConfig: tlsKeylogConfig,
	}

	// Apply LI configuration (only available in -tags li builds)
	if liConfig := GetLIConfig(); liConfig != nil {
		config.LIEnabled = liConfig.Enabled
		config.LIX1ListenAddr = liConfig.X1ListenAddr
		config.LIX1TLSCertFile = liConfig.X1TLSCertFile
		config.LIX1TLSKeyFile = liConfig.X1TLSKeyFile
		config.LIX1TLSCAFile = liConfig.X1TLSCAFile
		config.LIADMFEndpoint = liConfig.ADMFEndpoint
		config.LIADMFTLSCertFile = liConfig.ADMFTLSCertFile
		config.LIADMFTLSKeyFile = liConfig.ADMFTLSKeyFile
		config.LIADMFTLSCAFile = liConfig.ADMFTLSCAFile
		config.LIADMFKeepalive = liConfig.ADMFKeepalive
		config.LIDeliveryTLSCertFile = liConfig.DeliveryTLSCertFile
		config.LIDeliveryTLSKeyFile = liConfig.DeliveryTLSKeyFile
		config.LIDeliveryTLSCAFile = liConfig.DeliveryTLSCAFile
		config.LIDeliveryTLSPinnedCert = liConfig.DeliveryTLSPinnedCert
	}

	// Validate TLS configuration: cert and key required when TLS is enabled
	if config.TLSEnabled && (config.TLSCertFile == "" || config.TLSKeyFile == "") {
		return fmt.Errorf("TLS enabled but certificate/key not provided\n\n" +
			"For TLS connections, provide certificate and key:\n" +
			"  --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
			"Or disable TLS entirely (NOT RECOMMENDED): --insecure")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Server will accept UNENCRYPTED hunter connections")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("  Enable TLS: --tls-cert=server.crt --tls-key=server.key")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		authMode := "Server TLS"
		if config.TLSClientAuth {
			authMode = "Mutual TLS (client certs required)"
		}
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED ✓")
		logger.Info("  Authentication mode: " + authMode)
		logger.Info("  All hunter connections will be encrypted")
		logger.Info("═══════════════════════════════════════════════════════════")
	}

	// Set default processor ID to hostname if not specified
	if config.ProcessorID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		config.ProcessorID = hostname
	}

	// Validate configuration
	if config.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("Processor configuration",
		"processor_id", config.ProcessorID,
		"mode", mode,
		"listen", config.ListenAddr,
		"upstream", config.UpstreamAddr,
		"max_hunters", config.MaxHunters,
		"write_file", config.WriteFile,
		"enable_detection", config.EnableDetection)

	// Create processor instance
	p, err := processor.New(config)
	if err != nil {
		return fmt.Errorf("failed to create processor: %w", err)
	}

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

	logger.Info("Processor started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Optionally start stats display
	var statsTicker *time.Ticker
	if config.DisplayStats {
		statsTicker = time.NewTicker(5 * time.Second)
		defer statsTicker.Stop()

		go func() {
			for range statsTicker.C {
				stats := p.GetStats()
				logger.Info("Processor stats",
					"hunters_connected", stats.TotalHunters,
					"hunters_healthy", stats.HealthyHunters,
					"hunters_warning", stats.WarningHunters,
					"hunters_error", stats.ErrorHunters,
					"packets_received", stats.TotalPacketsReceived,
					"packets_forwarded", stats.TotalPacketsForwarded,
					"active_filters", stats.TotalFilters)
			}
		}()
	}

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		// Signal received, give some time for graceful shutdown
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("Processor failed", "error", err)
		return err
	}

	logger.Info("Processor stopped")
	return nil
}

// Helper functions to get config values with fallback to flags
func getStringConfig(key, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return viper.GetString(key)
}

func getIntConfig(key string, flagValue int) int {
	// Simplified version without circular reference
	if viper.IsSet(key) {
		return viper.GetInt(key)
	}
	return flagValue
}

func getBoolConfig(key string, flagValue bool) bool {
	// Simplified version without circular reference
	if viper.IsSet(key) {
		return viper.GetBool(key)
	}
	return flagValue
}

func getStringSliceConfig(key string, flagValue []string) []string {
	// Check actual config value instead of viper.IsSet() which returns true
	// for bound flags even when config file doesn't define them
	if configValue := viper.GetStringSlice(key); len(configValue) > 0 {
		return configValue
	}
	return flagValue
}

func getFloat64Config(key string, flagValue float64) float64 {
	if viper.IsSet(key) {
		return viper.GetFloat64(key)
	}
	return flagValue
}

// parseSizeString parses a size string (e.g., "100M", "1G", "500K") and returns bytes
func parseSizeString(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Check last character for suffix
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

	// Parse number
	var value int64
	_, err := fmt.Sscanf(s, "%d", &value)
	if err != nil {
		return 0, fmt.Errorf("invalid size value: %w", err)
	}

	return value * multiplier, nil
}
