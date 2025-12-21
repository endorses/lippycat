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

Example:
  lc tap --interface eth0
  lc tap -i eth0 --per-call-pcap --per-call-pcap-dir /var/pcaps
  lc tap -i eth0 --upstream central-processor:50051
  lc tap -i eth0,eth1 --listen 0.0.0.0:50051`,
	RunE: runTap,
}

var (
	// Capture flags (from hunter)
	interfaces   []string
	bpfFilter    string
	promiscuous  bool
	bufferSize   int
	batchSize    int
	batchTimeout int

	// Management interface flags
	listenAddr     string
	tapID          string
	maxSubscribers int

	// Upstream forwarding
	upstreamAddr string

	// PCAP flags
	writeFile string

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

	// Protocol detection
	enableDetection bool

	// TLS flags (for management interface)
	tlsEnabled    bool
	tlsCertFile   string
	tlsKeyFile    string
	tlsCAFile     string
	tlsClientAuth bool

	// API Key Authentication
	apiKeyAuthEnabled bool

	// Security flags
	insecureAllowed bool
)

func init() {
	// ============================================================
	// Capture Configuration (persistent for voip subcommand)
	// ============================================================
	TapCmd.PersistentFlags().StringSliceVarP(&interfaces, "interface", "i", []string{"any"}, "Network interfaces to capture (comma-separated)")
	TapCmd.PersistentFlags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
	TapCmd.PersistentFlags().BoolVarP(&promiscuous, "promisc", "p", false, "Enable promiscuous mode")
	TapCmd.PersistentFlags().IntVarP(&bufferSize, "buffer-size", "b", 10000, "Packet buffer size")
	TapCmd.PersistentFlags().IntVar(&batchSize, "batch-size", 100, "Packets per batch")
	TapCmd.PersistentFlags().IntVar(&batchTimeout, "batch-timeout", 100, "Batch timeout in milliseconds")

	// ============================================================
	// Management Interface Configuration
	// ============================================================
	TapCmd.Flags().StringVarP(&listenAddr, "listen", "l", fmt.Sprintf(":%d", constants.DefaultGRPCPort), "Listen address for TUI connections (host:port)")
	TapCmd.Flags().StringVar(&tapID, "tap-id", "", "Unique tap identifier (default: hostname)")
	TapCmd.Flags().IntVar(&maxSubscribers, "max-subscribers", constants.DefaultMaxSubscribers, "Maximum concurrent TUI subscribers (0 = unlimited)")

	// Upstream forwarding
	TapCmd.Flags().StringVarP(&upstreamAddr, "upstream", "u", "", "Upstream processor address for hierarchical mode (host:port)")

	// ============================================================
	// PCAP Writing Configuration
	// ============================================================
	TapCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "Write received packets to PCAP file")

	// Per-call PCAP (VoIP)
	TapCmd.Flags().BoolVar(&perCallPcapEnabled, "per-call-pcap", false, "Enable per-call PCAP writing for VoIP traffic")
	TapCmd.Flags().StringVar(&perCallPcapDir, "per-call-pcap-dir", "./pcaps", "Directory for per-call PCAP files")
	TapCmd.Flags().StringVar(&perCallPcapPattern, "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "Filename pattern for per-call PCAP files")

	// Auto-rotate PCAP (non-VoIP)
	TapCmd.Flags().BoolVar(&autoRotatePcapEnabled, "auto-rotate-pcap", false, "Enable auto-rotating PCAP writing for non-VoIP traffic")
	TapCmd.Flags().StringVar(&autoRotatePcapDir, "auto-rotate-pcap-dir", "./auto-rotate-pcaps", "Directory for auto-rotating PCAP files")
	TapCmd.Flags().StringVar(&autoRotatePcapPattern, "auto-rotate-pcap-pattern", "{timestamp}.pcap", "Filename pattern for auto-rotating PCAP files")
	TapCmd.Flags().StringVar(&autoRotatePcapIdleTimeout, "auto-rotate-idle-timeout", "30s", "Close PCAP file after this idle time")
	TapCmd.Flags().StringVar(&autoRotatePcapMaxSize, "auto-rotate-max-size", "100M", "Maximum PCAP file size before rotation")

	// ============================================================
	// Virtual Interface Configuration
	// ============================================================
	TapCmd.Flags().BoolVar(&virtualInterface, "virtual-interface", false, "Enable virtual network interface for packet injection")
	TapCmd.Flags().StringVar(&virtualInterfaceName, "vif-name", "lc0", "Virtual interface name")
	TapCmd.Flags().StringVar(&vifType, "vif-type", "tap", "Virtual interface type: tap or tun")
	TapCmd.Flags().IntVar(&vifBufferSize, "vif-buffer-size", 65536, "Injection queue buffer size")
	TapCmd.Flags().StringVar(&vifNetNS, "vif-netns", "", "Network namespace for interface isolation")
	TapCmd.Flags().StringVar(&vifDropPrivileges, "vif-drop-privileges", "", "Drop privileges to specified user after interface creation")

	// ============================================================
	// Command Hooks Configuration
	// ============================================================
	TapCmd.Flags().StringVar(&pcapCommand, "pcap-command", "", "Command to execute when PCAP file closes (supports %pcap% placeholder)")
	TapCmd.Flags().StringVar(&voipCommand, "voip-command", "", "Command to execute when VoIP call completes (supports %callid%, %dirname%, etc.)")
	TapCmd.Flags().StringVar(&commandTimeout, "command-timeout", "30s", "Timeout for command execution")
	TapCmd.Flags().IntVar(&commandConcurrency, "command-concurrency", 10, "Maximum concurrent command executions")

	// ============================================================
	// Protocol Detection
	// ============================================================
	TapCmd.Flags().BoolVarP(&enableDetection, "detect", "d", true, "Enable protocol detection")

	// ============================================================
	// TLS Configuration (for management interface)
	// ============================================================
	TapCmd.Flags().BoolVar(&tlsEnabled, "tls", false, "Enable TLS encryption for management interface")
	TapCmd.Flags().StringVar(&tlsCertFile, "tls-cert", "", "Path to server TLS certificate")
	TapCmd.Flags().StringVar(&tlsKeyFile, "tls-key", "", "Path to server TLS key")
	TapCmd.Flags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for client verification")
	TapCmd.Flags().BoolVar(&tlsClientAuth, "tls-client-auth", false, "Require client certificate authentication")

	// API Key Authentication
	TapCmd.Flags().BoolVar(&apiKeyAuthEnabled, "api-key-auth", false, "Enable API key authentication")

	// Security
	TapCmd.Flags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS")

	// ============================================================
	// Viper Bindings
	// ============================================================
	// Capture configuration
	_ = viper.BindPFlag("tap.interfaces", TapCmd.PersistentFlags().Lookup("interface"))
	_ = viper.BindPFlag("tap.bpf_filter", TapCmd.PersistentFlags().Lookup("filter"))
	_ = viper.BindPFlag("tap.promiscuous", TapCmd.PersistentFlags().Lookup("promisc"))
	_ = viper.BindPFlag("tap.buffer_size", TapCmd.PersistentFlags().Lookup("buffer-size"))
	_ = viper.BindPFlag("tap.batch_size", TapCmd.PersistentFlags().Lookup("batch-size"))
	_ = viper.BindPFlag("tap.batch_timeout_ms", TapCmd.PersistentFlags().Lookup("batch-timeout"))

	// Management interface
	_ = viper.BindPFlag("tap.listen_addr", TapCmd.Flags().Lookup("listen"))
	_ = viper.BindPFlag("tap.tap_id", TapCmd.Flags().Lookup("tap-id"))
	_ = viper.BindPFlag("tap.max_subscribers", TapCmd.Flags().Lookup("max-subscribers"))
	_ = viper.BindPFlag("tap.upstream_addr", TapCmd.Flags().Lookup("upstream"))

	// PCAP configuration
	_ = viper.BindPFlag("tap.write_file", TapCmd.Flags().Lookup("write-file"))
	_ = viper.BindPFlag("tap.per_call_pcap.enabled", TapCmd.Flags().Lookup("per-call-pcap"))
	_ = viper.BindPFlag("tap.per_call_pcap.output_dir", TapCmd.Flags().Lookup("per-call-pcap-dir"))
	_ = viper.BindPFlag("tap.per_call_pcap.file_pattern", TapCmd.Flags().Lookup("per-call-pcap-pattern"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.enabled", TapCmd.Flags().Lookup("auto-rotate-pcap"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.output_dir", TapCmd.Flags().Lookup("auto-rotate-pcap-dir"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.file_pattern", TapCmd.Flags().Lookup("auto-rotate-pcap-pattern"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.idle_timeout", TapCmd.Flags().Lookup("auto-rotate-idle-timeout"))
	_ = viper.BindPFlag("tap.auto_rotate_pcap.max_size", TapCmd.Flags().Lookup("auto-rotate-max-size"))

	// Virtual interface
	_ = viper.BindPFlag("tap.virtual_interface", TapCmd.Flags().Lookup("virtual-interface"))
	_ = viper.BindPFlag("tap.vif_name", TapCmd.Flags().Lookup("vif-name"))
	_ = viper.BindPFlag("tap.vif_type", TapCmd.Flags().Lookup("vif-type"))
	_ = viper.BindPFlag("tap.vif_buffer_size", TapCmd.Flags().Lookup("vif-buffer-size"))
	_ = viper.BindPFlag("tap.vif_netns", TapCmd.Flags().Lookup("vif-netns"))
	_ = viper.BindPFlag("tap.vif_drop_privileges", TapCmd.Flags().Lookup("vif-drop-privileges"))

	// Command hooks
	_ = viper.BindPFlag("tap.pcap_command", TapCmd.Flags().Lookup("pcap-command"))
	_ = viper.BindPFlag("tap.voip_command", TapCmd.Flags().Lookup("voip-command"))
	_ = viper.BindPFlag("tap.command_timeout", TapCmd.Flags().Lookup("command-timeout"))
	_ = viper.BindPFlag("tap.command_concurrency", TapCmd.Flags().Lookup("command-concurrency"))

	// Detection
	_ = viper.BindPFlag("tap.enable_detection", TapCmd.Flags().Lookup("detect"))

	// TLS
	_ = viper.BindPFlag("tap.tls.enabled", TapCmd.Flags().Lookup("tls"))
	_ = viper.BindPFlag("tap.tls.cert_file", TapCmd.Flags().Lookup("tls-cert"))
	_ = viper.BindPFlag("tap.tls.key_file", TapCmd.Flags().Lookup("tls-key"))
	_ = viper.BindPFlag("tap.tls.ca_file", TapCmd.Flags().Lookup("tls-ca"))
	_ = viper.BindPFlag("tap.tls.client_auth", TapCmd.Flags().Lookup("tls-client-auth"))
	_ = viper.BindPFlag("security.api_keys.enabled", TapCmd.Flags().Lookup("api-key-auth"))
}

func runTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("tap.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build per-call PCAP config if enabled
	var pcapWriterConfig *processor.PcapWriterConfig
	if getBoolConfig("tap.per_call_pcap.enabled", perCallPcapEnabled) {
		pcapWriterConfig = &processor.PcapWriterConfig{
			Enabled:         true,
			OutputDir:       getStringConfig("tap.per_call_pcap.output_dir", perCallPcapDir),
			FilePattern:     getStringConfig("tap.per_call_pcap.file_pattern", perCallPcapPattern),
			MaxFileSize:     100 * 1024 * 1024, // 100MB default
			MaxFilesPerCall: 10,
			BufferSize:      4096,
			SyncInterval:    5 * time.Second,
		}
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
	voipCmd := getStringConfig("tap.voip_command", voipCommand)
	if pcapCmd != "" || voipCmd != "" {
		timeoutStr := getStringConfig("tap.command_timeout", commandTimeout)
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("invalid command-timeout: %w", err)
		}

		commandExecutorConfig = &processor.CommandExecutorConfig{
			PcapCommand: pcapCmd,
			VoipCommand: voipCmd,
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
		UpstreamAddr:          getStringConfig("tap.upstream_addr", upstreamAddr),
		MaxHunters:            0, // Not accepting hunters in tap mode
		MaxSubscribers:        getIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             getStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		PcapWriterConfig:      pcapWriterConfig,
		AutoRotateConfig:      autoRotateConfig,
		CommandExecutorConfig: commandExecutorConfig,
		EnableDetection:       getBoolConfig("tap.enable_detection", enableDetection),
		// TLS configuration
		TLSEnabled:    getBoolConfig("tap.tls.enabled", tlsEnabled),
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

	// Security check: require explicit opt-in to insecure mode
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
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
	}
	localSource := source.NewLocalSource(localSourceConfig)

	// Create LocalTarget for local BPF filtering
	localTargetConfig := filtering.LocalTargetConfig{
		BaseBPF: localSourceConfig.BPFFilter,
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
	if viper.IsSet(key) {
		return viper.GetStringSlice(key)
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
