//go:build tap || all
// +build tap all

package tap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// VoIP-specific flags
	sipuser           string
	sipuserDeprecated string // deprecated, use sipuser (via --sip-user)

	// BPF filter optimization flags for VoIP
	udpOnly       bool
	sipPorts      string
	rtpPortRanges string

	// Pattern matching flags
	patternAlgorithm string
	patternBufferMB  int

	// TCP-specific configuration flags
	tcpPerformanceMode string

	// Per-call PCAP flags (VoIP-specific)
	perCallPcapEnabled bool
	perCallPcapDir     string
	perCallPcapPattern string

	// VoIP command hook
	voipCommand string
)

var voipTapCmd = &cobra.Command{
	Use:   "voip",
	Short: "Standalone VoIP capture with full processor capabilities",
	Long: `Run lippycat in standalone VoIP tap mode.

VoIP tap mode combines local VoIP-optimized capture with full processor capabilities:
- Captures and analyzes SIP/RTP packets from local interfaces
- Provides per-call PCAP writing (separate SIP and RTP files)
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode

This is ideal for single-machine VoIP capture where you want:
- Call detection and per-call PCAP files
- Real-time call monitoring via TUI
- TCP SIP reassembly support
- Optional upstream forwarding

Example:
  lc tap voip --interface eth0 --sip-user alicent
  lc tap voip -i eth0 --per-call-pcap --per-call-pcap-dir /var/voip/pcaps
  lc tap voip -i eth0 --udp-only --sip-port 5060`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Handle deprecated --sipuser flag migration to --sip-user
		if cmd.Flags().Changed("sipuser") {
			if cmd.Flags().Changed("sip-user") {
				return fmt.Errorf("cannot use both --sipuser (deprecated) and --sip-user; use --sip-user only")
			}
			sipuser = sipuserDeprecated
			logger.Warn("--sipuser is deprecated, use --sip-user instead")
		}
		return nil
	},
	RunE: runVoIPTap,
}

func init() {
	TapCmd.AddCommand(voipTapCmd)

	// VoIP-specific flags
	// --sip-user is the new flag, --sipuser is deprecated
	voipTapCmd.Flags().StringVarP(&sipuser, "sip-user", "u", "", "SIP user/phone to match (comma-separated, supports wildcards: '*456789', 'alice*')")
	voipTapCmd.Flags().StringVar(&sipuserDeprecated, "sipuser", "", "")
	voipTapCmd.Flags().Lookup("sipuser").Deprecated = "use --sip-user instead"
	voipTapCmd.Flags().Lookup("sipuser").Hidden = true

	// BPF Filter Optimization Flags
	voipTapCmd.Flags().BoolVarP(&udpOnly, "udp-only", "U", false, "Capture UDP only, bypass TCP SIP (reduces CPU on TCP-heavy networks)")
	voipTapCmd.Flags().StringVarP(&sipPorts, "sip-port", "S", "", "Restrict SIP capture to specific port(s), comma-separated (e.g., '5060' or '5060,5061,5080')")
	voipTapCmd.Flags().StringVarP(&rtpPortRanges, "rtp-port-range", "R", "", "Custom RTP port range(s), comma-separated (e.g., '8000-9000' or '8000-9000,40000-50000')")

	// Pattern Matching Algorithm Flags
	voipTapCmd.Flags().StringVar(&patternAlgorithm, "pattern-algorithm", "auto", "Pattern matching algorithm: 'auto', 'linear', 'aho-corasick'")
	voipTapCmd.Flags().IntVar(&patternBufferMB, "pattern-buffer-mb", 64, "Memory budget for pattern buffer in MB")

	// TCP Performance Mode
	voipTapCmd.Flags().StringVarP(&tcpPerformanceMode, "tcp-performance-mode", "M", "balanced", "TCP performance mode: 'minimal', 'balanced', 'high_performance', 'low_latency'")

	// Per-call PCAP (VoIP-specific)
	voipTapCmd.Flags().BoolVar(&perCallPcapEnabled, "per-call-pcap", false, "Enable per-call PCAP writing for VoIP traffic (default: enabled for tap voip)")
	voipTapCmd.Flags().StringVar(&perCallPcapDir, "per-call-pcap-dir", "./pcaps", "Directory for per-call PCAP files")
	voipTapCmd.Flags().StringVar(&perCallPcapPattern, "per-call-pcap-pattern", "{timestamp}_{callid}.pcap", "Filename pattern for per-call PCAP files")

	// VoIP command hook
	voipTapCmd.Flags().StringVar(&voipCommand, "voip-command", "", "Command to execute when VoIP call completes (supports %callid%, %dirname%, etc.)")

	// Bind VoIP-specific flags to viper
	_ = viper.BindPFlag("tap.voip.sip_user", voipTapCmd.Flags().Lookup("sip-user"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("tap.voip.sipuser", voipTapCmd.Flags().Lookup("sip-user"))
	_ = viper.BindPFlag("tap.voip.udp_only", voipTapCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("tap.voip.sip_ports", voipTapCmd.Flags().Lookup("sip-port"))
	_ = viper.BindPFlag("tap.voip.rtp_port_ranges", voipTapCmd.Flags().Lookup("rtp-port-range"))
	_ = viper.BindPFlag("tap.voip.pattern_algorithm", voipTapCmd.Flags().Lookup("pattern-algorithm"))
	_ = viper.BindPFlag("tap.voip.pattern_buffer_mb", voipTapCmd.Flags().Lookup("pattern-buffer-mb"))
	_ = viper.BindPFlag("tap.voip.tcp_performance_mode", voipTapCmd.Flags().Lookup("tcp-performance-mode"))
	_ = viper.BindPFlag("tap.per_call_pcap.enabled", voipTapCmd.Flags().Lookup("per-call-pcap"))
	_ = viper.BindPFlag("tap.per_call_pcap.output_dir", voipTapCmd.Flags().Lookup("per-call-pcap-dir"))
	_ = viper.BindPFlag("tap.per_call_pcap.file_pattern", voipTapCmd.Flags().Lookup("per-call-pcap-pattern"))
	_ = viper.BindPFlag("tap.voip_command", voipTapCmd.Flags().Lookup("voip-command"))
}

func runVoIPTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone VoIP tap mode")

	// Initialize SIP user surveillance list
	expirationDate := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
	su := sipusers.SipUser{ExpirationDate: expirationDate}

	// Parse and add SIP users if specified
	if sipuser != "" {
		for _, user := range strings.Split(sipuser, ",") {
			user = strings.TrimSpace(user)
			if user != "" {
				sipusers.AddSipUser(user, &su)
				logger.Info("Added SIP user for monitoring", "user", user)
			}
		}
	}

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if getBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build optimized BPF filter using VoIPFilterBuilder
	baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
	effectiveBPFFilter := baseBPFFilter

	// Parse BPF filter optimization flags
	voipUDPOnly := viper.GetBool("tap.voip.udp_only")
	voipSIPPorts := viper.GetString("tap.voip.sip_ports")
	voipRTPPortRanges := viper.GetString("tap.voip.rtp_port_ranges")

	// Build VoIP filter if optimization flags are set
	if voipUDPOnly || voipSIPPorts != "" || voipRTPPortRanges != "" {
		parsedSIPPorts, err := voip.ParsePorts(voipSIPPorts)
		if err != nil {
			return fmt.Errorf("invalid --sip-port value: %w", err)
		}

		parsedRTPRanges, err := voip.ParsePortRanges(voipRTPPortRanges)
		if err != nil {
			return fmt.Errorf("invalid --rtp-port-range value: %w", err)
		}

		builder := voip.NewVoIPFilterBuilder()
		filterConfig := voip.VoIPFilterConfig{
			SIPPorts:      parsedSIPPorts,
			RTPPortRanges: parsedRTPRanges,
			UDPOnly:       voipUDPOnly,
			BaseFilter:    baseBPFFilter,
		}
		effectiveBPFFilter = builder.Build(filterConfig)

		logger.Info("VoIP BPF filter optimization enabled",
			"udp_only", voipUDPOnly,
			"sip_ports", voipSIPPorts,
			"rtp_port_ranges", voipRTPPortRanges,
			"effective_filter", effectiveBPFFilter)
	}

	// Set TCP performance mode in viper for VoIP processing
	viper.Set("voip.tcp_performance_mode", getStringConfig("tap.voip.tcp_performance_mode", tcpPerformanceMode))
	viper.Set("voip.pattern_algorithm", getStringConfig("tap.voip.pattern_algorithm", patternAlgorithm))
	viper.Set("voip.pattern_buffer_mb", getIntConfig("tap.voip.pattern_buffer_mb", patternBufferMB))

	// Default to enabling per-call PCAP for VoIP mode if not explicitly set
	effectivePerCallPcap := getBoolConfig("tap.per_call_pcap.enabled", perCallPcapEnabled)
	if !cmd.Flags().Changed("per-call-pcap") && !viper.IsSet("tap.per_call_pcap.enabled") {
		// VoIP mode should default to per-call PCAP enabled
		effectivePerCallPcap = true
	}

	// Build per-call PCAP config
	var pcapWriterConfig *processor.PcapWriterConfig
	if effectivePerCallPcap {
		pcapWriterConfig = &processor.PcapWriterConfig{
			Enabled:         true,
			OutputDir:       getStringConfig("tap.per_call_pcap.output_dir", perCallPcapDir),
			FilePattern:     getStringConfig("tap.per_call_pcap.file_pattern", perCallPcapPattern),
			MaxFileSize:     100 * 1024 * 1024,
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
	}

	// Set default tap ID
	effectiveTapID := getStringConfig("tap.tap_id", tapID)
	if effectiveTapID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		effectiveTapID = hostname + "-voip-tap"
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
		PcapWriterConfig:      pcapWriterConfig,
		AutoRotateConfig:      autoRotateConfig,
		CommandExecutorConfig: commandExecutorConfig,
		EnableDetection:       getBoolConfig("tap.enable_detection", enableDetection),
		FilterFile:            getStringConfig("tap.filter_file", filterFile),
		TLSEnabled:            !getBoolConfig("insecure", insecureAllowed),
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

	// Create LocalSource for local packet capture with optimized VoIP filter
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

	// Create VoIPProcessor for SIP/RTP metadata extraction
	// This enables per-call PCAP writing and RTP association in tap mode
	// Pass the ApplicationFilter so only matching calls are tracked
	voipProcConfig := voipprocessor.DefaultConfig()
	voipProcConfig.ApplicationFilter = appFilter
	voipProc := voipprocessor.New(voipProcConfig)
	voipAdapter := voipprocessor.NewSourceAdapter(voipProc)
	localSource.SetVoIPProcessor(voipAdapter)
	logger.Info("VoIP processor enabled for tap mode")

	// Set the local source and target on the processor
	p.SetPacketSource(localSource)
	p.SetFilterTarget(localTarget)

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("VoIP Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"sipuser", sipuser,
		"per_call_pcap", effectivePerCallPcap,
		"listen", config.ListenAddr,
		"tcp_performance_mode", tcpPerformanceMode,
		"pattern_algorithm", patternAlgorithm)

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

	logger.Info("VoIP Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("VoIP Tap node failed", "error", err)
		return err
	}

	logger.Info("VoIP Tap node stopped")
	return nil
}
