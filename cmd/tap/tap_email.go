//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Email-specific flags
	emailTapPorts   string
	emailTapAddress string
)

var emailTapCmd = &cobra.Command{
	Use:   "email",
	Short: "Standalone email capture with full processor capabilities",
	Long: `Run lippycat in standalone email tap mode.

Email tap mode combines local SMTP-optimized capture with full processor capabilities:
- Captures and analyzes SMTP traffic from local interfaces
- Provides auto-rotating PCAP writing
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode
- SMTP session tracking and correlation

This is ideal for single-machine email capture where you want:
- Real-time email monitoring via TUI
- Auto-rotating PCAP files for continuous capture
- Email address filtering

Example:
  lc tap email --interface eth0 --insecure
  lc tap email -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/email/pcaps
  lc tap email -i eth0 --smtp-port 25,587,2525
  lc tap email -i eth0 --address "*@example.com"`,
	RunE: runEmailTap,
}

func init() {
	TapCmd.AddCommand(emailTapCmd)

	// Email-specific flags
	emailTapCmd.Flags().StringVar(&emailTapPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")
	emailTapCmd.Flags().StringVar(&emailTapAddress, "address", "", "Filter by email address pattern (glob-style)")

	// Bind email-specific flags to viper
	_ = viper.BindPFlag("tap.email.ports", emailTapCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("tap.email.address", emailTapCmd.Flags().Lookup("address"))
}

func runEmailTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone Email tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("tap.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Build email filter
	filterBuilder := email.NewFilterBuilder()
	ports, err := email.ParsePorts(emailTapPorts)
	if err != nil {
		return fmt.Errorf("invalid --smtp-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
	filterConfig := email.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("Email BPF filter configured",
		"ports", emailTapPorts,
		"effective_filter", effectiveBPFFilter)

	// Build auto-rotate PCAP config - default for Email mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := getBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// Email mode should default to auto-rotate PCAP enabled
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
		effectiveTapID = hostname + "-email-tap"
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
		EnableDetection:       true, // Enable protocol detection
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

	// Create LocalSource for local packet capture with Email filter
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

	logger.Info("Email Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"smtp_ports", emailTapPorts,
		"address_filter", emailTapAddress,
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

	logger.Info("Email Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("Email Tap node failed", "error", err)
		return err
	}

	logger.Info("Email Tap node stopped")
	return nil
}
