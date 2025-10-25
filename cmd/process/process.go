//go:build processor || all
// +build processor all

package process

import (
	"context"
	"fmt"
	"os"
	"time"

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

Example:
  lc process --listen :50051
  lc process --listen 0.0.0.0:50051 --upstream parent:50051
  lc process --listen :50051 --max-hunters 100`,
	RunE: runProcess,
}

var (
	listenAddr      string
	processorID     string
	upstreamAddr    string
	maxHunters      int
	maxSubscribers  int
	writeFile       string
	displayStats    bool
	enableDetection bool
	filterFile      string
	// TLS flags
	tlsEnabled      bool
	tlsCertFile     string
	tlsKeyFile      string
	tlsCAFile       string
	tlsClientAuth   bool
	insecureAllowed bool
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
)

func init() {
	// Required flags
	ProcessCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":50051", "Listen address for hunter connections (host:port)")

	// Processor configuration
	ProcessCmd.Flags().StringVarP(&processorID, "processor-id", "", "", "Unique processor identifier (default: hostname)")
	ProcessCmd.Flags().StringVarP(&upstreamAddr, "upstream", "u", "", "Upstream processor address for hierarchical mode (host:port)")
	ProcessCmd.Flags().IntVarP(&maxHunters, "max-hunters", "m", 100, "Maximum number of concurrent hunter connections")
	ProcessCmd.Flags().IntVarP(&maxSubscribers, "max-subscribers", "", 100, "Maximum number of concurrent TUI/monitoring subscribers (0 = unlimited)")
	ProcessCmd.Flags().StringVarP(&writeFile, "write-file", "w", "", "Write received packets to PCAP file")
	ProcessCmd.Flags().BoolVarP(&displayStats, "stats", "s", true, "Display statistics")
	ProcessCmd.Flags().BoolVarP(&enableDetection, "enable-detection", "d", true, "Enable centralized protocol detection (default: true)")
	ProcessCmd.Flags().StringVarP(&filterFile, "filter-file", "f", "", "Path to filter persistence file (YAML, default: ~/.config/lippycat/filters.yaml)")

	// TLS configuration (security)
	ProcessCmd.Flags().BoolVar(&tlsEnabled, "tls", false, "Enable TLS encryption (recommended for production)")
	ProcessCmd.Flags().StringVar(&tlsCertFile, "tls-cert", "", "Path to server TLS certificate")
	ProcessCmd.Flags().StringVar(&tlsKeyFile, "tls-key", "", "Path to server TLS key")
	ProcessCmd.Flags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for client verification (mutual TLS)")
	ProcessCmd.Flags().BoolVar(&tlsClientAuth, "tls-client-auth", false, "Require client certificate authentication (mutual TLS)")
	ProcessCmd.Flags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS (must be explicitly set)")

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
	ProcessCmd.Flags().BoolVar(&virtualInterface, "virtual-interface", false, "Enable virtual network interface for packet injection")
	ProcessCmd.Flags().StringVar(&virtualInterfaceName, "vif-name", "lc0", "Virtual interface name (default: lc0)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("processor.listen_addr", ProcessCmd.Flags().Lookup("listen"))
	_ = viper.BindPFlag("processor.processor_id", ProcessCmd.Flags().Lookup("processor-id"))
	_ = viper.BindPFlag("processor.upstream_addr", ProcessCmd.Flags().Lookup("upstream"))
	_ = viper.BindPFlag("processor.max_hunters", ProcessCmd.Flags().Lookup("max-hunters"))
	_ = viper.BindPFlag("processor.max_subscribers", ProcessCmd.Flags().Lookup("max-subscribers"))
	_ = viper.BindPFlag("processor.write_file", ProcessCmd.Flags().Lookup("write-file"))
	_ = viper.BindPFlag("processor.display_stats", ProcessCmd.Flags().Lookup("stats"))
	_ = viper.BindPFlag("processor.enable_detection", ProcessCmd.Flags().Lookup("enable-detection"))
	_ = viper.BindPFlag("processor.filter_file", ProcessCmd.Flags().Lookup("filter-file"))
	_ = viper.BindPFlag("processor.tls.enabled", ProcessCmd.Flags().Lookup("tls"))
	_ = viper.BindPFlag("processor.tls.cert_file", ProcessCmd.Flags().Lookup("tls-cert"))
	_ = viper.BindPFlag("processor.tls.key_file", ProcessCmd.Flags().Lookup("tls-key"))
	_ = viper.BindPFlag("processor.tls.ca_file", ProcessCmd.Flags().Lookup("tls-ca"))
	_ = viper.BindPFlag("processor.tls.client_auth", ProcessCmd.Flags().Lookup("tls-client-auth"))
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
}

func runProcess(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in processor mode")

	// Production mode enforcement: check early before creating config
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("processor.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
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

	// Get configuration (flags override config file)
	config := processor.Config{
		ListenAddr:       getStringConfig("processor.listen_addr", listenAddr),
		ProcessorID:      getStringConfig("processor.processor_id", processorID),
		UpstreamAddr:     getStringConfig("processor.upstream_addr", upstreamAddr),
		MaxHunters:       getIntConfig("processor.max_hunters", maxHunters),
		MaxSubscribers:   getIntConfig("processor.max_subscribers", maxSubscribers),
		WriteFile:        getStringConfig("processor.write_file", writeFile),
		DisplayStats:     getBoolConfig("processor.display_stats", displayStats),
		PcapWriterConfig: pcapWriterConfig,
		AutoRotateConfig: autoRotateConfig,
		EnableDetection:  getBoolConfig("processor.enable_detection", enableDetection),
		FilterFile:       getStringConfig("processor.filter_file", filterFile),
		// TLS configuration
		TLSEnabled:    getBoolConfig("processor.tls.enabled", tlsEnabled),
		TLSCertFile:   getStringConfig("processor.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("processor.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("processor.tls.ca_file", tlsCAFile),
		TLSClientAuth: getBoolConfig("processor.tls.client_auth", tlsClientAuth),
		// Virtual interface configuration
		VirtualInterface:     getBoolConfig("processor.virtual_interface", virtualInterface),
		VirtualInterfaceName: getStringConfig("processor.vif_name", virtualInterfaceName),
	}

	// Security check: require explicit opt-in to insecure mode
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-cert=/path/to/server.crt --tls-key=/path/to/server.key\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure\n\n" +
			"WARNING: Insecure mode accepts unencrypted connections from hunters!")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Server will accept UNENCRYPTED hunter connections")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("  Enable TLS: --tls --tls-cert=server.crt --tls-key=server.key")
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
