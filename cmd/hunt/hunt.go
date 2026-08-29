//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/debugserver"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var HuntCmd = &cobra.Command{
	Use:   "hunt",
	Short: "Run as hunter node (edge packet capture)",
	Long: `Run lippycat in hunter mode.

Hunter nodes capture packets at the network edge and forward
matched packets to a central processor node via gRPC.

Hunters apply local filters to reduce bandwidth and only send
relevant packets upstream.

Example:
  lc hunt --processor processor.example.com:55555
  lc hunt --processor 192.168.1.100:55555 --interface eth0
  lc hunt --processor processor:55555 --id edge-01`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := debugserver.StartPprofFromConfig(
			cmdutil.GetStringConfig("hunter.debug_listen", debugListen),
			cmdutil.GetBoolConfig("hunter.debug_allow_non_loopback", debugAllowNonLoopback),
		); err != nil {
			return err
		}
		// Handle deprecated --hunter-id flag migration to --id
		if cmd.Flags().Changed("hunter-id") {
			if cmd.Flags().Changed("id") {
				return fmt.Errorf("cannot use both --hunter-id (deprecated) and --id; use --id only")
			}
			hunterID = hunterIDDeprecated
			logger.Warn("--hunter-id is deprecated, use --id instead")
		}
		return nil
	},
	RunE: runHunt,
}

var (
	processorAddr      string
	hunterID           string // renamed from hunter-id, now --id
	hunterIDDeprecated string // deprecated, use hunterID
	interfaces         []string
	bpfFilter          string
	pcapBufferSize     int
	bufferSize         int
	batchSize          int
	batchTimeout       int
	batchQueueSize     int
	promiscuous        bool
	// Disk buffer flags (nuclear-proof resilience)
	diskBufferEnabled bool
	diskBufferDir     string
	diskBufferMaxSize int // MB
	// TLS flags (TLS is enabled by default unless --insecure is set)
	tlsCertFile     string
	tlsKeyFile      string
	tlsCAFile       string
	tlsSkipVerify   bool
	insecureAllowed bool
	// Filter policy
	noFilterPolicy string

	// ESP-NULL decapsulation flags
	espNull      bool
	espHeuristic bool
	espICVSize   int
	// Debug/pprof flags
	debugListen           string
	debugAllowNonLoopback bool
)

func init() {
	// Required flags (persistent so subcommands inherit them)
	HuntCmd.PersistentFlags().StringVarP(&processorAddr, "processor", "P", "", "Processor address (host:port)")
	_ = HuntCmd.MarkPersistentFlagRequired("processor") // Error only occurs with invalid flag name (hard-coded string)

	// Hunter configuration (persistent for subcommands)
	// --id is the new flag, --hunter-id is deprecated
	HuntCmd.PersistentFlags().StringVarP(&hunterID, "id", "I", "", "Unique hunter identifier (default: hostname)")
	HuntCmd.PersistentFlags().StringVar(&hunterIDDeprecated, "hunter-id", "", "")
	HuntCmd.PersistentFlags().Lookup("hunter-id").Deprecated = "use --id instead"
	HuntCmd.PersistentFlags().Lookup("hunter-id").Hidden = true
	HuntCmd.PersistentFlags().StringSliceVarP(&interfaces, "interface", "i", []string{"any"}, "Network interfaces to capture (comma-separated)")
	HuntCmd.PersistentFlags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
	HuntCmd.PersistentFlags().BoolVarP(&promiscuous, "promisc", "p", false, "Enable promiscuous mode")
	HuntCmd.PersistentFlags().IntVar(&pcapBufferSize, "pcap-buffer-size", 16*1024*1024, "Kernel pcap buffer size in bytes (default 16MB, increase for high-traffic interfaces)")

	// Performance tuning (persistent for subcommands)
	HuntCmd.PersistentFlags().IntVarP(&bufferSize, "buffer-size", "b", 10000, "Packet buffer size")
	HuntCmd.PersistentFlags().IntVarP(&batchSize, "batch-size", "", 64, "Packets per batch sent to processor")
	HuntCmd.PersistentFlags().IntVarP(&batchTimeout, "batch-timeout", "", 100, "Batch timeout in milliseconds")
	HuntCmd.PersistentFlags().IntVarP(&batchQueueSize, "batch-queue-size", "", 0, "Batch queue buffer size (0 = default: 1000)")

	// VoIP filtering with GPU acceleration (only registered in CUDA builds)
	RegisterGPUFlags(HuntCmd)

	// Disk overflow buffer (nuclear-proof resilience) - persistent for subcommands
	HuntCmd.PersistentFlags().BoolVar(&diskBufferEnabled, "disk-buffer", false, "Enable disk overflow buffer (for extended disconnections)")
	HuntCmd.PersistentFlags().StringVar(&diskBufferDir, "disk-buffer-dir", "/var/tmp/lippycat-buffer", "Directory for disk buffer files")
	HuntCmd.PersistentFlags().IntVar(&diskBufferMaxSize, "disk-buffer-max-mb", 1024, "Maximum disk buffer size in megabytes")

	// TLS configuration (security) - persistent for subcommands
	// TLS is enabled by default unless --insecure is explicitly set
	HuntCmd.PersistentFlags().StringVar(&tlsCertFile, "tls-cert", "", "Path to client TLS certificate (for mutual TLS)")
	HuntCmd.PersistentFlags().StringVar(&tlsKeyFile, "tls-key", "", "Path to client TLS key (for mutual TLS)")
	HuntCmd.PersistentFlags().StringVar(&tlsCAFile, "tls-ca", "", "Path to CA certificate for server verification")
	HuntCmd.PersistentFlags().BoolVar(&tlsSkipVerify, "tls-skip-verify", false, "Skip TLS certificate verification (INSECURE - testing only)")
	HuntCmd.PersistentFlags().BoolVar(&insecureAllowed, "insecure", false, "Allow insecure connections without TLS (must be explicitly set)")

	// ESP-NULL Decapsulation (persistent for voip subcommand)
	HuntCmd.PersistentFlags().BoolVar(&espNull, "esp-null", false, "Assume all ESP traffic is NULL-encrypted (skip content heuristics)")
	HuntCmd.PersistentFlags().BoolVar(&espHeuristic, "esp-heuristic", false, "Detect ESP-NULL traffic by sniffing payload content (off by default)")
	HuntCmd.PersistentFlags().IntVar(&espICVSize, "esp-icv-size", -1, "ESP ICV size in bytes (0, 8, 12, 16; -1 = auto-detect). Requires --esp-null")
	HuntCmd.PersistentFlags().StringVar(&debugListen, "debug-listen", "", "Enable pprof debug HTTP listener on address (loopback only by default, e.g. 127.0.0.1:6060)")
	HuntCmd.PersistentFlags().BoolVar(&debugAllowNonLoopback, "debug-allow-non-loopback", false, "Allow pprof debug listener to bind non-loopback addresses")

	// Filter policy configuration
	HuntCmd.PersistentFlags().StringVar(&noFilterPolicy, "no-filter-policy", "deny", "Behavior when no filters are configured: 'allow' (match all) or 'deny' (match none)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("hunter.processor_addr", HuntCmd.PersistentFlags().Lookup("processor"))
	_ = viper.BindPFlag("hunter.id", HuntCmd.PersistentFlags().Lookup("id"))
	// Also bind to old key for backward compatibility with config files
	_ = viper.BindPFlag("hunter.hunter_id", HuntCmd.PersistentFlags().Lookup("id"))
	_ = viper.BindPFlag("hunter.interfaces", HuntCmd.PersistentFlags().Lookup("interface"))
	_ = viper.BindPFlag("hunter.bpf_filter", HuntCmd.PersistentFlags().Lookup("filter"))
	_ = viper.BindPFlag("hunter.buffer_size", HuntCmd.PersistentFlags().Lookup("buffer-size"))
	_ = viper.BindPFlag("hunter.batch_size", HuntCmd.PersistentFlags().Lookup("batch-size"))
	_ = viper.BindPFlag("hunter.batch_timeout_ms", HuntCmd.PersistentFlags().Lookup("batch-timeout"))
	_ = viper.BindPFlag("hunter.batch_queue_size", HuntCmd.PersistentFlags().Lookup("batch-queue-size"))
	_ = viper.BindPFlag("promiscuous", HuntCmd.PersistentFlags().Lookup("promisc"))
	_ = viper.BindPFlag("pcap_buffer_size", HuntCmd.PersistentFlags().Lookup("pcap-buffer-size"))
	// GPU viper bindings (only in CUDA builds)
	BindGPUViperFlags(HuntCmd)
	_ = viper.BindPFlag("hunter.disk_buffer.enabled", HuntCmd.PersistentFlags().Lookup("disk-buffer"))
	_ = viper.BindPFlag("hunter.disk_buffer.dir", HuntCmd.PersistentFlags().Lookup("disk-buffer-dir"))
	_ = viper.BindPFlag("hunter.disk_buffer.max_mb", HuntCmd.PersistentFlags().Lookup("disk-buffer-max-mb"))
	_ = viper.BindPFlag("hunter.tls.cert_file", HuntCmd.PersistentFlags().Lookup("tls-cert"))
	_ = viper.BindPFlag("hunter.tls.key_file", HuntCmd.PersistentFlags().Lookup("tls-key"))
	_ = viper.BindPFlag("hunter.tls.ca_file", HuntCmd.PersistentFlags().Lookup("tls-ca"))
	_ = viper.BindPFlag("hunter.tls.skip_verify", HuntCmd.PersistentFlags().Lookup("tls-skip-verify"))
	_ = viper.BindPFlag("hunter.insecure", HuntCmd.PersistentFlags().Lookup("insecure"))
	_ = viper.BindPFlag("hunter.no_filter_policy", HuntCmd.PersistentFlags().Lookup("no-filter-policy"))

	// ESP-NULL decapsulation
	_ = viper.BindPFlag("esp_null", HuntCmd.PersistentFlags().Lookup("esp-null"))
	_ = viper.BindPFlag("esp_heuristic", HuntCmd.PersistentFlags().Lookup("esp-heuristic"))
	_ = viper.BindPFlag("esp_icv_size", HuntCmd.PersistentFlags().Lookup("esp-icv-size"))
	_ = viper.BindPFlag("hunter.debug_listen", HuntCmd.PersistentFlags().Lookup("debug-listen"))
	_ = viper.BindPFlag("hunter.debug_allow_non_loopback", HuntCmd.PersistentFlags().Lookup("debug-allow-non-loopback"))
}

func runHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in hunter mode")

	// Production mode enforcement: check early before creating config
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Get configuration (flags override config file)
	config := buildHunterConfig(hunterConfigSpec{
		bpfFilter:           cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter),
		useGPUFlag:          true,
		includeDiskBuffer:   true,
		includeFilterPolicy: true,
	})

	// Validate TLS configuration: CA file required when TLS is enabled
	if config.TLSEnabled && config.TLSCAFile == "" && !config.TLSSkipVerify {
		return fmt.Errorf("TLS enabled but no CA certificate provided\n\n" +
			"For TLS connections, provide a CA certificate: --tls-ca=/path/to/ca.crt\n" +
			"Or skip verification (INSECURE - testing only): --tls-skip-verify\n" +
			"Or disable TLS entirely (NOT RECOMMENDED): --insecure")
	}

	// Display security banner
	if !config.TLSEnabled {
		logger.Warn("═══════════════════════════════════════════════════════════")
		logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
		logger.Warn("  Packet data will be transmitted in CLEARTEXT")
		logger.Warn("  This mode should ONLY be used in trusted networks")
		logger.Warn("  Enable TLS for production: --tls-ca=/path/to/ca.crt")
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED ✓")
		logger.Info("  All traffic to processor will be encrypted")
		logger.Info("═══════════════════════════════════════════════════════════")
	}

	// Set default hunter ID to hostname if not specified
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

	logger.Info("Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"buffer_size", config.BufferSize,
		"batch_size", config.BatchSize)

	// Create hunter instance
	h, err := hunter.New(config)
	if err != nil {
		return fmt.Errorf("failed to create hunter: %w", err)
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

	logger.Info("Hunter started successfully",
		"processor", config.ProcessorAddr,
		"hunter_id", config.HunterID)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		// Signal received, give some time for graceful shutdown
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("Hunter failed", "error", err)
		return err
	}

	logger.Info("Hunter stopped")
	return nil
}
