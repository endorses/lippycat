//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/http"
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
	// HTTP-specific flags
	httpTapPorts            string
	httpTapHost             string
	httpTapPath             string
	httpTapMethods          string
	httpTapStatusCodes      string
	httpTapUserAgent        string
	httpTapContentType      string
	httpTapHostsFile        string
	httpTapPathsFile        string
	httpTapUserAgentsFile   string
	httpTapContentTypesFile string
	httpTapKeywordsFile     string
	httpTapCaptureBody      bool
	httpTapMaxBodySize      int

	// TLS decryption flags
	httpTapTLSKeylog     string
	httpTapTLSKeylogPipe string
)

var httpTapCmd = &cobra.Command{
	Use:   "http",
	Short: "Standalone HTTP capture with full processor capabilities",
	Long: `Run lippycat in standalone HTTP tap mode.

HTTP tap mode combines local HTTP-optimized capture with full processor capabilities:
- Captures and analyzes HTTP/1.x traffic from local interfaces
- Provides auto-rotating PCAP writing
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode
- Request/response tracking and correlation
- Content filtering (host, path, method, status, keywords)
- HTTPS decryption via SSLKEYLOGFILE

Filter Options:
  --host         Match host header (glob pattern)
  --path         Match request path/URL (glob pattern)
  --method       Match HTTP methods (comma-separated, e.g., "GET,POST")
  --status       Match status codes (e.g., "404", "4xx", "400-499")
  --user-agent   Match User-Agent header (glob pattern)
  --content-type Match Content-Type header (glob pattern)
  --keywords-file Keywords for body matching (Aho-Corasick)

Body Capture (for keyword matching in body):
  --capture-body      Enable body content capture (default: false)
  --max-body-size     Maximum body size to capture (default: 64KB)

TLS Decryption (HTTPS):
  --tls-keylog        Path to SSLKEYLOGFILE for HTTPS decryption
  --tls-keylog-pipe   Path to named pipe for real-time TLS key injection

Pattern Files (one pattern per line, # for comments):
  --hosts-file, --paths-file, --user-agents-file, --content-types-file

Example:
  lc tap http --interface eth0 --insecure
  lc tap http -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/http/pcaps
  lc tap http -i eth0 --http-port 80,8080,3000
  lc tap http -i eth0 --host "*.example.com"
  lc tap http -i eth0 --path "/api/*"
  lc tap http -i eth0 --method "POST,PUT"
  lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log --insecure`,
	RunE: runHTTPTap,
}

func init() {
	TapCmd.AddCommand(httpTapCmd)

	// HTTP-specific flags - single patterns
	httpTapCmd.Flags().StringVar(&httpTapPorts, "http-port", "80,8080,8000,3000,8888", "HTTP port(s) to capture, comma-separated")
	httpTapCmd.Flags().StringVar(&httpTapHost, "host", "", "Filter by host pattern (glob-style)")
	httpTapCmd.Flags().StringVar(&httpTapPath, "path", "", "Filter by path/URL pattern (glob-style)")
	httpTapCmd.Flags().StringVar(&httpTapMethods, "method", "", "Filter by HTTP methods (comma-separated)")
	httpTapCmd.Flags().StringVar(&httpTapStatusCodes, "status", "", "Filter by status codes (e.g., '404', '4xx')")
	httpTapCmd.Flags().StringVar(&httpTapUserAgent, "user-agent", "", "Filter by User-Agent pattern (glob-style)")
	httpTapCmd.Flags().StringVar(&httpTapContentType, "content-type", "", "Filter by Content-Type pattern (glob-style)")

	// HTTP filter file flags - bulk patterns
	httpTapCmd.Flags().StringVar(&httpTapHostsFile, "hosts-file", "", "Load host patterns from file (one per line)")
	httpTapCmd.Flags().StringVar(&httpTapPathsFile, "paths-file", "", "Load path patterns from file (one per line)")
	httpTapCmd.Flags().StringVar(&httpTapUserAgentsFile, "user-agents-file", "", "Load user-agent patterns from file (one per line)")
	httpTapCmd.Flags().StringVar(&httpTapContentTypesFile, "content-types-file", "", "Load content-type patterns from file (one per line)")
	httpTapCmd.Flags().StringVar(&httpTapKeywordsFile, "keywords-file", "", "Load keywords from file for body matching (Aho-Corasick)")

	// Body capture flags
	httpTapCmd.Flags().BoolVar(&httpTapCaptureBody, "capture-body", false, "Enable HTTP body content capture (for keyword matching)")
	httpTapCmd.Flags().IntVar(&httpTapMaxBodySize, "max-body-size", 65536, "Maximum body size to capture in bytes (default: 64KB)")

	// TLS decryption flags
	httpTapCmd.Flags().StringVar(&httpTapTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")
	httpTapCmd.Flags().StringVar(&httpTapTLSKeylogPipe, "tls-keylog-pipe", "", "Path to named pipe for real-time TLS key injection")

	// Bind HTTP-specific flags to viper
	_ = viper.BindPFlag("tap.http.ports", httpTapCmd.Flags().Lookup("http-port"))
	_ = viper.BindPFlag("tap.http.host_pattern", httpTapCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("tap.http.path_pattern", httpTapCmd.Flags().Lookup("path"))
	_ = viper.BindPFlag("tap.http.methods", httpTapCmd.Flags().Lookup("method"))
	_ = viper.BindPFlag("tap.http.status_codes", httpTapCmd.Flags().Lookup("status"))
	_ = viper.BindPFlag("tap.http.user_agent_pattern", httpTapCmd.Flags().Lookup("user-agent"))
	_ = viper.BindPFlag("tap.http.content_type_pattern", httpTapCmd.Flags().Lookup("content-type"))
	_ = viper.BindPFlag("tap.http.hosts_file", httpTapCmd.Flags().Lookup("hosts-file"))
	_ = viper.BindPFlag("tap.http.paths_file", httpTapCmd.Flags().Lookup("paths-file"))
	_ = viper.BindPFlag("tap.http.user_agents_file", httpTapCmd.Flags().Lookup("user-agents-file"))
	_ = viper.BindPFlag("tap.http.content_types_file", httpTapCmd.Flags().Lookup("content-types-file"))
	_ = viper.BindPFlag("tap.http.keywords_file", httpTapCmd.Flags().Lookup("keywords-file"))
	_ = viper.BindPFlag("tap.http.capture_body", httpTapCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("tap.http.max_body_size", httpTapCmd.Flags().Lookup("max-body-size"))
	_ = viper.BindPFlag("tap.http.tls_keylog", httpTapCmd.Flags().Lookup("tls-keylog"))
	_ = viper.BindPFlag("tap.http.tls_keylog_pipe", httpTapCmd.Flags().Lookup("tls-keylog-pipe"))
}

func runHTTPTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone HTTP tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if getBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Set HTTP filter patterns from flags
	if cmd.Flags().Changed("host") {
		viper.Set("http.host_pattern", httpTapHost)
	}
	if cmd.Flags().Changed("path") {
		viper.Set("http.path_pattern", httpTapPath)
	}
	if cmd.Flags().Changed("method") {
		methods := http.ParseMethods(httpTapMethods)
		viper.Set("http.methods", methods)
	}
	if cmd.Flags().Changed("status") {
		statusCodes := http.ParseStatusCodes(httpTapStatusCodes)
		viper.Set("http.status_codes", statusCodes)
	}
	if cmd.Flags().Changed("user-agent") {
		viper.Set("http.user_agent_pattern", httpTapUserAgent)
	}
	if cmd.Flags().Changed("content-type") {
		viper.Set("http.content_type_pattern", httpTapContentType)
	}
	if cmd.Flags().Changed("capture-body") {
		viper.Set("http.capture_body", httpTapCaptureBody)
	}
	if cmd.Flags().Changed("max-body-size") {
		viper.Set("http.max_body_size", httpTapMaxBodySize)
	}

	// Load patterns from files if specified
	if httpTapHostsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpTapHostsFile)
		if err != nil {
			return fmt.Errorf("failed to load hosts file: %w", err)
		}
		viper.Set("http.host_patterns", patterns)
		logger.Info("Loaded host patterns from file", "count", len(patterns), "file", httpTapHostsFile)
	}

	if httpTapPathsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpTapPathsFile)
		if err != nil {
			return fmt.Errorf("failed to load paths file: %w", err)
		}
		viper.Set("http.url_patterns", patterns)
		logger.Info("Loaded path patterns from file", "count", len(patterns), "file", httpTapPathsFile)
	}

	if httpTapUserAgentsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpTapUserAgentsFile)
		if err != nil {
			return fmt.Errorf("failed to load user-agents file: %w", err)
		}
		viper.Set("http.user_agent_patterns", patterns)
		logger.Info("Loaded user-agent patterns from file", "count", len(patterns), "file", httpTapUserAgentsFile)
	}

	if httpTapContentTypesFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpTapContentTypesFile)
		if err != nil {
			return fmt.Errorf("failed to load content-types file: %w", err)
		}
		viper.Set("http.content_type_patterns", patterns)
		logger.Info("Loaded content-type patterns from file", "count", len(patterns), "file", httpTapContentTypesFile)
	}

	if httpTapKeywordsFile != "" {
		keywords, err := http.LoadKeywordsFromFile(httpTapKeywordsFile)
		if err != nil {
			return fmt.Errorf("failed to load keywords file: %w", err)
		}
		viper.Set("http.keywords", keywords)
		logger.Info("Loaded keywords from file", "count", len(keywords), "file", httpTapKeywordsFile)
	}

	// Configure TLS decryption if specified
	tlsKeylogPath := httpTapTLSKeylog
	if tlsKeylogPath == "" {
		tlsKeylogPath = httpTapTLSKeylogPipe
	}
	if tlsKeylogPath != "" {
		decryptConfig := tls.DecryptConfig{
			KeylogFile: httpTapTLSKeylog,
			KeylogPipe: httpTapTLSKeylogPipe,
		}
		if err := decryptConfig.Validate(); err != nil {
			return fmt.Errorf("invalid TLS keylog configuration: %w", err)
		}
		viper.Set("http.tls_keylog", tlsKeylogPath)
		viper.Set("http.tls_decryption_enabled", true)
		logger.Info("TLS decryption configured", "keylog", tlsKeylogPath)
	}

	// Build HTTP filter
	filterBuilder := http.NewFilterBuilder()
	ports, err := http.ParsePorts(httpTapPorts)
	if err != nil {
		return fmt.Errorf("invalid --http-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
	filterConfig := http.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("HTTP BPF filter configured",
		"ports", httpTapPorts,
		"effective_filter", effectiveBPFFilter)

	// Build auto-rotate PCAP config - default for HTTP mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := getBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// HTTP mode should default to auto-rotate PCAP enabled
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
		effectiveTapID = hostname + "-http-tap"
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
		EnableDetection:       true, // Enable protocol detection
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

	// Create LocalSource for local packet capture with HTTP filter
	localSourceConfig := source.LocalSourceConfig{
		Interfaces:   getStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    effectiveBPFFilter,
		BatchSize:    getIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(getIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   getIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
		ProcessorID:  effectiveTapID, // For virtual hunter ID generation
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

	// Set the local source and target on the processor
	p.SetPacketSource(localSource)
	p.SetFilterTarget(localTarget)

	mode := "standalone"
	if config.UpstreamAddr != "" {
		mode = "hierarchical"
	}

	logger.Info("HTTP Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"bpf_filter", localSourceConfig.BPFFilter,
		"http_ports", httpTapPorts,
		"host_filter", httpTapHost,
		"path_filter", httpTapPath,
		"method_filter", httpTapMethods,
		"status_filter", httpTapStatusCodes,
		"auto_rotate_pcap", effectiveAutoRotate,
		"tls_decryption", tlsKeylogPath != "",
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

	logger.Info("HTTP Tap node started successfully",
		"listen", config.ListenAddr,
		"mode", mode)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		time.Sleep(constants.GracefulShutdownTimeout)
	case err := <-errChan:
		logger.Error("HTTP Tap node failed", "error", err)
		return err
	}

	logger.Info("HTTP Tap node stopped")
	return nil
}
