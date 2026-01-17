//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// HTTP-specific flags for hunter mode
	hunterHTTPPorts string

	// Content filter flags for local filtering (in addition to processor-pushed filters)
	hunterHTTPHost        string // Host patterns (comma-separated)
	hunterHTTPPath        string // Path patterns (comma-separated)
	hunterHTTPMethods     string // HTTP methods (comma-separated)
	hunterHTTPStatusCodes string // Status codes (comma-separated)
	hunterHTTPKeywords    string // Body/URL keyword patterns (comma-separated)
	hunterHTTPCaptureBody bool   // Enable body capture for keyword filtering
	hunterHTTPMaxBodySize int    // Max body size to capture (bytes)

	// TLS decryption flags
	hunterHTTPTLSKeylog     string // Path to SSLKEYLOGFILE
	hunterHTTPTLSKeylogPipe string // Path to named pipe for key injection
)

var httpHuntCmd = &cobra.Command{
	Use:   "http",
	Short: "Run as HTTP hunter with content filtering",
	Long: `Run lippycat in HTTP hunter mode with TCP reassembly and content filtering.

HTTP hunter mode captures HTTP traffic, reassembles TCP streams, applies
content filtering (including body keyword matching), and forwards matched
HTTP requests/responses to the processor.

Features:
- HTTP TCP stream reassembly for complete message parsing
- Port filtering (default: 80, 8080, 8000, 3000, 8888)
- Host/path filtering (glob patterns)
- Method and status code filtering
- Body content keyword filtering (Aho-Corasick)
- Efficient forwarding to processor
- HTTPS decryption via SSLKEYLOGFILE (forwards encrypted + keys to processor)

Filters can be specified locally (flags) or pushed from the processor.
Local filters apply in addition to processor-pushed filters.

TLS Decryption (HTTPS):
  --tls-keylog        Path to SSLKEYLOGFILE for HTTPS decryption
  --tls-keylog-pipe   Path to named pipe for real-time TLS key injection

When TLS decryption is enabled, the hunter decrypts traffic locally to apply
content filters, then forwards the original encrypted packets plus session
keys to the processor. The processor stores encrypted PCAP + keylog files
(Wireshark-compatible) for audit integrity.

Example:
  lc hunt http --processor processor:50051
  lc hunt http --processor 192.168.1.100:50051 --interface eth0
  lc hunt http --processor processor:50051 --http-port 80,8080,3000
  lc hunt http --processor processor:50051 --host "*.example.com"
  lc hunt http --processor processor:50051 --path "/api/*"
  lc hunt http --processor processor:50051 --method "POST,PUT"
  lc hunt http --processor processor:50051 --keywords "password,secret" --capture-body
  lc hunt http --processor processor:50051 --tls-keylog /tmp/sslkeys.log`,
	RunE: runHTTPHunt,
}

func init() {
	HuntCmd.AddCommand(httpHuntCmd)

	// HTTP-specific flags (BPF-level filtering)
	httpHuntCmd.Flags().StringVar(&hunterHTTPPorts, "http-port", "80,8080,8000,3000,8888", "HTTP port(s) to capture, comma-separated")

	// Content filter flags for local filtering
	httpHuntCmd.Flags().StringVar(&hunterHTTPHost, "host", "", "Host patterns (comma-separated, glob-style)")
	httpHuntCmd.Flags().StringVar(&hunterHTTPPath, "path", "", "Path patterns (comma-separated, glob-style)")
	httpHuntCmd.Flags().StringVar(&hunterHTTPMethods, "method", "", "HTTP methods (comma-separated)")
	httpHuntCmd.Flags().StringVar(&hunterHTTPStatusCodes, "status", "", "Status codes (comma-separated)")
	httpHuntCmd.Flags().StringVar(&hunterHTTPKeywords, "keywords", "", "Body/URL keywords (comma-separated)")
	httpHuntCmd.Flags().BoolVar(&hunterHTTPCaptureBody, "capture-body", false, "Enable body capture for keyword filtering")
	httpHuntCmd.Flags().IntVar(&hunterHTTPMaxBodySize, "max-body-size", 65536, "Max body size to capture in bytes (default: 64KB)")

	// TLS decryption flags
	httpHuntCmd.Flags().StringVar(&hunterHTTPTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")
	httpHuntCmd.Flags().StringVar(&hunterHTTPTLSKeylogPipe, "tls-keylog-pipe", "", "Path to named pipe for real-time TLS key injection")

	// Bind to viper
	_ = viper.BindPFlag("hunter.http.ports", httpHuntCmd.Flags().Lookup("http-port"))
	_ = viper.BindPFlag("hunter.http.host", httpHuntCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("hunter.http.path", httpHuntCmd.Flags().Lookup("path"))
	_ = viper.BindPFlag("hunter.http.method", httpHuntCmd.Flags().Lookup("method"))
	_ = viper.BindPFlag("hunter.http.status", httpHuntCmd.Flags().Lookup("status"))
	_ = viper.BindPFlag("hunter.http.keywords", httpHuntCmd.Flags().Lookup("keywords"))
	_ = viper.BindPFlag("hunter.http.capture_body", httpHuntCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("hunter.http.max_body_size", httpHuntCmd.Flags().Lookup("max-body-size"))
	_ = viper.BindPFlag("hunter.http.tls_keylog", httpHuntCmd.Flags().Lookup("tls-keylog"))
	_ = viper.BindPFlag("hunter.http.tls_keylog_pipe", httpHuntCmd.Flags().Lookup("tls-keylog-pipe"))
}

func runHTTPHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in HTTP hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build HTTP filter
	filterBuilder := http.NewFilterBuilder()
	ports, err := http.ParsePorts(hunterHTTPPorts)
	if err != nil {
		return fmt.Errorf("invalid --http-port value: %w", err)
	}

	baseBPFFilter := cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := http.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("HTTP BPF filter configured",
		"ports", hunterHTTPPorts,
		"effective_filter", effectiveBPFFilter)

	// Configure TLS decryption if specified
	tlsKeylogPath := hunterHTTPTLSKeylog
	if tlsKeylogPath == "" {
		tlsKeylogPath = hunterHTTPTLSKeylogPipe
	}
	if tlsKeylogPath != "" {
		decryptConfig := tls.DecryptConfig{
			KeylogFile: hunterHTTPTLSKeylog,
			KeylogPipe: hunterHTTPTLSKeylogPipe,
		}
		if err := decryptConfig.Validate(); err != nil {
			return fmt.Errorf("invalid TLS keylog configuration: %w", err)
		}
		viper.Set("http.tls_keylog", tlsKeylogPath)
		viper.Set("http.tls_decryption_enabled", true)
		logger.Info("TLS decryption configured (keys will be forwarded to processor)",
			"keylog", tlsKeylogPath)
	}

	// Get configuration (reuse flags from parent command)
	config := hunter.Config{
		ProcessorAddr:  cmdutil.GetStringConfig("hunter.processor_addr", processorAddr),
		HunterID:       cmdutil.GetStringConfig("hunter.hunter_id", hunterID),
		Interfaces:     cmdutil.GetStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:      effectiveBPFFilter,
		BufferSize:     cmdutil.GetIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:      cmdutil.GetIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:   time.Duration(cmdutil.GetIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize: cmdutil.GetIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:       false, // Not VoIP mode
		// HTTP hunter supports BPF, IP, and HTTP host/path filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"},
		// TLS configuration (enabled by default unless --insecure is set)
		TLSEnabled:    !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:   cmdutil.GetStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:    cmdutil.GetStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:     cmdutil.GetStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify: cmdutil.GetBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
	}

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
		logger.Warn("═══════════════════════════════════════════════════════════")
	} else {
		logger.Info("═══════════════════════════════════════════════════════════")
		logger.Info("  Security: TLS ENABLED ✓")
		logger.Info("  All traffic to processor will be encrypted")
		logger.Info("═══════════════════════════════════════════════════════════")
	}

	// Set default hunter ID
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

	logger.Info("HTTP Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"http_ports", hunterHTTPPorts,
		"tls_decryption", tlsKeylogPath != "")

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

	// Build content filter from flags (local filters)
	contentFilter := buildHTTPContentFilter()

	// Create HTTP packet processor with content filtering
	processorConfig := http.ProcessorConfig{
		HostPatterns:  splitAndTrimHTTP(hunterHTTPHost),
		PathPatterns:  splitAndTrimHTTP(hunterHTTPPath),
		Methods:       splitAndTrimHTTP(hunterHTTPMethods),
		ContentFilter: contentFilter,
	}

	processor := http.NewProcessor(processorConfig)
	defer processor.Stop()

	// Set the packet processor on the hunter
	h.SetPacketProcessor(processor)

	logger.Info("HTTP hunter initialized with content filtering",
		"has_host_filter", len(hunterHTTPHost) > 0,
		"has_path_filter", len(hunterHTTPPath) > 0,
		"has_method_filter", len(hunterHTTPMethods) > 0,
		"has_keywords", len(hunterHTTPKeywords) > 0,
		"capture_body", hunterHTTPCaptureBody)

	// Start hunter in background
	errChan := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		if err := h.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	// Wait for error or context cancellation
	select {
	case err := <-errChan:
		return fmt.Errorf("hunter error: %w", err)
	case <-ctx.Done():
		logger.Info("Shutdown signal received, stopping HTTP hunter...")
		return nil
	}
}

// buildHTTPContentFilter creates a ContentFilter from command-line flags.
func buildHTTPContentFilter() *http.ContentFilter {
	cfg := http.ContentFilterConfig{}

	// Parse comma-separated patterns
	if hunterHTTPHost != "" {
		cfg.HostPatterns = splitAndTrimHTTP(hunterHTTPHost)
	}
	if hunterHTTPPath != "" {
		cfg.URLPatterns = splitAndTrimHTTP(hunterHTTPPath)
	}
	if hunterHTTPMethods != "" {
		cfg.Methods = splitAndTrimHTTP(hunterHTTPMethods)
	}
	if hunterHTTPStatusCodes != "" {
		cfg.StatusCodes = splitAndTrimHTTP(hunterHTTPStatusCodes)
	}
	if hunterHTTPKeywords != "" {
		cfg.Keywords = splitAndTrimHTTP(hunterHTTPKeywords)
	}

	return http.NewContentFilter(cfg)
}

// splitAndTrimHTTP splits a comma-separated string and trims whitespace.
func splitAndTrimHTTP(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
