//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
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

Filters can be specified locally (flags) or pushed from the processor.
Local filters apply in addition to processor-pushed filters.

Example:
  lc hunt http --processor processor:50051
  lc hunt http --processor 192.168.1.100:50051 --interface eth0
  lc hunt http --processor processor:50051 --http-port 80,8080,3000
  lc hunt http --processor processor:50051 --host "*.example.com"
  lc hunt http --processor processor:50051 --path "/api/*"
  lc hunt http --processor processor:50051 --method "POST,PUT"
  lc hunt http --processor processor:50051 --keywords "password,secret" --capture-body`,
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

	// Bind to viper
	_ = viper.BindPFlag("hunter.http.ports", httpHuntCmd.Flags().Lookup("http-port"))
	_ = viper.BindPFlag("hunter.http.host", httpHuntCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("hunter.http.path", httpHuntCmd.Flags().Lookup("path"))
	_ = viper.BindPFlag("hunter.http.method", httpHuntCmd.Flags().Lookup("method"))
	_ = viper.BindPFlag("hunter.http.status", httpHuntCmd.Flags().Lookup("status"))
	_ = viper.BindPFlag("hunter.http.keywords", httpHuntCmd.Flags().Lookup("keywords"))
	_ = viper.BindPFlag("hunter.http.capture_body", httpHuntCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("hunter.http.max_body_size", httpHuntCmd.Flags().Lookup("max-body-size"))
}

func runHTTPHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in HTTP hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build HTTP filter
	filterBuilder := http.NewFilterBuilder()
	ports, err := http.ParsePorts(hunterHTTPPorts)
	if err != nil {
		return fmt.Errorf("invalid --http-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := http.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("HTTP BPF filter configured",
		"ports", hunterHTTPPorts,
		"effective_filter", effectiveBPFFilter)

	// Get configuration (reuse flags from parent command)
	config := hunter.Config{
		ProcessorAddr:  getStringConfig("hunter.processor_addr", processorAddr),
		HunterID:       getStringConfig("hunter.hunter_id", hunterID),
		Interfaces:     getStringSliceConfig("hunter.interfaces", interfaces),
		BPFFilter:      effectiveBPFFilter,
		BufferSize:     getIntConfig("hunter.buffer_size", bufferSize),
		BatchSize:      getIntConfig("hunter.batch_size", batchSize),
		BatchTimeout:   time.Duration(getIntConfig("hunter.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BatchQueueSize: getIntConfig("hunter.batch_queue_size", batchQueueSize),
		VoIPMode:       false, // Not VoIP mode
		// HTTP hunter supports BPF, IP, and HTTP host/path filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "http_host", "http_path"},
		// TLS configuration
		TLSEnabled:    getBoolConfig("hunter.tls.enabled", tlsEnabled),
		TLSCertFile:   getStringConfig("hunter.tls.cert_file", tlsCertFile),
		TLSKeyFile:    getStringConfig("hunter.tls.key_file", tlsKeyFile),
		TLSCAFile:     getStringConfig("hunter.tls.ca_file", tlsCAFile),
		TLSSkipVerify: getBoolConfig("hunter.tls.skip_verify", tlsSkipVerify),
	}

	// Security check
	if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
		return fmt.Errorf("TLS is disabled but --insecure flag not set\n\n" +
			"For security, lippycat requires TLS encryption for production deployments.\n" +
			"To enable TLS, use: --tls --tls-ca=/path/to/ca.crt\n" +
			"To explicitly allow insecure connections (NOT RECOMMENDED), use: --insecure")
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
		"http_ports", hunterHTTPPorts)

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
