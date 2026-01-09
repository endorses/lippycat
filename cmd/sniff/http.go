//go:build cli || all

package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/http"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Sniff in HTTP mode",
	Long: `Sniff in HTTP mode. Capture and analyze HTTP/1.x traffic.

Features:
- HTTP request/response parsing
- Request/response correlation with RTT measurement
- TCP stream reassembly
- Host/path extraction
- Content-type detection
- Method and status code filtering
- User-Agent and keyword matching
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
  --tls-keylog-pipe   Path to named pipe for real-time key injection

Pattern Files (one pattern per line, # for comments):
  --hosts-file, --paths-file, --user-agents-file, --content-types-file

Examples:
  # Basic HTTP capture
  lc sniff http -i eth0

  # Filter by host
  lc sniff http -i eth0 --host "*.example.com"

  # Filter by path
  lc sniff http -i eth0 --path "/api/*"

  # Filter by method
  lc sniff http -i eth0 --method "POST,PUT,DELETE"

  # Filter by status code
  lc sniff http -i eth0 --status "4xx,5xx"

  # Use keyword file for body matching
  lc sniff http -i eth0 --keywords-file keywords.txt --capture-body

  # Read from PCAP file
  lc sniff http -r capture.pcap

  # Capture on non-standard port
  lc sniff http -i eth0 --http-port 80,8080,3000

  # Write to output file
  lc sniff http -i eth0 -w http-output.pcap

  # HTTPS decryption with keylog file
  lc sniff http -i eth0 --tls-keylog /tmp/sslkeys.log

  # HTTPS decryption from PCAP + keylog
  lc sniff http -r capture.pcap --tls-keylog keys.log

  # Real-time HTTPS decryption via named pipe
  mkfifo /tmp/sslkeys.pipe
  lc sniff http -i eth0 --tls-keylog-pipe /tmp/sslkeys.pipe &
  SSLKEYLOGFILE=/tmp/sslkeys.pipe curl https://example.com`,
	Run: httpHandler,
}

var (
	// HTTP-specific flags
	httpHostPattern        string
	httpPathPattern        string
	httpMethods            string
	httpStatusCodes        string
	httpUserAgentPattern   string
	httpContentTypePattern string
	httpPorts              string
	httpTrackRequests      bool
	httpWriteFile          string

	// HTTP filter file flags
	httpHostsFile        string
	httpPathsFile        string
	httpUserAgentsFile   string
	httpContentTypesFile string
	httpKeywordsFile     string

	// Body capture flags
	httpCaptureBody bool
	httpMaxBodySize int

	// TLS decryption flags
	httpTLSKeylog     string
	httpTLSKeylogPipe string
)

func httpHandler(cmd *cobra.Command, args []string) {
	// Set HTTP configuration values
	if cmd.Flags().Changed("host") {
		viper.Set("http.host_pattern", httpHostPattern)
	}
	if cmd.Flags().Changed("path") {
		viper.Set("http.path_pattern", httpPathPattern)
	}
	if cmd.Flags().Changed("method") {
		methods := http.ParseMethods(httpMethods)
		viper.Set("http.methods", methods)
	}
	if cmd.Flags().Changed("status") {
		statusCodes := http.ParseStatusCodes(httpStatusCodes)
		viper.Set("http.status_codes", statusCodes)
	}
	if cmd.Flags().Changed("user-agent") {
		viper.Set("http.user_agent_pattern", httpUserAgentPattern)
	}
	if cmd.Flags().Changed("content-type") {
		viper.Set("http.content_type_pattern", httpContentTypePattern)
	}
	if cmd.Flags().Changed("http-port") {
		viper.Set("http.ports", httpPorts)
	}
	if cmd.Flags().Changed("track-requests") {
		viper.Set("http.track_requests", httpTrackRequests)
	}
	if httpWriteFile != "" {
		viper.Set("http.write_file", httpWriteFile)
	}
	if cmd.Flags().Changed("capture-body") {
		viper.Set("http.capture_body", httpCaptureBody)
	}
	if cmd.Flags().Changed("max-body-size") {
		viper.Set("http.max_body_size", httpMaxBodySize)
	}

	// Load host patterns from file if specified
	if httpHostsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpHostsFile)
		if err != nil {
			logger.Error("Failed to load hosts file", "error", err, "file", httpHostsFile)
			return
		}
		viper.Set("http.host_patterns", patterns)
		logger.Info("Loaded host patterns from file", "count", len(patterns), "file", httpHostsFile)
	}

	// Load path patterns from file if specified
	if httpPathsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpPathsFile)
		if err != nil {
			logger.Error("Failed to load paths file", "error", err, "file", httpPathsFile)
			return
		}
		viper.Set("http.url_patterns", patterns)
		logger.Info("Loaded path patterns from file", "count", len(patterns), "file", httpPathsFile)
	}

	// Load user-agent patterns from file if specified
	if httpUserAgentsFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpUserAgentsFile)
		if err != nil {
			logger.Error("Failed to load user-agents file", "error", err, "file", httpUserAgentsFile)
			return
		}
		viper.Set("http.user_agent_patterns", patterns)
		logger.Info("Loaded user-agent patterns from file", "count", len(patterns), "file", httpUserAgentsFile)
	}

	// Load content-type patterns from file if specified
	if httpContentTypesFile != "" {
		patterns, err := http.LoadPatternsFromFile(httpContentTypesFile)
		if err != nil {
			logger.Error("Failed to load content-types file", "error", err, "file", httpContentTypesFile)
			return
		}
		viper.Set("http.content_type_patterns", patterns)
		logger.Info("Loaded content-type patterns from file", "count", len(patterns), "file", httpContentTypesFile)
	}

	// Load keywords from file if specified
	if httpKeywordsFile != "" {
		keywords, err := http.LoadKeywordsFromFile(httpKeywordsFile)
		if err != nil {
			logger.Error("Failed to load keywords file", "error", err, "file", httpKeywordsFile)
			return
		}
		viper.Set("http.keywords", keywords)
		logger.Info("Loaded keywords from file", "count", len(keywords), "file", httpKeywordsFile)
	}

	// Build HTTP filter
	filterBuilder := http.NewFilterBuilder()
	ports, err := http.ParsePorts(httpPorts)
	if err != nil {
		logger.Error("Invalid HTTP port specification", "error", err)
		return
	}

	filterConfig := http.FilterConfig{
		Ports:      ports,
		BaseFilter: filter,
	}
	effectiveFilter := filterBuilder.Build(filterConfig)

	// Configure TLS decryption if specified
	tlsKeylogPath := httpTLSKeylog
	if tlsKeylogPath == "" {
		tlsKeylogPath = httpTLSKeylogPipe
	}
	if tlsKeylogPath != "" {
		decryptConfig := tls.DecryptConfig{
			KeylogFile: httpTLSKeylog,
			KeylogPipe: httpTLSKeylogPipe,
		}
		if err := decryptConfig.Validate(); err != nil {
			logger.Error("Invalid TLS keylog configuration", "error", err)
			return
		}
		viper.Set("http.tls_keylog", tlsKeylogPath)
		viper.Set("http.tls_decryption_enabled", true)
	}

	logger.Info("Starting HTTP sniffing",
		"interfaces", interfaces,
		"filter", effectiveFilter,
		"host_pattern", httpHostPattern,
		"path_pattern", httpPathPattern,
		"methods", httpMethods,
		"status_codes", httpStatusCodes,
		"track_requests", httpTrackRequests,
		"tls_decryption", tlsKeylogPath != "")

	// Start HTTP sniffer using appropriate mode
	if readFile == "" {
		http.StartLiveHTTPSniffer(interfaces, effectiveFilter)
	} else {
		http.StartOfflineHTTPSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// HTTP-specific flags - single patterns
	httpCmd.Flags().StringVar(&httpHostPattern, "host", "", "Filter by host pattern (glob-style, e.g., '*.example.com')")
	httpCmd.Flags().StringVar(&httpPathPattern, "path", "", "Filter by path/URL pattern (glob-style, e.g., '/api/*')")
	httpCmd.Flags().StringVar(&httpMethods, "method", "", "Filter by HTTP methods (comma-separated, e.g., 'GET,POST')")
	httpCmd.Flags().StringVar(&httpStatusCodes, "status", "", "Filter by status codes (e.g., '404', '4xx', '400-499')")
	httpCmd.Flags().StringVar(&httpUserAgentPattern, "user-agent", "", "Filter by User-Agent pattern (glob-style)")
	httpCmd.Flags().StringVar(&httpContentTypePattern, "content-type", "", "Filter by Content-Type pattern (glob-style)")

	// HTTP filter file flags - bulk patterns
	httpCmd.Flags().StringVar(&httpHostsFile, "hosts-file", "", "Load host patterns from file (one per line)")
	httpCmd.Flags().StringVar(&httpPathsFile, "paths-file", "", "Load path patterns from file (one per line)")
	httpCmd.Flags().StringVar(&httpUserAgentsFile, "user-agents-file", "", "Load user-agent patterns from file (one per line)")
	httpCmd.Flags().StringVar(&httpContentTypesFile, "content-types-file", "", "Load content-type patterns from file (one per line)")
	httpCmd.Flags().StringVar(&httpKeywordsFile, "keywords-file", "", "Load keywords from file for body matching (Aho-Corasick)")

	// Other HTTP flags
	httpCmd.Flags().StringVar(&httpPorts, "http-port", "80,8080,8000,3000,8888", "HTTP port(s) to capture, comma-separated")
	httpCmd.Flags().BoolVar(&httpTrackRequests, "track-requests", true, "Enable request/response tracking")
	httpCmd.Flags().StringVarP(&httpWriteFile, "write-file", "w", "", "Write captured HTTP packets to PCAP file")

	// Body capture flags
	httpCmd.Flags().BoolVar(&httpCaptureBody, "capture-body", false, "Enable HTTP body content capture (for keyword matching)")
	httpCmd.Flags().IntVar(&httpMaxBodySize, "max-body-size", 65536, "Maximum body size to capture in bytes (default: 64KB)")

	// TLS decryption flags
	httpCmd.Flags().StringVar(&httpTLSKeylog, "tls-keylog", "", "Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)")
	httpCmd.Flags().StringVar(&httpTLSKeylogPipe, "tls-keylog-pipe", "", "Path to named pipe for real-time TLS key injection")

	// Bind to viper for config file support
	_ = viper.BindPFlag("http.host_pattern", httpCmd.Flags().Lookup("host"))
	_ = viper.BindPFlag("http.path_pattern", httpCmd.Flags().Lookup("path"))
	_ = viper.BindPFlag("http.methods", httpCmd.Flags().Lookup("method"))
	_ = viper.BindPFlag("http.status_codes", httpCmd.Flags().Lookup("status"))
	_ = viper.BindPFlag("http.user_agent_pattern", httpCmd.Flags().Lookup("user-agent"))
	_ = viper.BindPFlag("http.content_type_pattern", httpCmd.Flags().Lookup("content-type"))
	_ = viper.BindPFlag("http.hosts_file", httpCmd.Flags().Lookup("hosts-file"))
	_ = viper.BindPFlag("http.paths_file", httpCmd.Flags().Lookup("paths-file"))
	_ = viper.BindPFlag("http.user_agents_file", httpCmd.Flags().Lookup("user-agents-file"))
	_ = viper.BindPFlag("http.content_types_file", httpCmd.Flags().Lookup("content-types-file"))
	_ = viper.BindPFlag("http.keywords_file", httpCmd.Flags().Lookup("keywords-file"))
	_ = viper.BindPFlag("http.ports", httpCmd.Flags().Lookup("http-port"))
	_ = viper.BindPFlag("http.track_requests", httpCmd.Flags().Lookup("track-requests"))
	_ = viper.BindPFlag("http.capture_body", httpCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("http.max_body_size", httpCmd.Flags().Lookup("max-body-size"))
	_ = viper.BindPFlag("http.tls_keylog", httpCmd.Flags().Lookup("tls-keylog"))
	_ = viper.BindPFlag("http.tls_keylog_pipe", httpCmd.Flags().Lookup("tls-keylog-pipe"))
}
