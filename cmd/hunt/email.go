//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Email-specific flags for hunter mode
	hunterEmailPorts string

	// Content filter flags for local filtering (in addition to processor-pushed filters)
	hunterEmailSender    string // Sender address patterns (comma-separated)
	hunterEmailRecipient string // Recipient address patterns (comma-separated)
	hunterEmailSubject   string // Subject patterns (comma-separated)
	hunterEmailKeywords  string // Body/subject keyword patterns (comma-separated)
	hunterCaptureBody    bool   // Enable body capture for keyword filtering
	hunterMaxBodySize    int    // Max body size to capture (bytes)
)

var emailHuntCmd = &cobra.Command{
	Use:   "email",
	Short: "Run as Email hunter with SMTP filtering",
	Long: `Run lippycat in Email hunter mode with TCP reassembly and content filtering.

Email hunter mode captures SMTP traffic, reassembles TCP streams, applies
content filtering (including body keyword matching), and forwards matched
email sessions to the processor.

Features:
- SMTP TCP stream reassembly for complete message parsing
- Port filtering (default: 25, 587, 465)
- Sender/recipient address filtering (glob patterns)
- Subject line filtering (glob patterns)
- Body content keyword filtering (Aho-Corasick)
- Efficient forwarding to processor

Filters can be specified locally (flags) or pushed from the processor.
Local filters apply in addition to processor-pushed filters.

Example:
  lc hunt email --processor processor:50051
  lc hunt email --processor 192.168.1.100:50051 --interface eth0
  lc hunt email --processor processor:50051 --smtp-port 25,587,2525
  lc hunt email --processor processor:50051 --sender "*@suspicious.com"
  lc hunt email --processor processor:50051 --keywords "confidential,secret" --capture-body`,
	RunE: runEmailHunt,
}

func init() {
	HuntCmd.AddCommand(emailHuntCmd)

	// Email-specific flags (BPF-level filtering)
	emailHuntCmd.Flags().StringVar(&hunterEmailPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")

	// Content filter flags for local filtering
	emailHuntCmd.Flags().StringVar(&hunterEmailSender, "sender", "", "Sender address patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailRecipient, "recipient", "", "Recipient address patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailSubject, "subject", "", "Subject patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailKeywords, "keywords", "", "Body/subject keywords (comma-separated)")
	emailHuntCmd.Flags().BoolVar(&hunterCaptureBody, "capture-body", false, "Enable body capture for keyword filtering")
	emailHuntCmd.Flags().IntVar(&hunterMaxBodySize, "max-body-size", 65536, "Max body size to capture in bytes (default: 64KB)")

	// Bind to viper
	_ = viper.BindPFlag("hunter.email.ports", emailHuntCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("hunter.email.sender", emailHuntCmd.Flags().Lookup("sender"))
	_ = viper.BindPFlag("hunter.email.recipient", emailHuntCmd.Flags().Lookup("recipient"))
	_ = viper.BindPFlag("hunter.email.subject", emailHuntCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("hunter.email.keywords", emailHuntCmd.Flags().Lookup("keywords"))
	_ = viper.BindPFlag("hunter.email.capture_body", emailHuntCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("hunter.email.max_body_size", emailHuntCmd.Flags().Lookup("max-body-size"))
}

func runEmailHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in Email hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build email filter
	filterBuilder := email.NewFilterBuilder()
	ports, err := email.ParsePorts(hunterEmailPorts)
	if err != nil {
		return fmt.Errorf("invalid --smtp-port value: %w", err)
	}

	baseBPFFilter := getStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := email.FilterConfig{
		Ports:      ports,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("Email BPF filter configured",
		"ports", hunterEmailPorts,
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
		// Email hunter supports BPF, IP, email address, and email subject filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"},
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

	logger.Info("Email Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"smtp_ports", hunterEmailPorts)

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
	contentFilter := buildEmailContentFilter()

	// Configure SMTP stream factory
	smtpConfig := email.SMTPStreamFactoryConfig{
		MaxGoroutines:   1000,
		CleanupInterval: 30 * time.Second,
		ServerPorts:     ports,
		CaptureBody:     hunterCaptureBody || len(hunterEmailKeywords) > 0, // Enable if keywords specified
		MaxBodySize:     hunterMaxBodySize,
	}

	// Create email packet processor with TCP reassembly and content filtering
	processor := email.NewEmailPacketProcessor(ctx, h, contentFilter, smtpConfig)
	defer processor.Close()

	// Set the packet processor on the hunter
	h.SetPacketProcessor(processor)

	logger.Info("Email hunter initialized with TCP reassembly and content filtering",
		"has_sender_filter", len(hunterEmailSender) > 0,
		"has_recipient_filter", len(hunterEmailRecipient) > 0,
		"has_subject_filter", len(hunterEmailSubject) > 0,
		"has_keywords", len(hunterEmailKeywords) > 0,
		"capture_body", smtpConfig.CaptureBody)

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
		logger.Info("Shutdown signal received, stopping Email hunter...")
		return nil
	}
}

// buildEmailContentFilter creates a ContentFilter from command-line flags.
func buildEmailContentFilter() *email.ContentFilter {
	cfg := email.ContentFilterConfig{}

	// Parse comma-separated patterns
	if hunterEmailSender != "" {
		cfg.SenderPatterns = splitAndTrim(hunterEmailSender)
	}
	if hunterEmailRecipient != "" {
		cfg.RecipientPatterns = splitAndTrim(hunterEmailRecipient)
	}
	if hunterEmailSubject != "" {
		cfg.SubjectPatterns = splitAndTrim(hunterEmailSubject)
	}
	if hunterEmailKeywords != "" {
		cfg.Keywords = splitAndTrim(hunterEmailKeywords)
	}

	return email.NewContentFilter(cfg)
}

// splitAndTrim splits a comma-separated string and trims whitespace.
func splitAndTrim(s string) []string {
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
