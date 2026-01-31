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
	"github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Email-specific flags for hunter mode
	hunterEmailPorts     string
	hunterEmailImapPorts string
	hunterEmailPop3Ports string
	hunterEmailProtocol  string

	// Content filter flags for local filtering (in addition to processor-pushed filters)
	hunterEmailSender    string // Sender address patterns (comma-separated)
	hunterEmailRecipient string // Recipient address patterns (comma-separated)
	hunterEmailSubject   string // Subject patterns (comma-separated)
	hunterEmailKeywords  string // Body/subject keyword patterns (comma-separated)
	hunterEmailMailbox   string // IMAP mailbox name patterns (comma-separated)
	hunterEmailCommand   string // IMAP/POP3 command patterns (comma-separated)
	hunterCaptureBody    bool   // Enable body capture for keyword filtering
	hunterMaxBodySize    int    // Max body size to capture (bytes)
)

var emailHuntCmd = &cobra.Command{
	Use:   "email",
	Short: "Run as Email hunter with SMTP/IMAP/POP3 filtering",
	Long: `Run lippycat in Email hunter mode with TCP reassembly and content filtering.

Email hunter mode captures SMTP, IMAP, and POP3 traffic, reassembles TCP streams,
applies content filtering (including body keyword matching), and forwards matched
email sessions to the processor.

Features:
- Multi-protocol support: SMTP, IMAP, POP3
- TCP stream reassembly for complete message parsing
- Sender/recipient address filtering (glob patterns)
- Subject line filtering (glob patterns)
- Mailbox name filtering (IMAP, glob patterns)
- Command filtering (IMAP/POP3 commands, glob patterns)
- Body content keyword filtering (Aho-Corasick)
- Efficient forwarding to processor

Protocol Selection:
  --protocol smtp    SMTP only (ports 25, 465, 587)
  --protocol imap    IMAP only (ports 143, 993)
  --protocol pop3    POP3 only (ports 110, 995)
  --protocol all     All email protocols (default)

Filters can be specified locally (flags) or pushed from the processor.
Local filters apply in addition to processor-pushed filters.

Example:
  lc hunt email --processor processor:55555
  lc hunt email --processor 192.168.1.100:55555 --interface eth0
  lc hunt email --processor processor:55555 --protocol imap
  lc hunt email --processor processor:55555 --smtp-port 25,587,2525
  lc hunt email --processor processor:55555 --sender "*@suspicious.com"
  lc hunt email --processor processor:55555 --keywords "confidential,secret" --capture-body
  lc hunt email --processor processor:55555 --protocol imap --mailbox "INBOX"
  lc hunt email --processor processor:55555 --protocol pop3 --command "RETR"`,
	RunE: runEmailHunt,
}

func init() {
	HuntCmd.AddCommand(emailHuntCmd)

	// Protocol selection
	emailHuntCmd.Flags().StringVar(&hunterEmailProtocol, "protocol", "all", "Email protocol to capture: smtp, imap, pop3, all")

	// Port configuration
	emailHuntCmd.Flags().StringVar(&hunterEmailPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")
	emailHuntCmd.Flags().StringVar(&hunterEmailImapPorts, "imap-port", "143,993", "IMAP port(s) to capture, comma-separated")
	emailHuntCmd.Flags().StringVar(&hunterEmailPop3Ports, "pop3-port", "110,995", "POP3 port(s) to capture, comma-separated")

	// Content filter flags for local filtering
	emailHuntCmd.Flags().StringVar(&hunterEmailSender, "sender", "", "Sender address patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailRecipient, "recipient", "", "Recipient address patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailSubject, "subject", "", "Subject patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailKeywords, "keywords", "", "Body/subject keywords (comma-separated)")
	emailHuntCmd.Flags().StringVar(&hunterEmailMailbox, "mailbox", "", "IMAP mailbox name patterns (comma-separated, glob-style)")
	emailHuntCmd.Flags().StringVar(&hunterEmailCommand, "command", "", "IMAP/POP3 command patterns (comma-separated, glob-style, e.g., FETCH, RETR)")
	emailHuntCmd.Flags().BoolVar(&hunterCaptureBody, "capture-body", false, "Enable body capture for keyword filtering")
	emailHuntCmd.Flags().IntVar(&hunterMaxBodySize, "max-body-size", 65536, "Max body size to capture in bytes (default: 64KB)")

	// Bind to viper
	_ = viper.BindPFlag("hunter.email.protocol", emailHuntCmd.Flags().Lookup("protocol"))
	_ = viper.BindPFlag("hunter.email.smtp_ports", emailHuntCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("hunter.email.imap_ports", emailHuntCmd.Flags().Lookup("imap-port"))
	_ = viper.BindPFlag("hunter.email.pop3_ports", emailHuntCmd.Flags().Lookup("pop3-port"))
	_ = viper.BindPFlag("hunter.email.sender", emailHuntCmd.Flags().Lookup("sender"))
	_ = viper.BindPFlag("hunter.email.recipient", emailHuntCmd.Flags().Lookup("recipient"))
	_ = viper.BindPFlag("hunter.email.subject", emailHuntCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("hunter.email.keywords", emailHuntCmd.Flags().Lookup("keywords"))
	_ = viper.BindPFlag("hunter.email.mailbox", emailHuntCmd.Flags().Lookup("mailbox"))
	_ = viper.BindPFlag("hunter.email.command", emailHuntCmd.Flags().Lookup("command"))
	_ = viper.BindPFlag("hunter.email.capture_body", emailHuntCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("hunter.email.max_body_size", emailHuntCmd.Flags().Lookup("max-body-size"))
}

func runEmailHunt(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in Email hunter mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Determine protocol and ports
	protocol := hunterEmailProtocol
	if protocol == "" {
		protocol = "all"
	}

	// Build port list based on protocol selection
	var ports []uint16
	switch protocol {
	case "smtp":
		parsed, err := email.ParsePorts(hunterEmailPorts)
		if err != nil {
			return fmt.Errorf("invalid SMTP port specification: %w", err)
		}
		ports = parsed
	case "imap":
		parsed, err := email.ParsePorts(hunterEmailImapPorts)
		if err != nil {
			return fmt.Errorf("invalid IMAP port specification: %w", err)
		}
		if len(parsed) == 0 {
			ports = email.DefaultIMAPPorts
		} else {
			ports = parsed
		}
	case "pop3":
		parsed, err := email.ParsePorts(hunterEmailPop3Ports)
		if err != nil {
			return fmt.Errorf("invalid POP3 port specification: %w", err)
		}
		if len(parsed) == 0 {
			ports = email.DefaultPOP3Ports
		} else {
			ports = parsed
		}
	case "all":
		// Combine all protocol ports
		var allPorts []uint16
		smtpParsed, err := email.ParsePorts(hunterEmailPorts)
		if err == nil && len(smtpParsed) > 0 {
			allPorts = append(allPorts, smtpParsed...)
		} else {
			allPorts = append(allPorts, email.DefaultSMTPPorts...)
		}
		imapParsed, err := email.ParsePorts(hunterEmailImapPorts)
		if err == nil && len(imapParsed) > 0 {
			allPorts = append(allPorts, imapParsed...)
		} else {
			allPorts = append(allPorts, email.DefaultIMAPPorts...)
		}
		pop3Parsed, err := email.ParsePorts(hunterEmailPop3Ports)
		if err == nil && len(pop3Parsed) > 0 {
			allPorts = append(allPorts, pop3Parsed...)
		} else {
			allPorts = append(allPorts, email.DefaultPOP3Ports...)
		}
		ports = allPorts
	default:
		return fmt.Errorf("invalid protocol: %s (valid: smtp, imap, pop3, all)", protocol)
	}

	// Build email filter
	filterBuilder := email.NewFilterBuilder()
	baseBPFFilter := cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter)
	filterConfig := email.FilterConfig{
		Ports:      ports,
		Protocol:   protocol,
		BaseFilter: baseBPFFilter,
	}
	effectiveBPFFilter := filterBuilder.Build(filterConfig)

	logger.Info("Email BPF filter configured",
		"protocol", protocol,
		"ports", ports,
		"effective_filter", effectiveBPFFilter)

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
		// Email hunter supports BPF, IP, email address, and email subject filters
		SupportedFilterTypes: []string{"bpf", "ip_address", "email_address", "email_subject"},
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
		"protocol", protocol,
		"has_sender_filter", len(hunterEmailSender) > 0,
		"has_recipient_filter", len(hunterEmailRecipient) > 0,
		"has_subject_filter", len(hunterEmailSubject) > 0,
		"has_mailbox_filter", len(hunterEmailMailbox) > 0,
		"has_command_filter", len(hunterEmailCommand) > 0,
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
	if hunterEmailMailbox != "" {
		cfg.MailboxPatterns = splitAndTrim(hunterEmailMailbox)
	}
	if hunterEmailCommand != "" {
		cfg.CommandPatterns = splitAndTrim(hunterEmailCommand)
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
