//go:build tap || all

package tap

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
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
	emailTapPorts          string
	emailTapImapPorts      string
	emailTapPop3Ports      string
	emailTapProtocol       string
	emailTapAddress        string
	emailTapSender         string
	emailTapRecipient      string
	emailTapSubject        string
	emailTapMailbox        string
	emailTapCommand        string
	emailTapAddressesFile  string
	emailTapSendersFile    string
	emailTapRecipientsFile string
	emailTapSubjectsFile   string
	emailTapKeywordsFile   string
	emailTapCaptureBody    bool
	emailTapMaxBodySize    int
)

var emailTapCmd = &cobra.Command{
	Use:   "email",
	Short: "Standalone email capture with full processor capabilities",
	Long: `Run lippycat in standalone email tap mode.

Email tap mode combines local email capture with full processor capabilities:
- Captures and analyzes SMTP, IMAP, and POP3 traffic from local interfaces
- Provides auto-rotating PCAP writing
- Serves TUI connections for monitoring
- Supports upstream forwarding in hierarchical mode
- Session tracking and correlation for all protocols
- Content filtering (sender, recipient, subject, keywords, mailbox, command)

Protocol Selection:
  --protocol smtp    SMTP only (ports 25, 465, 587)
  --protocol imap    IMAP only (ports 143, 993)
  --protocol pop3    POP3 only (ports 110, 995)
  --protocol all     All email protocols (default)

Filter Options:
  --address       Match either sender OR recipient (glob pattern)
  --sender        Match sender only (MAIL FROM, glob pattern)
  --recipient     Match recipient only (RCPT TO, glob pattern)
  --subject       Match subject line (glob pattern)
  --mailbox       Match IMAP mailbox name (glob pattern)
  --command       Match IMAP/POP3 command (glob pattern, e.g., "FETCH", "RETR")
  --keywords-file Keywords for subject/body matching (Aho-Corasick)

Body Capture (for keyword matching in body):
  --capture-body      Enable body content capture (default: false)
  --max-body-size     Maximum body size to capture (default: 64KB)

Pattern Files (one pattern per line, # for comments):
  --addresses-file, --senders-file, --recipients-file, --subjects-file

Example:
  lc tap email --interface eth0 --insecure
  lc tap email -i eth0 --protocol imap --insecure
  lc tap email -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/email/pcaps
  lc tap email -i eth0 --smtp-port 25,587,2525
  lc tap email -i eth0 --address "*@example.com"
  lc tap email -i eth0 --sender "*@suspicious.com"
  lc tap email -i eth0 --subject "*invoice*"
  lc tap email -i eth0 --protocol imap --mailbox "INBOX"
  lc tap email -i eth0 --protocol imap --command "FETCH"`,
	RunE: runEmailTap,
}

func init() {
	TapCmd.AddCommand(emailTapCmd)

	// Protocol selection
	emailTapCmd.Flags().StringVar(&emailTapProtocol, "protocol", "all", "Email protocol to capture: smtp, imap, pop3, all")

	// Port configuration
	emailTapCmd.Flags().StringVar(&emailTapPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")
	emailTapCmd.Flags().StringVar(&emailTapImapPorts, "imap-port", "143,993", "IMAP port(s) to capture, comma-separated")
	emailTapCmd.Flags().StringVar(&emailTapPop3Ports, "pop3-port", "110,995", "POP3 port(s) to capture, comma-separated")

	// Email-specific flags - single patterns
	emailTapCmd.Flags().StringVar(&emailTapAddress, "address", "", "Filter by email address pattern (matches sender OR recipient, glob-style)")
	emailTapCmd.Flags().StringVar(&emailTapSender, "sender", "", "Filter by sender address pattern (MAIL FROM, glob-style)")
	emailTapCmd.Flags().StringVar(&emailTapRecipient, "recipient", "", "Filter by recipient address pattern (RCPT TO, glob-style)")
	emailTapCmd.Flags().StringVar(&emailTapSubject, "subject", "", "Filter by subject pattern (glob-style)")
	emailTapCmd.Flags().StringVar(&emailTapMailbox, "mailbox", "", "Filter by IMAP mailbox name (glob-style)")
	emailTapCmd.Flags().StringVar(&emailTapCommand, "command", "", "Filter by IMAP/POP3 command (glob-style, e.g., FETCH, RETR)")

	// Email filter file flags - bulk patterns
	emailTapCmd.Flags().StringVar(&emailTapAddressesFile, "addresses-file", "", "Load address patterns from file (one per line)")
	emailTapCmd.Flags().StringVar(&emailTapSendersFile, "senders-file", "", "Load sender patterns from file (one per line)")
	emailTapCmd.Flags().StringVar(&emailTapRecipientsFile, "recipients-file", "", "Load recipient patterns from file (one per line)")
	emailTapCmd.Flags().StringVar(&emailTapSubjectsFile, "subjects-file", "", "Load subject patterns from file (one per line)")
	emailTapCmd.Flags().StringVar(&emailTapKeywordsFile, "keywords-file", "", "Load keywords from file for subject/body matching (Aho-Corasick)")

	// Body capture flags
	emailTapCmd.Flags().BoolVar(&emailTapCaptureBody, "capture-body", false, "Enable email body content capture (for keyword matching)")
	emailTapCmd.Flags().IntVar(&emailTapMaxBodySize, "max-body-size", 65536, "Maximum body size to capture in bytes (default: 64KB)")

	// Bind email-specific flags to viper
	_ = viper.BindPFlag("tap.email.protocol", emailTapCmd.Flags().Lookup("protocol"))
	_ = viper.BindPFlag("tap.email.smtp_ports", emailTapCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("tap.email.imap_ports", emailTapCmd.Flags().Lookup("imap-port"))
	_ = viper.BindPFlag("tap.email.pop3_ports", emailTapCmd.Flags().Lookup("pop3-port"))
	_ = viper.BindPFlag("tap.email.address_pattern", emailTapCmd.Flags().Lookup("address"))
	_ = viper.BindPFlag("tap.email.sender_pattern", emailTapCmd.Flags().Lookup("sender"))
	_ = viper.BindPFlag("tap.email.recipient_pattern", emailTapCmd.Flags().Lookup("recipient"))
	_ = viper.BindPFlag("tap.email.subject_pattern", emailTapCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("tap.email.mailbox_pattern", emailTapCmd.Flags().Lookup("mailbox"))
	_ = viper.BindPFlag("tap.email.command_pattern", emailTapCmd.Flags().Lookup("command"))
	_ = viper.BindPFlag("tap.email.addresses_file", emailTapCmd.Flags().Lookup("addresses-file"))
	_ = viper.BindPFlag("tap.email.senders_file", emailTapCmd.Flags().Lookup("senders-file"))
	_ = viper.BindPFlag("tap.email.recipients_file", emailTapCmd.Flags().Lookup("recipients-file"))
	_ = viper.BindPFlag("tap.email.subjects_file", emailTapCmd.Flags().Lookup("subjects-file"))
	_ = viper.BindPFlag("tap.email.keywords_file", emailTapCmd.Flags().Lookup("keywords-file"))
	_ = viper.BindPFlag("tap.email.capture_body", emailTapCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("tap.email.max_body_size", emailTapCmd.Flags().Lookup("max-body-size"))
}

func runEmailTap(cmd *cobra.Command, args []string) error {
	logger.Info("Starting lippycat in standalone Email tap mode")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
		}
		logger.Info("Production mode: TLS enforcement enabled")
	}

	// Set email filter patterns from flags
	if cmd.Flags().Changed("protocol") {
		viper.Set("email.protocol", emailTapProtocol)
	}
	if cmd.Flags().Changed("address") {
		viper.Set("email.address_pattern", emailTapAddress)
	}
	if cmd.Flags().Changed("sender") {
		viper.Set("email.sender_pattern", emailTapSender)
	}
	if cmd.Flags().Changed("recipient") {
		viper.Set("email.recipient_pattern", emailTapRecipient)
	}
	if cmd.Flags().Changed("subject") {
		viper.Set("email.subject_pattern", emailTapSubject)
	}
	if cmd.Flags().Changed("mailbox") {
		viper.Set("email.mailbox_pattern", emailTapMailbox)
	}
	if cmd.Flags().Changed("command") {
		viper.Set("email.command_pattern", emailTapCommand)
	}
	if cmd.Flags().Changed("smtp-port") {
		viper.Set("email.smtp_ports", emailTapPorts)
	}
	if cmd.Flags().Changed("imap-port") {
		viper.Set("email.imap_ports", emailTapImapPorts)
	}
	if cmd.Flags().Changed("pop3-port") {
		viper.Set("email.pop3_ports", emailTapPop3Ports)
	}
	if cmd.Flags().Changed("capture-body") {
		viper.Set("email.capture_body", emailTapCaptureBody)
	}
	if cmd.Flags().Changed("max-body-size") {
		viper.Set("email.max_body_size", emailTapMaxBodySize)
	}

	// Load patterns from files if specified
	if emailTapAddressesFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailTapAddressesFile)
		if err != nil {
			return fmt.Errorf("failed to load addresses file: %w", err)
		}
		viper.Set("email.address_patterns", patterns)
		logger.Info("Loaded address patterns from file", "count", len(patterns), "file", emailTapAddressesFile)
	}

	if emailTapSendersFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailTapSendersFile)
		if err != nil {
			return fmt.Errorf("failed to load senders file: %w", err)
		}
		viper.Set("email.sender_patterns", patterns)
		logger.Info("Loaded sender patterns from file", "count", len(patterns), "file", emailTapSendersFile)
	}

	if emailTapRecipientsFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailTapRecipientsFile)
		if err != nil {
			return fmt.Errorf("failed to load recipients file: %w", err)
		}
		viper.Set("email.recipient_patterns", patterns)
		logger.Info("Loaded recipient patterns from file", "count", len(patterns), "file", emailTapRecipientsFile)
	}

	if emailTapSubjectsFile != "" {
		patterns, err := email.LoadSubjectPatternsFromFile(emailTapSubjectsFile)
		if err != nil {
			return fmt.Errorf("failed to load subjects file: %w", err)
		}
		viper.Set("email.subject_patterns", patterns)
		logger.Info("Loaded subject patterns from file", "count", len(patterns), "file", emailTapSubjectsFile)
	}

	if emailTapKeywordsFile != "" {
		keywords, err := email.LoadKeywordsFromFile(emailTapKeywordsFile)
		if err != nil {
			return fmt.Errorf("failed to load keywords file: %w", err)
		}
		viper.Set("email.keywords", keywords)
		logger.Info("Loaded keywords from file", "count", len(keywords), "file", emailTapKeywordsFile)
	}

	// Determine protocol and ports
	protocol := viper.GetString("email.protocol")
	if protocol == "" {
		protocol = "all"
	}

	// Build port list based on protocol selection
	var ports []uint16
	switch protocol {
	case "smtp":
		smtpPortStr := viper.GetString("email.smtp_ports")
		if smtpPortStr == "" {
			smtpPortStr = emailTapPorts
		}
		parsed, err := email.ParsePorts(smtpPortStr)
		if err != nil {
			return fmt.Errorf("invalid SMTP port specification: %w", err)
		}
		ports = parsed
	case "imap":
		imapPortStr := viper.GetString("email.imap_ports")
		if imapPortStr == "" {
			imapPortStr = emailTapImapPorts
		}
		parsed, err := email.ParsePorts(imapPortStr)
		if err != nil {
			return fmt.Errorf("invalid IMAP port specification: %w", err)
		}
		if len(parsed) == 0 {
			ports = email.DefaultIMAPPorts
		} else {
			ports = parsed
		}
	case "pop3":
		pop3PortStr := viper.GetString("email.pop3_ports")
		if pop3PortStr == "" {
			pop3PortStr = emailTapPop3Ports
		}
		parsed, err := email.ParsePorts(pop3PortStr)
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
		smtpPortStr := viper.GetString("email.smtp_ports")
		if smtpPortStr == "" {
			smtpPortStr = emailTapPorts
		}
		smtpParsed, err := email.ParsePorts(smtpPortStr)
		if err == nil && len(smtpParsed) > 0 {
			allPorts = append(allPorts, smtpParsed...)
		} else {
			allPorts = append(allPorts, email.DefaultSMTPPorts...)
		}
		imapPortStr := viper.GetString("email.imap_ports")
		if imapPortStr == "" {
			imapPortStr = emailTapImapPorts
		}
		imapParsed, err := email.ParsePorts(imapPortStr)
		if err == nil && len(imapParsed) > 0 {
			allPorts = append(allPorts, imapParsed...)
		} else {
			allPorts = append(allPorts, email.DefaultIMAPPorts...)
		}
		pop3PortStr := viper.GetString("email.pop3_ports")
		if pop3PortStr == "" {
			pop3PortStr = emailTapPop3Ports
		}
		pop3Parsed, err := email.ParsePorts(pop3PortStr)
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
	baseBPFFilter := cmdutil.GetStringConfig("tap.bpf_filter", bpfFilter)
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

	// Build auto-rotate PCAP config - default for Email mode
	var autoRotateConfig *processor.AutoRotateConfig
	effectiveAutoRotate := cmdutil.GetBoolConfig("tap.auto_rotate_pcap.enabled", autoRotatePcapEnabled)
	if !cmd.Flags().Changed("auto-rotate-pcap") && !viper.IsSet("tap.auto_rotate_pcap.enabled") {
		// Email mode should default to auto-rotate PCAP enabled
		effectiveAutoRotate = true
	}

	if effectiveAutoRotate {
		idleTimeoutStr := cmdutil.GetStringConfig("tap.auto_rotate_pcap.idle_timeout", autoRotatePcapIdleTimeout)
		idleTimeout, err := time.ParseDuration(idleTimeoutStr)
		if err != nil {
			idleTimeout = 5 * time.Minute
		}

		maxSizeStr := cmdutil.GetStringConfig("tap.auto_rotate_pcap.max_size", autoRotatePcapMaxSize)
		maxSize, err := cmdutil.ParseSizeString(maxSizeStr)
		if err != nil {
			maxSize = 100 * 1024 * 1024 // 100MB default
		}

		autoRotateConfig = &processor.AutoRotateConfig{
			Enabled:      true,
			OutputDir:    cmdutil.GetStringConfig("tap.auto_rotate_pcap.output_dir", autoRotatePcapDir),
			FilePattern:  cmdutil.GetStringConfig("tap.auto_rotate_pcap.file_pattern", autoRotatePcapPattern),
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
	if cmdutil.GetBoolConfig("security.api_keys.enabled", apiKeyAuthEnabled) {
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
	effectiveTapID := cmdutil.GetStringConfig("tap.tap_id", tapID)
	if effectiveTapID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname: %w", err)
		}
		effectiveTapID = hostname + "-email-tap"
	}

	// Build processor configuration
	config := processor.Config{
		ListenAddr:            cmdutil.GetStringConfig("tap.listen_addr", listenAddr),
		ProcessorID:           effectiveTapID,
		UpstreamAddr:          cmdutil.GetStringConfig("tap.processor_addr", processorAddr),
		MaxHunters:            0,
		MaxSubscribers:        cmdutil.GetIntConfig("tap.max_subscribers", maxSubscribers),
		WriteFile:             cmdutil.GetStringConfig("tap.write_file", writeFile),
		DisplayStats:          true,
		AutoRotateConfig:      autoRotateConfig,
		EnableDetection:       true, // Enable protocol detection
		FilterFile:            cmdutil.GetStringConfig("tap.filter_file", filterFile),
		TLSEnabled:            !cmdutil.GetBoolConfig("insecure", insecureAllowed),
		TLSCertFile:           cmdutil.GetStringConfig("tap.tls.cert_file", tlsCertFile),
		TLSKeyFile:            cmdutil.GetStringConfig("tap.tls.key_file", tlsKeyFile),
		TLSCAFile:             cmdutil.GetStringConfig("tap.tls.ca_file", tlsCAFile),
		TLSClientAuth:         cmdutil.GetBoolConfig("tap.tls.client_auth", tlsClientAuth),
		AuthConfig:            authConfig,
		VirtualInterface:      cmdutil.GetBoolConfig("tap.virtual_interface", virtualInterface),
		VirtualInterfaceName:  cmdutil.GetStringConfig("tap.vif_name", virtualInterfaceName),
		VirtualInterfaceType:  cmdutil.GetStringConfig("tap.vif_type", vifType),
		VifBufferSize:         cmdutil.GetIntConfig("tap.vif_buffer_size", vifBufferSize),
		VifNetNS:              cmdutil.GetStringConfig("tap.vif_netns", vifNetNS),
		VifDropPrivilegesUser: cmdutil.GetStringConfig("tap.vif_drop_privileges", vifDropPrivileges),
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

	// Apply own-traffic BPF exclusion
	exclusionFilter := buildOwnTrafficExclusionFilter(config.ListenAddr, config.UpstreamAddr)
	effectiveBPFFilter = combineFiltersWithExclusion(effectiveBPFFilter, exclusionFilter)

	if exclusionFilter != "" {
		logger.Info("Own-traffic BPF exclusion applied",
			"exclusion", exclusionFilter,
			"effective_filter", effectiveBPFFilter)
	}

	// Create LocalSource for local packet capture with Email filter
	localSourceConfig := source.LocalSourceConfig{
		Interfaces:   cmdutil.GetStringSliceConfig("tap.interfaces", interfaces),
		BPFFilter:    effectiveBPFFilter,
		BatchSize:    cmdutil.GetIntConfig("tap.batch_size", batchSize),
		BatchTimeout: time.Duration(cmdutil.GetIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
		BufferSize:   cmdutil.GetIntConfig("tap.buffer_size", bufferSize),
		BatchBuffer:  1000,
		ProcessorID:  effectiveTapID, // For virtual hunter ID generation
		ProtocolMode: "email",
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
	appFilter, err := createApplicationFilter(GetGPUConfig())
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

	logger.Info("Email Tap configuration",
		"tap_id", effectiveTapID,
		"mode", mode,
		"interfaces", localSourceConfig.Interfaces,
		"protocol", protocol,
		"bpf_filter", localSourceConfig.BPFFilter,
		"ports", ports,
		"address_filter", emailTapAddress,
		"sender_filter", emailTapSender,
		"recipient_filter", emailTapRecipient,
		"subject_filter", emailTapSubject,
		"mailbox_filter", emailTapMailbox,
		"command_filter", emailTapCommand,
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
