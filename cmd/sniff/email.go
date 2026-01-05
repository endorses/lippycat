//go:build cli || all

package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/email"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var emailCmd = &cobra.Command{
	Use:   "email",
	Short: "Sniff in Email mode",
	Long: `Sniff in Email mode. Capture and analyze SMTP traffic.

Features:
- SMTP command/response parsing
- Session tracking and correlation
- MAIL FROM/RCPT TO extraction
- STARTTLS detection
- Message-ID correlation
- Content filtering (sender, recipient, subject, keywords)

Filter Options:
  --address       Match either sender OR recipient (glob pattern)
  --sender        Match sender only (MAIL FROM, glob pattern)
  --recipient     Match recipient only (RCPT TO, glob pattern)
  --subject       Match subject line (glob pattern)
  --keywords-file Keywords for subject/body matching (Aho-Corasick)

Body Capture (for keyword matching in body):
  --capture-body      Enable body content capture (default: false)
  --max-body-size     Maximum body size to capture (default: 64KB)

Pattern Files (one pattern per line, # for comments):
  --addresses-file, --senders-file, --recipients-file, --subjects-file

Examples:
  # Basic SMTP capture
  lc sniff email -i eth0

  # Filter by sender domain
  lc sniff email -i eth0 --sender "*@example.com"

  # Filter by recipient
  lc sniff email -i eth0 --recipient "admin@*"

  # Filter by either sender or recipient
  lc sniff email -i eth0 --address "*@suspicious.com"

  # Filter by subject containing keyword
  lc sniff email -i eth0 --subject "*invoice*"

  # Use keyword file for subject matching
  lc sniff email -i eth0 --keywords-file keywords.txt

  # Match keywords in both subject and body
  lc sniff email -i eth0 --keywords-file keywords.txt --capture-body

  # Read from PCAP file
  lc sniff email -r capture.pcap

  # Capture on non-standard port
  lc sniff email -i eth0 --smtp-port 25,587,2525

  # Write to output file
  lc sniff email -i eth0 -w email-output.pcap`,
	Run: emailHandler,
}

var (
	// Email-specific flags
	emailAddressPattern   string
	emailSenderPattern    string
	emailRecipientPattern string
	emailSubjectPattern   string
	smtpPorts             string
	emailTrackSessions    bool
	emailWriteFile        string

	// Email filter file flags
	emailAddressesFile  string
	emailSendersFile    string
	emailRecipientsFile string
	emailSubjectsFile   string
	emailKeywordsFile   string

	// Body capture flags
	emailCaptureBody bool
	emailMaxBodySize int
)

func emailHandler(cmd *cobra.Command, args []string) {
	// Set email configuration values
	if cmd.Flags().Changed("address") {
		viper.Set("email.address_pattern", emailAddressPattern)
	}
	if cmd.Flags().Changed("sender") {
		viper.Set("email.sender_pattern", emailSenderPattern)
	}
	if cmd.Flags().Changed("recipient") {
		viper.Set("email.recipient_pattern", emailRecipientPattern)
	}
	if cmd.Flags().Changed("subject") {
		viper.Set("email.subject_pattern", emailSubjectPattern)
	}
	if cmd.Flags().Changed("smtp-port") {
		viper.Set("email.ports", smtpPorts)
	}
	if cmd.Flags().Changed("track-sessions") {
		viper.Set("email.track_sessions", emailTrackSessions)
	}
	if emailWriteFile != "" {
		viper.Set("email.write_file", emailWriteFile)
	}
	if cmd.Flags().Changed("capture-body") {
		viper.Set("email.capture_body", emailCaptureBody)
	}
	if cmd.Flags().Changed("max-body-size") {
		viper.Set("email.max_body_size", emailMaxBodySize)
	}

	// Load address patterns from file if specified
	if emailAddressesFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailAddressesFile)
		if err != nil {
			logger.Error("Failed to load addresses file", "error", err, "file", emailAddressesFile)
			return
		}
		viper.Set("email.address_patterns", patterns)
		logger.Info("Loaded address patterns from file", "count", len(patterns), "file", emailAddressesFile)
	}

	// Load sender patterns from file if specified
	if emailSendersFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailSendersFile)
		if err != nil {
			logger.Error("Failed to load senders file", "error", err, "file", emailSendersFile)
			return
		}
		viper.Set("email.sender_patterns", patterns)
		logger.Info("Loaded sender patterns from file", "count", len(patterns), "file", emailSendersFile)
	}

	// Load recipient patterns from file if specified
	if emailRecipientsFile != "" {
		patterns, err := email.LoadEmailPatternsFromFile(emailRecipientsFile)
		if err != nil {
			logger.Error("Failed to load recipients file", "error", err, "file", emailRecipientsFile)
			return
		}
		viper.Set("email.recipient_patterns", patterns)
		logger.Info("Loaded recipient patterns from file", "count", len(patterns), "file", emailRecipientsFile)
	}

	// Load subject patterns from file if specified
	if emailSubjectsFile != "" {
		patterns, err := email.LoadSubjectPatternsFromFile(emailSubjectsFile)
		if err != nil {
			logger.Error("Failed to load subjects file", "error", err, "file", emailSubjectsFile)
			return
		}
		viper.Set("email.subject_patterns", patterns)
		logger.Info("Loaded subject patterns from file", "count", len(patterns), "file", emailSubjectsFile)
	}

	// Load keywords from file if specified
	if emailKeywordsFile != "" {
		keywords, err := email.LoadKeywordsFromFile(emailKeywordsFile)
		if err != nil {
			logger.Error("Failed to load keywords file", "error", err, "file", emailKeywordsFile)
			return
		}
		viper.Set("email.keywords", keywords)
		logger.Info("Loaded keywords from file", "count", len(keywords), "file", emailKeywordsFile)
	}

	// Build email filter
	filterBuilder := email.NewFilterBuilder()
	ports, err := email.ParsePorts(smtpPorts)
	if err != nil {
		logger.Error("Invalid SMTP port specification", "error", err)
		return
	}

	filterConfig := email.FilterConfig{
		Ports:      ports,
		BaseFilter: filter,
	}
	effectiveFilter := filterBuilder.Build(filterConfig)

	logger.Info("Starting Email sniffing",
		"interfaces", interfaces,
		"filter", effectiveFilter,
		"address_pattern", emailAddressPattern,
		"sender_pattern", emailSenderPattern,
		"recipient_pattern", emailRecipientPattern,
		"subject_pattern", emailSubjectPattern,
		"track_sessions", emailTrackSessions)

	// Start email sniffer using appropriate mode
	if readFile == "" {
		email.StartLiveEmailSniffer(interfaces, effectiveFilter)
	} else {
		email.StartOfflineEmailSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// Email-specific flags - single patterns
	emailCmd.Flags().StringVar(&emailAddressPattern, "address", "", "Filter by email address pattern (matches sender OR recipient, glob-style, e.g., '*@example.com')")
	emailCmd.Flags().StringVar(&emailSenderPattern, "sender", "", "Filter by sender address pattern (MAIL FROM, glob-style)")
	emailCmd.Flags().StringVar(&emailRecipientPattern, "recipient", "", "Filter by recipient address pattern (RCPT TO, glob-style)")
	emailCmd.Flags().StringVar(&emailSubjectPattern, "subject", "", "Filter by subject pattern (glob-style)")

	// Email filter file flags - bulk patterns
	emailCmd.Flags().StringVar(&emailAddressesFile, "addresses-file", "", "Load address patterns from file (one per line)")
	emailCmd.Flags().StringVar(&emailSendersFile, "senders-file", "", "Load sender patterns from file (one per line)")
	emailCmd.Flags().StringVar(&emailRecipientsFile, "recipients-file", "", "Load recipient patterns from file (one per line)")
	emailCmd.Flags().StringVar(&emailSubjectsFile, "subjects-file", "", "Load subject patterns from file (one per line)")
	emailCmd.Flags().StringVar(&emailKeywordsFile, "keywords-file", "", "Load keywords from file for subject matching (Aho-Corasick)")

	// Other email flags
	emailCmd.Flags().StringVar(&smtpPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")
	emailCmd.Flags().BoolVar(&emailTrackSessions, "track-sessions", true, "Enable session tracking")
	emailCmd.Flags().StringVarP(&emailWriteFile, "write-file", "w", "", "Write captured email packets to PCAP file")

	// Body capture flags
	emailCmd.Flags().BoolVar(&emailCaptureBody, "capture-body", false, "Enable email body content capture (for keyword matching)")
	emailCmd.Flags().IntVar(&emailMaxBodySize, "max-body-size", 65536, "Maximum body size to capture in bytes (default: 64KB)")

	// Bind to viper for config file support
	_ = viper.BindPFlag("email.address_pattern", emailCmd.Flags().Lookup("address"))
	_ = viper.BindPFlag("email.sender_pattern", emailCmd.Flags().Lookup("sender"))
	_ = viper.BindPFlag("email.recipient_pattern", emailCmd.Flags().Lookup("recipient"))
	_ = viper.BindPFlag("email.subject_pattern", emailCmd.Flags().Lookup("subject"))
	_ = viper.BindPFlag("email.addresses_file", emailCmd.Flags().Lookup("addresses-file"))
	_ = viper.BindPFlag("email.senders_file", emailCmd.Flags().Lookup("senders-file"))
	_ = viper.BindPFlag("email.recipients_file", emailCmd.Flags().Lookup("recipients-file"))
	_ = viper.BindPFlag("email.subjects_file", emailCmd.Flags().Lookup("subjects-file"))
	_ = viper.BindPFlag("email.keywords_file", emailCmd.Flags().Lookup("keywords-file"))
	_ = viper.BindPFlag("email.ports", emailCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("email.track_sessions", emailCmd.Flags().Lookup("track-sessions"))
	_ = viper.BindPFlag("email.capture_body", emailCmd.Flags().Lookup("capture-body"))
	_ = viper.BindPFlag("email.max_body_size", emailCmd.Flags().Lookup("max-body-size"))
}
