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

Examples:
  # Basic SMTP capture
  lc sniff email -i eth0

  # Filter for specific address pattern
  lc sniff email -i eth0 --address "*@example.com"

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
	emailAddressPattern string
	smtpPorts           string
	emailTrackSessions  bool
	emailWriteFile      string
)

func emailHandler(cmd *cobra.Command, args []string) {
	// Set email configuration values
	if cmd.Flags().Changed("address") {
		viper.Set("email.address_pattern", emailAddressPattern)
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
		"track_sessions", emailTrackSessions)

	// Start email sniffer using appropriate mode
	if readFile == "" {
		email.StartLiveEmailSniffer(interfaces, effectiveFilter)
	} else {
		email.StartOfflineEmailSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// Email-specific flags
	emailCmd.Flags().StringVar(&emailAddressPattern, "address", "", "Filter by email address pattern (glob-style, e.g., '*@example.com')")
	emailCmd.Flags().StringVar(&smtpPorts, "smtp-port", "25,587,465", "SMTP port(s) to capture, comma-separated")
	emailCmd.Flags().BoolVar(&emailTrackSessions, "track-sessions", true, "Enable session tracking")
	emailCmd.Flags().StringVarP(&emailWriteFile, "write-file", "w", "", "Write captured email packets to PCAP file")

	// Bind to viper for config file support
	_ = viper.BindPFlag("email.address_pattern", emailCmd.Flags().Lookup("address"))
	_ = viper.BindPFlag("email.ports", emailCmd.Flags().Lookup("smtp-port"))
	_ = viper.BindPFlag("email.track_sessions", emailCmd.Flags().Lookup("track-sessions"))
}
