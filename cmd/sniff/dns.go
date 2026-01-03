//go:build cli || all

package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Sniff in DNS mode",
	Long: `Sniff in DNS mode. Capture and analyze DNS queries and responses.

Features:
- Query/response correlation with response time tracking
- DNS tunneling detection via entropy analysis
- Domain pattern filtering (glob-style wildcards)
- Top queried domains statistics

Examples:
  # Basic DNS capture
  lc sniff dns -i eth0

  # Filter for specific domain pattern
  lc sniff dns -i eth0 --domain "*.example.com"

  # Read from PCAP file
  lc sniff dns -r capture.pcap

  # Write to output file
  lc sniff dns -i eth0 -w dns-output.pcap`,
	Run: dnsHandler,
}

var (
	// DNS-specific flags
	dnsDomainPattern string
	dnsUDPOnly       bool
	dnsPorts         string
	dnsTrackQueries  bool
	dnsDetectTunnel  bool
	dnsWriteFile     string
)

func dnsHandler(cmd *cobra.Command, args []string) {
	// Set DNS configuration values
	if cmd.Flags().Changed("domain") {
		viper.Set("dns.domain_pattern", dnsDomainPattern)
	}
	if cmd.Flags().Changed("udp-only") {
		viper.Set("dns.udp_only", dnsUDPOnly)
	}
	if cmd.Flags().Changed("dns-port") {
		viper.Set("dns.ports", dnsPorts)
	}
	if cmd.Flags().Changed("track-queries") {
		viper.Set("dns.track_queries", dnsTrackQueries)
	}
	if cmd.Flags().Changed("detect-tunneling") {
		viper.Set("dns.detect_tunneling", dnsDetectTunnel)
	}
	if dnsWriteFile != "" {
		viper.Set("dns.write_file", dnsWriteFile)
	}

	// Build DNS filter
	filterBuilder := dns.NewFilterBuilder()
	ports, err := dns.ParsePorts(dnsPorts)
	if err != nil {
		logger.Error("Invalid DNS port specification", "error", err)
		return
	}

	filterConfig := dns.FilterConfig{
		Ports:      ports,
		UDPOnly:    dnsUDPOnly,
		BaseFilter: filter,
	}
	effectiveFilter := filterBuilder.Build(filterConfig)

	logger.Info("Starting DNS sniffing",
		"interfaces", interfaces,
		"filter", effectiveFilter,
		"domain_pattern", dnsDomainPattern,
		"track_queries", dnsTrackQueries,
		"detect_tunneling", dnsDetectTunnel)

	// Start DNS sniffer using appropriate mode
	if readFile == "" {
		dns.StartLiveDNSSniffer(interfaces, effectiveFilter)
	} else {
		dns.StartOfflineDNSSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// DNS-specific flags
	dnsCmd.Flags().StringVar(&dnsDomainPattern, "domain", "", "Filter by domain pattern (glob-style, e.g., '*.example.com')")
	dnsCmd.Flags().BoolVar(&dnsUDPOnly, "udp-only", false, "Capture UDP DNS only (ignore TCP DNS)")
	dnsCmd.Flags().StringVar(&dnsPorts, "dns-port", "53", "DNS port(s) to capture, comma-separated (default: 53)")
	dnsCmd.Flags().BoolVar(&dnsTrackQueries, "track-queries", true, "Enable query/response correlation")
	dnsCmd.Flags().BoolVar(&dnsDetectTunnel, "detect-tunneling", true, "Enable DNS tunneling detection")
	dnsCmd.Flags().StringVarP(&dnsWriteFile, "write-file", "w", "", "Write captured DNS packets to PCAP file")

	// Bind to viper for config file support
	_ = viper.BindPFlag("dns.domain_pattern", dnsCmd.Flags().Lookup("domain"))
	_ = viper.BindPFlag("dns.udp_only", dnsCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("dns.ports", dnsCmd.Flags().Lookup("dns-port"))
	_ = viper.BindPFlag("dns.track_queries", dnsCmd.Flags().Lookup("track-queries"))
	_ = viper.BindPFlag("dns.detect_tunneling", dnsCmd.Flags().Lookup("detect-tunneling"))
}
