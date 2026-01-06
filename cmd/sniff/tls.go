//go:build cli || all

package sniff

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Sniff in TLS mode",
	Long: `Sniff in TLS mode. Capture and analyze TLS handshakes.

Features:
- JA3/JA3S/JA4 fingerprint calculation
- SNI (Server Name Indication) extraction
- ClientHello/ServerHello correlation
- TLS version and cipher suite analysis
- Fingerprint-based filtering

Examples:
  # Basic TLS capture
  lc sniff tls -i eth0

  # Filter by SNI pattern
  lc sniff tls -i eth0 --sni "*.example.com"

  # Filter by JA3 fingerprint (known malware fingerprint)
  lc sniff tls -i eth0 --ja3 "e35d9e5ba41e1b6e51ba3ee8...

  # Read from PCAP file
  lc sniff tls -r capture.pcap

  # Write matching packets to file
  lc sniff tls -i eth0 -w tls-output.pcap`,
	Run: tlsHandler,
}

var (
	// TLS-specific flags
	tlsSNIPattern string
	tlsSNIFile    string
	tlsJA3        string
	tlsJA3File    string
	tlsJA3S       string
	tlsJA3SFile   string
	tlsJA4        string
	tlsJA4File    string
	tlsPorts      string
	tlsTrackConns bool
	tlsWriteFile  string
)

func tlsHandler(cmd *cobra.Command, args []string) {
	// Set TLS configuration values
	if cmd.Flags().Changed("sni") {
		viper.Set("tls.sni_pattern", tlsSNIPattern)
	}
	if cmd.Flags().Changed("tls-port") {
		viper.Set("tls.ports", tlsPorts)
	}
	if cmd.Flags().Changed("track-connections") {
		viper.Set("tls.track_connections", tlsTrackConns)
	}
	if tlsWriteFile != "" {
		viper.Set("tls.write_file", tlsWriteFile)
	}

	// Load SNI patterns from file if specified
	if tlsSNIFile != "" {
		patterns, err := tls.LoadSNIPatternsFromFile(tlsSNIFile)
		if err != nil {
			logger.Error("Failed to load SNI patterns file", "error", err, "file", tlsSNIFile)
			return
		}
		viper.Set("tls.sni_patterns", patterns)
		logger.Info("Loaded SNI patterns from file", "count", len(patterns), "file", tlsSNIFile)
	}

	// Set JA3 filters
	if cmd.Flags().Changed("ja3") {
		if !tls.IsValidJA3Hash(tlsJA3) {
			logger.Error("Invalid JA3 hash format (must be 32-char hex)", "hash", tlsJA3)
			return
		}
		viper.Set("tls.ja3", tlsJA3)
	}
	if tlsJA3File != "" {
		hashes, err := tls.LoadJA3HashesFromFile(tlsJA3File)
		if err != nil {
			logger.Error("Failed to load JA3 hashes file", "error", err, "file", tlsJA3File)
			return
		}
		viper.Set("tls.ja3_hashes", hashes)
		logger.Info("Loaded JA3 hashes from file", "count", len(hashes), "file", tlsJA3File)
	}

	// Set JA3S filters
	if cmd.Flags().Changed("ja3s") {
		if !tls.IsValidJA3Hash(tlsJA3S) {
			logger.Error("Invalid JA3S hash format (must be 32-char hex)", "hash", tlsJA3S)
			return
		}
		viper.Set("tls.ja3s", tlsJA3S)
	}
	if tlsJA3SFile != "" {
		hashes, err := tls.LoadJA3SHashesFromFile(tlsJA3SFile)
		if err != nil {
			logger.Error("Failed to load JA3S hashes file", "error", err, "file", tlsJA3SFile)
			return
		}
		viper.Set("tls.ja3s_hashes", hashes)
		logger.Info("Loaded JA3S hashes from file", "count", len(hashes), "file", tlsJA3SFile)
	}

	// Set JA4 filters
	if cmd.Flags().Changed("ja4") {
		if !tls.IsValidJA4Fingerprint(tlsJA4) {
			logger.Error("Invalid JA4 fingerprint format", "fingerprint", tlsJA4)
			return
		}
		viper.Set("tls.ja4", tlsJA4)
	}
	if tlsJA4File != "" {
		fingerprints, err := tls.LoadJA4FingerprintsFromFile(tlsJA4File)
		if err != nil {
			logger.Error("Failed to load JA4 fingerprints file", "error", err, "file", tlsJA4File)
			return
		}
		viper.Set("tls.ja4_fingerprints", fingerprints)
		logger.Info("Loaded JA4 fingerprints from file", "count", len(fingerprints), "file", tlsJA4File)
	}

	// Build TLS filter
	filterBuilder := tls.NewFilterBuilder()
	ports, err := tls.ParsePorts(tlsPorts)
	if err != nil {
		logger.Error("Invalid TLS port specification", "error", err)
		return
	}

	filterConfig := tls.FilterConfig{
		Ports:      ports,
		BaseFilter: filter,
	}
	effectiveFilter := filterBuilder.Build(filterConfig)

	logger.Info("Starting TLS sniffing",
		"interfaces", interfaces,
		"filter", effectiveFilter,
		"sni_pattern", tlsSNIPattern,
		"sni_file", tlsSNIFile,
		"ja3", tlsJA3 != "",
		"ja3s", tlsJA3S != "",
		"ja4", tlsJA4 != "",
		"track_connections", tlsTrackConns)

	// Start TLS sniffer using appropriate mode
	if readFile == "" {
		tls.StartLiveTLSSniffer(interfaces, effectiveFilter)
	} else {
		tls.StartOfflineTLSSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// TLS-specific flags
	tlsCmd.Flags().StringVar(&tlsSNIPattern, "sni", "", "Filter by SNI pattern (glob-style, e.g., '*.example.com')")
	tlsCmd.Flags().StringVar(&tlsSNIFile, "sni-file", "", "Load SNI patterns from file (one per line)")
	tlsCmd.Flags().StringVar(&tlsJA3, "ja3", "", "Filter by JA3 fingerprint hash (32-char hex)")
	tlsCmd.Flags().StringVar(&tlsJA3File, "ja3-file", "", "Load JA3 hashes from file (one per line)")
	tlsCmd.Flags().StringVar(&tlsJA3S, "ja3s", "", "Filter by JA3S fingerprint hash (32-char hex)")
	tlsCmd.Flags().StringVar(&tlsJA3SFile, "ja3s-file", "", "Load JA3S hashes from file (one per line)")
	tlsCmd.Flags().StringVar(&tlsJA4, "ja4", "", "Filter by JA4 fingerprint (e.g., t13d1516h2_...)")
	tlsCmd.Flags().StringVar(&tlsJA4File, "ja4-file", "", "Load JA4 fingerprints from file (one per line)")
	tlsCmd.Flags().StringVar(&tlsPorts, "tls-port", "443", "TLS port(s) to capture, comma-separated")
	tlsCmd.Flags().BoolVar(&tlsTrackConns, "track-connections", true, "Enable ClientHello/ServerHello correlation")
	tlsCmd.Flags().StringVarP(&tlsWriteFile, "write-file", "w", "", "Write captured TLS packets to PCAP file")

	// Bind to viper for config file support
	_ = viper.BindPFlag("tls.sni_pattern", tlsCmd.Flags().Lookup("sni"))
	_ = viper.BindPFlag("tls.sni_file", tlsCmd.Flags().Lookup("sni-file"))
	_ = viper.BindPFlag("tls.ja3", tlsCmd.Flags().Lookup("ja3"))
	_ = viper.BindPFlag("tls.ja3_file", tlsCmd.Flags().Lookup("ja3-file"))
	_ = viper.BindPFlag("tls.ja3s", tlsCmd.Flags().Lookup("ja3s"))
	_ = viper.BindPFlag("tls.ja3s_file", tlsCmd.Flags().Lookup("ja3s-file"))
	_ = viper.BindPFlag("tls.ja4", tlsCmd.Flags().Lookup("ja4"))
	_ = viper.BindPFlag("tls.ja4_file", tlsCmd.Flags().Lookup("ja4-file"))
	_ = viper.BindPFlag("tls.ports", tlsCmd.Flags().Lookup("tls-port"))
	_ = viper.BindPFlag("tls.track_connections", tlsCmd.Flags().Lookup("track-connections"))
}
