//go:build cli || all

package sniff

import (
	"fmt"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var voipCmd = &cobra.Command{
	Use:   "voip",
	Short: "Sniff in VOIP mode",
	Long:  `Sniff in VOIP mode. Filter for SIP username, capture RTP stream.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Handle deprecated --sipuser flag migration to --sip-user
		if cmd.Flags().Changed("sipuser") {
			if cmd.Flags().Changed("sip-user") {
				return fmt.Errorf("cannot use both --sipuser (deprecated) and --sip-user; use --sip-user only")
			}
			sipuser = sipuserDeprecated
			logger.Warn("--sipuser is deprecated, use --sip-user instead")
		}
		return nil
	},
	Run: voipHandler,
}

var (
	sipuser           string
	sipuserDeprecated string // deprecated, use sipuser (via --sip-user)
	writeVoipFile     string

	// BPF filter optimization flags
	udpOnly       bool
	sipPorts      string
	rtpPortRanges string

	// Pattern matching flags
	patternAlgorithm string
	patternBufferMB  int

	// TCP-specific configuration flags
	tcpMaxGoroutines      int
	tcpCleanupInterval    time.Duration
	tcpBufferMaxAge       time.Duration
	tcpStreamMaxQueueTime time.Duration
	maxTCPBuffers         int
	tcpStreamTimeout      time.Duration
	tcpAssemblerMaxPages  int
	tcpPerformanceMode    string
	tcpBufferStrategy     string
	enableBackpressure    bool
	memoryOptimization    bool

	// Virtual interface flags inherited from parent SniffCmd
	// (defined in sniff.go as PersistentFlags)
)

func voipHandler(cmd *cobra.Command, args []string) {
	expirationDate := time.Date(1, 1, 1, 1, 1, 1, 1, time.UTC)
	su := sipusers.SipUser{ExpirationDate: expirationDate}

	// Only add non-empty users to surveillance list
	// If no users specified, promiscuous mode (accept all VoIP traffic)
	if sipuser != "" {
		for _, user := range strings.Split(sipuser, ",") {
			user = strings.TrimSpace(user)
			if user != "" {
				sipusers.AddSipUser(user, &su)
			}
		}
	}

	// Set writeVoip based on whether --write-file was provided
	writeVoip := writeVoipFile != ""

	logger.Info("Starting VoIP sniffing",
		"users", strings.Split(sipuser, ","),
		"interfaces", interfaces,
		"write_voip", writeVoip,
		"output_file", writeVoipFile)
	viper.Set("writeVoip", writeVoip)
	if writeVoipFile != "" {
		viper.Set("voip.output_file", writeVoipFile)
	}

	// Set GPU configuration values (no-op in non-CUDA builds)
	ApplyGPUConfig(cmd)

	// Set pattern algorithm configuration values
	if cmd.Flags().Changed("pattern-algorithm") {
		viper.Set("voip.pattern_algorithm", patternAlgorithm)
	}
	if cmd.Flags().Changed("pattern-buffer-mb") {
		viper.Set("voip.pattern_buffer_mb", patternBufferMB)
	}

	// Set TCP-specific configuration values
	if cmd.Flags().Changed("tcp-max-goroutines") {
		viper.Set("voip.max_goroutines", tcpMaxGoroutines)
	}
	if cmd.Flags().Changed("tcp-cleanup-interval") {
		viper.Set("voip.tcp_cleanup_interval", tcpCleanupInterval)
	}
	if cmd.Flags().Changed("tcp-buffer-max-age") {
		viper.Set("voip.tcp_buffer_max_age", tcpBufferMaxAge)
	}
	if cmd.Flags().Changed("tcp-stream-max-queue-time") {
		viper.Set("voip.tcp_stream_max_queue_time", tcpStreamMaxQueueTime)
	}
	if cmd.Flags().Changed("max-tcp-buffers") {
		viper.Set("voip.max_tcp_buffers", maxTCPBuffers)
	}
	if cmd.Flags().Changed("tcp-stream-timeout") {
		viper.Set("voip.tcp_stream_timeout", tcpStreamTimeout)
	}
	if cmd.Flags().Changed("tcp-assembler-max-pages") {
		viper.Set("voip.tcp_assembler_max_pages", tcpAssemblerMaxPages)
	}
	if cmd.Flags().Changed("tcp-performance-mode") {
		viper.Set("voip.tcp_performance_mode", tcpPerformanceMode)
	}
	if cmd.Flags().Changed("tcp-buffer-strategy") {
		viper.Set("voip.tcp_buffer_strategy", tcpBufferStrategy)
	}
	if cmd.Flags().Changed("enable-backpressure") {
		viper.Set("voip.enable_backpressure", enableBackpressure)
	}
	if cmd.Flags().Changed("memory-optimization") {
		viper.Set("voip.memory_optimization", memoryOptimization)
	}

	// Virtual interface flags are inherited from parent SniffCmd
	// They are automatically bound to viper via sniff.go init()
	// Read from sniff.* namespace (not voip.* namespace)

	// Build optimized BPF filter using VoIPFilterBuilder
	effectiveFilter := filter // Start with the base --filter value

	// Parse BPF filter optimization flags (from flags or viper config)
	voipUDPOnly := viper.GetBool("voip.udp_only")
	voipSIPPorts := viper.GetString("voip.sip_ports")
	voipRTPPortRanges := viper.GetString("voip.rtp_port_ranges")

	// Warn if no SIP port filter is specified - all TCP will be captured
	if voipSIPPorts == "" && !voipUDPOnly {
		logger.Warn("No --sip-port specified: capturing all TCP traffic for SIP detection")
		logger.Warn("For better performance, use: --sip-port 5060 (or your SIP port)")
	}

	// Only build VoIP filter if any optimization flags are set
	if voipUDPOnly || voipSIPPorts != "" || voipRTPPortRanges != "" {
		// Parse SIP ports
		parsedSIPPorts, err := voip.ParsePorts(voipSIPPorts)
		if err != nil {
			logger.Error("Invalid --sip-port value", "error", err)
			return
		}

		// Parse RTP port ranges
		parsedRTPRanges, err := voip.ParsePortRanges(voipRTPPortRanges)
		if err != nil {
			logger.Error("Invalid --rtp-port-range value", "error", err)
			return
		}

		// Build optimized filter
		builder := voip.NewVoIPFilterBuilder()
		filterConfig := voip.VoIPFilterConfig{
			SIPPorts:      parsedSIPPorts,
			RTPPortRanges: parsedRTPRanges,
			UDPOnly:       voipUDPOnly,
			BaseFilter:    filter,
		}
		effectiveFilter = builder.Build(filterConfig)

		logger.Info("VoIP BPF filter optimization enabled",
			"udp_only", voipUDPOnly,
			"sip_ports", voipSIPPorts,
			"rtp_port_ranges", voipRTPPortRanges,
			"effective_filter", effectiveFilter)
	}

	logger.Info("Starting VoIP sniffing with optimizations",
		"gpu_enable", viper.GetBool("voip.gpu_enable"),
		"gpu_backend", viper.GetString("voip.gpu_backend"),
		"pattern_algorithm", viper.GetString("voip.pattern_algorithm"),
		"pattern_buffer_mb", viper.GetInt("voip.pattern_buffer_mb"),
		"tcp_max_goroutines", viper.GetInt("voip.max_goroutines"),
		"tcp_performance_mode", viper.GetString("voip.tcp_performance_mode"),
		"tcp_buffer_strategy", viper.GetString("voip.tcp_buffer_strategy"),
		"enable_backpressure", viper.GetBool("voip.enable_backpressure"),
		"memory_optimization", viper.GetBool("voip.memory_optimization"),
		"virtual_interface", viper.GetBool("sniff.virtual_interface"),
		"vif_name", viper.GetString("sniff.vif_name"),
		"vif_startup_delay", viper.GetDuration("sniff.vif_startup_delay"),
		"vif_replay_timing", viper.GetBool("sniff.vif_replay_timing"))

	if readFile == "" {
		voip.StartLiveVoipSniffer(interfaces, effectiveFilter)
	} else {
		voip.StartOfflineVoipSniffer(readFile, effectiveFilter)
	}
}

func init() {
	// --sip-user is the new flag, --sipuser is deprecated
	voipCmd.Flags().StringVarP(&sipuser, "sip-user", "u", "", "SIP user/phone to match (supports wildcards: '*456789' for suffix, 'alice*' for prefix)")
	voipCmd.Flags().StringVar(&sipuserDeprecated, "sipuser", "", "")
	voipCmd.Flags().Lookup("sipuser").Deprecated = "use --sip-user instead"
	voipCmd.Flags().Lookup("sipuser").Hidden = true
	voipCmd.Flags().StringVarP(&writeVoipFile, "write-file", "w", "", "prefix for output pcap files (creates <prefix>_sip_<callid>.pcap and <prefix>_rtp_<callid>.pcap)")

	// BPF Filter Optimization Flags
	voipCmd.Flags().BoolVarP(&udpOnly, "udp-only", "U", false, "")
	voipCmd.Flags().Lookup("udp-only").Deprecated = "this flag misses TCP SIP traffic; use --sip-port instead for proper BPF filtering"
	voipCmd.Flags().Lookup("udp-only").Hidden = true
	voipCmd.Flags().StringVarP(&sipPorts, "sip-port", "S", "", "Restrict SIP capture to specific port(s), comma-separated (e.g., '5060' or '5060,5061,5080')")
	voipCmd.Flags().StringVarP(&rtpPortRanges, "rtp-port-range", "R", "", "Custom RTP port range(s), comma-separated (e.g., '8000-9000' or '8000-9000,40000-50000'). Default: 10000-32768")

	// Bind BPF filter optimization flags to viper
	_ = viper.BindPFlag("voip.udp_only", voipCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("voip.sip_ports", voipCmd.Flags().Lookup("sip-port"))
	_ = viper.BindPFlag("voip.rtp_port_ranges", voipCmd.Flags().Lookup("rtp-port-range"))

	// GPU Acceleration Flags (only registered in CUDA builds)
	RegisterGPUFlags(voipCmd)

	// Pattern Matching Algorithm Flags
	voipCmd.Flags().StringVar(&patternAlgorithm, "pattern-algorithm", "auto", "Pattern matching algorithm: 'auto', 'linear', 'aho-corasick' (default: auto)")
	voipCmd.Flags().IntVar(&patternBufferMB, "pattern-buffer-mb", 64, "Memory budget for pattern buffer in MB (default: 64)")

	// TCP Performance and Configuration Flags
	voipCmd.Flags().IntVar(&tcpMaxGoroutines, "tcp-max-goroutines", 0, "Maximum concurrent TCP stream processing goroutines (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpCleanupInterval, "tcp-cleanup-interval", 0, "TCP resource cleanup interval (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpBufferMaxAge, "tcp-buffer-max-age", 0, "Maximum age for TCP packet buffers (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpStreamMaxQueueTime, "tcp-stream-max-queue-time", 0, "Maximum time a stream can wait in queue (0 = use default)")
	voipCmd.Flags().IntVar(&maxTCPBuffers, "max-tcp-buffers", 0, "Maximum number of TCP packet buffers (0 = use default)")
	voipCmd.Flags().DurationVar(&tcpStreamTimeout, "tcp-stream-timeout", 0, "Timeout for TCP stream processing (0 = use default)")
	voipCmd.Flags().IntVar(&tcpAssemblerMaxPages, "tcp-assembler-max-pages", 0, "Maximum pages for TCP assembler (0 = use default)")

	// TCP Performance Optimization Flags
	voipCmd.Flags().StringVarP(&tcpPerformanceMode, "tcp-performance-mode", "M", "", "TCP performance mode: 'balanced', 'throughput', 'latency', 'memory' (default: balanced)")
	voipCmd.Flags().StringVar(&tcpBufferStrategy, "tcp-buffer-strategy", "", "TCP buffering strategy: 'adaptive', 'fixed', 'ring' (default: adaptive)")
	voipCmd.Flags().BoolVar(&enableBackpressure, "enable-backpressure", false, "Enable backpressure handling for TCP streams")
	voipCmd.Flags().BoolVar(&memoryOptimization, "memory-optimization", false, "Enable memory usage optimizations")

	// Bind GPU flags to viper (only in CUDA builds)
	BindGPUViperFlags(voipCmd)

	// Bind pattern algorithm flags to viper for config file support
	_ = viper.BindPFlag("voip.pattern_algorithm", voipCmd.Flags().Lookup("pattern-algorithm"))
	_ = viper.BindPFlag("voip.pattern_buffer_mb", voipCmd.Flags().Lookup("pattern-buffer-mb"))

	// Bind flags to viper for config file support
	_ = viper.BindPFlag("voip.max_goroutines", voipCmd.Flags().Lookup("tcp-max-goroutines"))
	_ = viper.BindPFlag("voip.tcp_cleanup_interval", voipCmd.Flags().Lookup("tcp-cleanup-interval"))
	_ = viper.BindPFlag("voip.tcp_buffer_max_age", voipCmd.Flags().Lookup("tcp-buffer-max-age"))
	_ = viper.BindPFlag("voip.tcp_stream_max_queue_time", voipCmd.Flags().Lookup("tcp-stream-max-queue-time"))
	_ = viper.BindPFlag("voip.max_tcp_buffers", voipCmd.Flags().Lookup("max-tcp-buffers"))
	_ = viper.BindPFlag("voip.tcp_stream_timeout", voipCmd.Flags().Lookup("tcp-stream-timeout"))
	_ = viper.BindPFlag("voip.tcp_assembler_max_pages", voipCmd.Flags().Lookup("tcp-assembler-max-pages"))
	_ = viper.BindPFlag("voip.tcp_performance_mode", voipCmd.Flags().Lookup("tcp-performance-mode"))
	_ = viper.BindPFlag("voip.tcp_buffer_strategy", voipCmd.Flags().Lookup("tcp-buffer-strategy"))
	_ = viper.BindPFlag("voip.enable_backpressure", voipCmd.Flags().Lookup("enable-backpressure"))
	_ = viper.BindPFlag("voip.memory_optimization", voipCmd.Flags().Lookup("memory-optimization"))

	// Virtual Interface Flags are inherited from parent SniffCmd (sniff.go)
	// No need to register them here - they're PersistentFlags on the parent
}
