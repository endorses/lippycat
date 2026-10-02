//go:build hunter || all

package hunt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// BPF filter optimization flags for VoIP hunter
	hunterUDPOnly       bool
	hunterSIPPorts      string
	hunterRTPPortRanges string

	// Pattern matching flags for VoIP hunter
	hunterPatternAlgorithm string
	hunterPatternBufferMB  int

	// TCP SIP configuration
	hunterTCPSIPIdleTimeout time.Duration
	hunterTCPMaxStreams     int
)

var voipHuntCmd = &cobra.Command{
	Use:   "voip",
	Short: "Run as VoIP hunter with call buffering",
	Long: `Run lippycat in VoIP hunter mode with packet buffering and call filtering.

VoIP hunter mode captures SIP/RTP packets, buffers them until the call can be
identified, then applies filters received from the processor. Only matched calls
are forwarded, reducing bandwidth and storage.

Features:
- SIP header extraction (From, To, P-Asserted-Identity)
- SDP parsing for RTP port discovery
- Per-call packet buffering (SIP + RTP)
- Filter matching using processor-provided filters
- Selective forwarding (only matched calls)

Filters are managed centrally by the processor and pushed to hunters via
the filter subscription mechanism. Use the processor's management API or
filter file to configure which SIP users to track.

Example:
  lc hunt voip --processor processor:55555
  lc hunt voip --processor 192.168.1.100:55555 --interface eth0`,
	RunE: runVoIPHunt,
}

func init() {
	HuntCmd.AddCommand(voipHuntCmd)
	cmdutil.RegisterMediaAdmissionFlags(voipHuntCmd, viper.GetViper(), "hunter.voip.rtp_ebpf")

	// BPF Filter Optimization Flags (VoIP-specific)
	voipHuntCmd.Flags().BoolVarP(&hunterUDPOnly, "udp-only", "U", false, "")
	voipHuntCmd.Flags().Lookup("udp-only").Deprecated = "this flag misses TCP SIP traffic; use --sip-port instead for proper BPF filtering"
	voipHuntCmd.Flags().Lookup("udp-only").Hidden = true
	voipHuntCmd.Flags().StringVarP(&hunterSIPPorts, "sip-port", "S", "", "Restrict SIP capture to specific port(s), comma-separated (e.g., '5060' or '5060,5061,5080')")
	voipHuntCmd.Flags().StringVarP(&hunterRTPPortRanges, "rtp-port-range", "R", "", "Custom RTP port range(s), comma-separated (e.g., '8000-9000' or '8000-9000,40000-50000'). Default: 10000-32768")

	// Pattern Matching Algorithm Flags (VoIP-specific)
	voipHuntCmd.Flags().StringVar(&hunterPatternAlgorithm, "pattern-algorithm", "auto", "Pattern matching algorithm: 'auto', 'linear', 'aho-corasick' (default: auto)")
	voipHuntCmd.Flags().IntVar(&hunterPatternBufferMB, "pattern-buffer-mb", 64, "Memory budget for pattern buffer in MB (default: 64)")

	// TCP SIP configuration
	voipHuntCmd.Flags().DurationVar(&hunterTCPSIPIdleTimeout, "tcp-sip-idle-timeout", 0, "Idle timeout for SIP TCP connections (default: 120s, 0 = use default)")
	voipHuntCmd.Flags().IntVar(&hunterTCPMaxStreams, "tcp-max-streams", 0, "Maximum active buffered TCP SIP connections, both directions per slot (0 = unlimited)")

	// Bind BPF filter optimization flags to viper under hunter.voip.* namespace
	_ = viper.BindPFlag("hunter.voip.udp_only", voipHuntCmd.Flags().Lookup("udp-only"))
	_ = viper.BindPFlag("hunter.voip.sip_ports", voipHuntCmd.Flags().Lookup("sip-port"))
	_ = viper.BindPFlag("hunter.voip.rtp_port_ranges", voipHuntCmd.Flags().Lookup("rtp-port-range"))

	// Bind pattern algorithm flags to viper
	_ = viper.BindPFlag("voip.pattern_algorithm", voipHuntCmd.Flags().Lookup("pattern-algorithm"))
	_ = viper.BindPFlag("voip.pattern_buffer_mb", voipHuntCmd.Flags().Lookup("pattern-buffer-mb"))
	_ = viper.BindPFlag("voip.tcp_sip_idle_timeout", voipHuntCmd.Flags().Lookup("tcp-sip-idle-timeout"))
	_ = viper.BindPFlag("voip.max_streams", voipHuntCmd.Flags().Lookup("tcp-max-streams"))
}

func runVoIPHunt(cmd *cobra.Command, args []string) error {
	admissionConfig, err := cmdutil.ReadMediaAdmissionConfig(viper.GetViper(), "hunter.voip.rtp_ebpf")
	if err != nil {
		return err
	}
	streamConfig, err := huntSIPStreamConfig(cmd)
	if err != nil {
		return err
	}
	logger.Info("Starting lippycat in VoIP hunter mode")
	logger.Info("VoIP filters will be received from processor via filter subscription")

	// Production mode enforcement
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
	if productionMode {
		if cmdutil.GetBoolConfig("insecure", insecureAllowed) {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
		}
		logger.Info("Production mode: TLS encryption enforced")
	}

	// Build optimized BPF filter using VoIPFilterBuilder
	baseBPFFilter := cmdutil.GetStringConfig("hunter.bpf_filter", bpfFilter)
	effectiveBPFFilter := baseBPFFilter

	// Parse BPF filter optimization flags (from flags or viper config)
	voipUDPOnly := viper.GetBool("hunter.voip.udp_only")
	voipSIPPorts := viper.GetString("hunter.voip.sip_ports")
	voipRTPPortRanges := viper.GetString("hunter.voip.rtp_port_ranges")

	// Warn if no SIP port filter is specified - all TCP will be captured
	if voipSIPPorts == "" && !voipUDPOnly {
		logger.Warn("No --sip-port specified: capturing all TCP traffic for SIP detection")
		logger.Warn("For better performance, use: --sip-port 5060 (or your SIP port)")
	}

	// Only build VoIP filter if any optimization flags are set
	if !admissionConfig.Enabled && (voipUDPOnly || voipSIPPorts != "" || voipRTPPortRanges != "") {
		// Parse SIP ports
		parsedSIPPorts, err := voip.ParsePorts(voipSIPPorts)
		if err != nil {
			return fmt.Errorf("invalid --sip-port value: %w", err)
		}

		// Parse RTP port ranges
		parsedRTPRanges, err := voip.ParsePortRanges(voipRTPPortRanges)
		if err != nil {
			return fmt.Errorf("invalid --rtp-port-range value: %w", err)
		}

		// Build optimized filter
		builder := voip.NewVoIPFilterBuilder()
		filterConfig := voip.VoIPFilterConfig{
			SIPPorts:      parsedSIPPorts,
			RTPPortRanges: parsedRTPRanges,
			UDPOnly:       voipUDPOnly,
			BaseFilter:    baseBPFFilter,
		}
		effectiveBPFFilter = builder.Build(filterConfig)

		logger.Info("VoIP BPF filter optimization enabled",
			"udp_only", voipUDPOnly,
			"sip_ports", voipSIPPorts,
			"rtp_port_ranges", voipRTPPortRanges,
			"effective_filter", effectiveBPFFilter)
	}

	var admissionOptions admissionintegration.SessionOptions
	if admissionConfig.Enabled {
		ports, err := voip.ParsePorts(voipSIPPorts)
		if err != nil {
			return err
		}
		ranges, err := voip.ParsePortRanges(voipRTPPortRanges)
		if err != nil {
			return err
		}
		policy, err := voip.BuildAdmissionFilter(voip.VoIPFilterConfig{SIPPorts: ports, RTPPortRanges: ranges, UDPOnly: voipUDPOnly, BaseFilter: baseBPFFilter})
		if err != nil {
			return err
		}
		effectiveBPFFilter = policy.Expression
		admissionOptions = admissionintegration.SessionOptions{SIPPorts: policy.SIPPorts, UDPOnly: policy.UDPOnly, ESPEnabled: true}
		for _, r := range policy.RTPPortRanges {
			admissionOptions.RTPPortRanges = append(admissionOptions.RTPPortRanges, admissionintegration.PortRange{Start: r.Start, End: r.End})
		}
	}
	// Get configuration (reuse flags from parent command)
	config, err := buildHunterConfigChecked(protocolHunterConfigSpec("voip", effectiveBPFFilter))
	if err != nil {
		return err
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

	logger.Info("VoIP Hunter configuration",
		"hunter_id", config.HunterID,
		"processor", config.ProcessorAddr,
		"interfaces", config.Interfaces,
		"pattern_algorithm", viper.GetString("voip.pattern_algorithm"),
		"pattern_buffer_mb", viper.GetInt("voip.pattern_buffer_mb"))

	if admissionConfig.Enabled {
		session, err := admissionintegration.NewSession(context.Background(), admissionConfig, admissionOptions)
		if err != nil {
			return fmt.Errorf("initialize hunter RTP admission: %w", err)
		}
		defer func() {
			if err := session.Close(); err != nil {
				logger.Error("Close hunter RTP admission", "error", err)
			}
		}()
		config.MediaAdmission = session
	}
	var bufferMgr *voip.BufferManager
	return runCatalogHunterRuntime(config, "voip", hunterRuntimeHooks{
		setup: func(_ context.Context, _ *hunter.Hunter) (func(), error) {
			if config.MediaAdmission != nil {
				return nil, nil
			}
			bufferMgr = voip.NewBufferManager(5*time.Second, 200)
			logger.Info("VoIP buffer manager initialized", "max_age", "5s", "max_size", 200)
			return bufferMgr.Close, nil
		},
		start: func(ctx context.Context, h *hunter.Hunter) error {
			if config.MediaAdmission != nil {
				return runAdmissionVoIPHunter(ctx, h, config.MediaAdmission, config.Interfaces, streamConfig)
			}
			return runVoIPHunterWithBuffering(ctx, h, bufferMgr, streamConfig)
		},
	})
}

// runVoIPHunterWithBuffering wraps hunter packet processing with VoIP buffering and TCP reassembly
func runVoIPHunterWithBuffering(ctx context.Context, h *hunter.Hunter, bufferMgr *voip.BufferManager, streamConfig voip.Config) error {
	tracker := voip.NewCallTracker()
	defer tracker.Shutdown()
	// Create TCP SIP handler for hunter mode
	// This handler is called when complete SIP messages are reassembled from TCP streams
	tcpHandler := voip.NewHunterForwardHandler(tracker, h, bufferMgr)

	// Create TCP stream factory with hunter handler
	// The factory creates SIPStream instances that parse TCP streams for SIP messages
	streamFactory := voip.NewSipStreamFactoryWithConfig(ctx, tcpHandler, streamConfig, tracker.IsCallActive)

	// Create connection-aware reassembly assembler for TCP reassembly
	// This is the same pattern used in sniff/tap modes (see voip/core.go)
	assembler := pipeline.NewReassemblyEngine(streamFactory, pipeline.DefaultReassemblyConfig())
	defer func() {
		if err := assembler.Close(); err != nil {
			logger.Error("Failed to close TCP reassembly engine", "error", err)
		}
	}()

	// Create VoIP packet processor for UDP buffering
	// This handles UDP SIP/RTP packets with buffering and filtering
	processor := voip.NewVoIPPacketProcessor(tracker, h, bufferMgr)
	defer processor.Close()

	// Wire TCP handler to processor so ApplicationFilter propagates to both
	// This enables proper multi-filter support (phone_number, sip_user, etc.)
	// for both UDP and TCP SIP traffic
	processor.SetTCPHandler(tcpHandler)

	// Wire the TCP assembler to the processor
	// TCP packets will be fed to the assembler for stream reconstruction
	processor.SetAssembler(assembler)

	h.SetPacketProcessor(processor)

	logger.Info("VoIP hunter initialized with full TCP reassembly",
		"tcp_handler", "HunterForwardHandler",
		"tcp_assembler", "reassembly.Assembler",
		"udp_handler", "UDPPacketHandler",
		"buffer_manager", "enabled",
		"features", "TCP SIP reassembly, UDP SIP buffering, UDP RTP buffering")

	// Start background goroutine to periodically flush old TCP streams
	// This prevents memory leaks from incomplete streams and ensures
	// timely processing of SIP messages in slow connections
	go func() {
		if err := assembler.Run(ctx); err != nil {
			logger.Error("TCP reassembly engine stopped", "error", err)
		}
	}()

	// Start the hunter's normal operation
	// The hunter will capture packets and forward them via its existing pipeline:
	// - TCP SIP packets: reassembled by tcpassembly, filtered by HunterForwardHandler
	// - UDP SIP packets: buffered by UDPPacketHandler until filter decision
	// - UDP RTP packets: buffered by UDPPacketHandler, associated with SIP calls
	if err := h.Start(ctx); err != nil {
		return fmt.Errorf("failed to start hunter: %w", err)
	}

	// Block until context is done
	<-ctx.Done()

	return nil
}

func huntSIPStreamConfig(cmd *cobra.Command) (voip.Config, error) {
	config := *voip.GetConfig()
	limit, err := cmdutil.GetIntConfigStrict("voip.max_streams", hunterTCPMaxStreams)
	if cmd.Flags().Changed("tcp-max-streams") {
		limit, err = hunterTCPMaxStreams, nil
	}
	if err != nil {
		return config, err
	}
	if limit < 0 {
		return config, fmt.Errorf("--tcp-max-streams (voip.max_streams) must be non-negative; positive values may reject new TCP SIP streams")
	}
	config.MaxStreams = limit
	return config, nil
}
