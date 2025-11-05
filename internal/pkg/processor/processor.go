// Package processor provides the core processor node implementation for the distributed
// capture system. This file contains the core types, configuration, constructor, and
// basic accessors for the Processor.
//
// File Organization:
//   - processor.go                - Core types, Config, Processor struct, New() constructor
//   - processor_lifecycle.go      - Server lifecycle: Start(), Shutdown(), listener setup
//   - processor_packet_pipeline.go - Packet processing: processBatch(), PCAP coordination
//   - processor_grpc_handlers.go  - gRPC service implementations (21 methods)
//
// The Processor acts as a central aggregation node that:
//   - Accepts connections from multiple hunter nodes
//   - Receives packet streams via gRPC
//   - Performs protocol detection and enrichment
//   - Distributes filters to hunters
//   - Writes packets to PCAP files (unified, per-call, auto-rotating)
//   - Broadcasts packets to TUI subscribers
//   - Forwards packets to upstream processors (hierarchical mode)
package processor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/auth"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/downstream"
	"github.com/endorses/lippycat/internal/pkg/processor/enrichment"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/flow"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/endorses/lippycat/internal/pkg/processor/stats"
	"github.com/endorses/lippycat/internal/pkg/processor/subscriber"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"google.golang.org/grpc"
)

// Config contains processor configuration
type Config struct {
	ListenAddr       string
	ProcessorID      string
	UpstreamAddr     string
	MaxHunters       int
	MaxSubscribers   int // Maximum concurrent TUI/monitoring subscribers (0 = unlimited)
	WriteFile        string
	DisplayStats     bool
	PcapWriterConfig *PcapWriterConfig // Per-call PCAP writing configuration (VoIP)
	AutoRotateConfig *AutoRotateConfig // Auto-rotating PCAP writing configuration (non-VoIP)
	EnableDetection  bool              // Enable centralized protocol detection
	FilterFile       string            // Path to filter persistence file (YAML)
	// TLS settings
	TLSEnabled    bool   // Enable TLS encryption for gRPC server
	TLSCertFile   string // Path to TLS certificate file
	TLSKeyFile    string // Path to TLS key file
	TLSCAFile     string // Path to CA certificate file (for mutual TLS)
	TLSClientAuth bool   // Require client certificate authentication (mutual TLS)
	// API Key Authentication (for non-mTLS deployments)
	AuthConfig *auth.Config // API key authentication configuration (alternative to mTLS)
	// Virtual interface settings
	VirtualInterface      bool   // Enable virtual network interface
	VirtualInterfaceName  string // Virtual interface name
	VirtualInterfaceType  string // Virtual interface type (tap/tun)
	VifBufferSize         int    // Virtual interface buffer size
	VifNetNS              string // Network namespace for interface isolation
	VifDropPrivilegesUser string // User to drop privileges to after interface creation
}

// Processor represents a processor node
type Processor struct {
	config Config

	// Protocol detector (for centralized detection)
	detector *detector.Detector

	// gRPC server
	grpcServer *grpc.Server
	listener   net.Listener

	// Extracted managers
	hunterManager     *hunter.Manager
	hunterMonitor     *hunter.Monitor
	filterManager     *filtering.Manager
	pcapWriter        *pcap.Writer
	flowController    *flow.Controller
	statsCollector    *stats.Collector
	subscriberManager *subscriber.Manager
	upstreamManager   *upstream.Manager
	downstreamManager *downstream.Manager
	enricher          *enrichment.Enricher
	proxyManager      *proxy.Manager // Manages topology subscriptions and operation proxying

	// Packet counters (shared with stats collector and flow controller)
	packetsReceived  atomic.Uint64
	packetsForwarded atomic.Uint64

	// Per-call PCAP writer (separate from main PCAP writer)
	perCallPcapWriter *PcapWriterManager

	// Auto-rotate PCAP writer (for non-VoIP traffic)
	autoRotatePcapWriter *AutoRotatePcapWriter

	// Protocol aggregators
	callAggregator *voip.CallAggregator // VoIP call state aggregation
	callCorrelator *CallCorrelator      // Cross-B2BUA call correlation

	// Virtual interface manager
	vifManager vinterface.Manager

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Embed gRPC service implementations
	data.UnimplementedDataServiceServer
	management.UnimplementedManagementServiceServer
}

// New creates a new processor instance
func New(config Config) (*Processor, error) {
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	p := &Processor{
		config:         config,
		callAggregator: voip.NewCallAggregator(), // Initialize call aggregator
		callCorrelator: NewCallCorrelator(),      // Initialize call correlator
	}

	// Initialize protocol detector and enricher if enabled
	if config.EnableDetection {
		p.detector = detector.InitDefault()
		p.enricher = enrichment.NewEnricher(p.detector)
		logger.Info("Protocol detection enabled on processor")
	}

	// Initialize per-call PCAP writer if configured
	if config.PcapWriterConfig != nil && config.PcapWriterConfig.Enabled {
		writer, err := NewPcapWriterManager(config.PcapWriterConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize per-call PCAP writer: %w", err)
		}
		p.perCallPcapWriter = writer
		logger.Info("Per-call PCAP writing enabled",
			"output_dir", config.PcapWriterConfig.OutputDir,
			"pattern", config.PcapWriterConfig.FilePattern)
	}

	// Initialize auto-rotate PCAP writer if configured
	if config.AutoRotateConfig != nil && config.AutoRotateConfig.Enabled {
		writer, err := NewAutoRotatePcapWriter(config.AutoRotateConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize auto-rotate PCAP writer: %w", err)
		}
		p.autoRotatePcapWriter = writer
		logger.Info("Auto-rotate PCAP writing enabled",
			"output_dir", config.AutoRotateConfig.OutputDir,
			"pattern", config.AutoRotateConfig.FilePattern,
			"max_idle_time", config.AutoRotateConfig.MaxIdleTime,
			"max_file_size", config.AutoRotateConfig.MaxFileSize)
	}

	// Initialize virtual interface if configured
	if config.VirtualInterface {
		ifaceName := config.VirtualInterfaceName
		if ifaceName == "" {
			ifaceName = "lc0"
		}

		cfg := vinterface.DefaultConfig()
		cfg.Name = ifaceName

		// Apply type from config (default: tap)
		if config.VirtualInterfaceType != "" {
			cfg.Type = config.VirtualInterfaceType
		}

		// Apply buffer size from config (default: 4096)
		if config.VifBufferSize > 0 {
			cfg.BufferSize = config.VifBufferSize
		}

		// Apply network namespace from config (default: empty)
		if config.VifNetNS != "" {
			cfg.NetNS = config.VifNetNS
		}

		// Apply privilege dropping user from config (default: empty)
		if config.VifDropPrivilegesUser != "" {
			cfg.DropPrivilegesUser = config.VifDropPrivilegesUser
		}

		mgr, err := vinterface.NewManager(cfg)
		if err != nil {
			// Don't fail processor startup if virtual interface fails
			// Provide helpful error message for common errors
			if errors.Is(err, vinterface.ErrPermissionDenied) {
				logger.Error("Virtual interface requires elevated privileges",
					"error", err,
					"interface_name", ifaceName,
					"solution", "Run with sudo or add CAP_NET_ADMIN capability")
			} else if errors.Is(err, vinterface.ErrInterfaceExists) {
				logger.Error("Virtual interface already exists",
					"error", err,
					"interface_name", ifaceName,
					"solution", "Delete existing interface or choose a different name with --vif-name")
			} else {
				logger.Error("Failed to create virtual interface manager",
					"error", err,
					"interface_name", ifaceName)
			}
			logger.Warn("Continuing without virtual interface")
		} else {
			p.vifManager = mgr
			logger.Info("Virtual interface initialized", "interface", ifaceName)
		}
	}

	// Initialize stats collector (needs to be created first as it's used by other managers)
	p.statsCollector = stats.NewCollector(config.ProcessorID, &p.packetsReceived, &p.packetsForwarded)

	// Set upstream processor address if configured (for hierarchy visualization)
	if config.UpstreamAddr != "" {
		p.statsCollector.SetUpstreamProcessor(config.UpstreamAddr)
	}

	// Create callback for stats updates (called when hunter health changes)
	onStatsChanged := func() {
		total, healthy, warning, errCount, totalFilters := p.hunterManager.GetHealthStats()
		p.statsCollector.UpdateHealthStats(total, healthy, warning, errCount, totalFilters)
	}

	// Initialize hunter manager
	p.hunterManager = hunter.NewManager(config.MaxHunters, onStatsChanged)

	// Initialize hunter monitor (will be started in Start())
	p.hunterMonitor = hunter.NewMonitor(p.hunterManager)

	// Create callbacks for filter manager
	onFilterFailure := func(hunterID string, failed bool) {
		p.hunterManager.UpdateFilterFailure(hunterID, failed)
	}

	// Initialize filter manager
	persistence := filtering.NewYAMLPersistence()
	p.filterManager = filtering.NewManager(config.FilterFile, persistence, p.hunterManager, onFilterFailure, nil)

	// Initialize flow controller
	hasUpstream := config.UpstreamAddr != ""
	p.flowController = flow.NewController(&p.packetsReceived, &p.packetsForwarded, hasUpstream)

	// Initialize subscriber manager
	p.subscriberManager = subscriber.NewManager(config.MaxSubscribers)

	// Initialize upstream manager if configured
	if config.UpstreamAddr != "" {
		p.upstreamManager = upstream.NewManager(
			upstream.Config{
				Address:       config.UpstreamAddr,
				TLSEnabled:    config.TLSEnabled,
				TLSCAFile:     config.TLSCAFile,
				TLSCertFile:   config.TLSCertFile,
				TLSKeyFile:    config.TLSKeyFile,
				ProcessorID:   config.ProcessorID,
				ListenAddress: config.ListenAddr, // Use the listen address so upstream can query back
			},
			&p.packetsForwarded,
		)
	}

	// Initialize downstream manager (always, to track processors forwarding to us)
	p.downstreamManager = downstream.NewManager(
		!config.TLSEnabled, // tlsInsecure = !TLSEnabled
		config.TLSCertFile,
		config.TLSKeyFile,
		config.TLSCAFile,
		false, // tlsSkipVerify
		"",    // tlsServerName
	)

	// Initialize proxy manager for topology subscriptions and operation proxying
	proxyLogger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	p.proxyManager = proxy.NewManager(proxyLogger, config.ProcessorID)

	// Set TLS credentials for token signing if TLS is enabled
	if config.TLSEnabled && config.TLSCertFile != "" && config.TLSKeyFile != "" {
		certPEM, err := os.ReadFile(config.TLSCertFile)
		if err != nil {
			logger.Warn("Failed to read TLS certificate for proxy manager",
				"error", err,
				"cert_file", config.TLSCertFile)
		} else {
			keyPEM, err := os.ReadFile(config.TLSKeyFile)
			if err != nil {
				logger.Warn("Failed to read TLS key for proxy manager",
					"error", err,
					"key_file", config.TLSKeyFile)
			} else {
				p.proxyManager.SetTLSCredentials(certPEM, keyPEM)
				logger.Debug("Proxy manager TLS credentials configured for token signing")
			}
		}
	}

	// Wire up topology event flow: hunter/downstream managers → proxy manager → subscribers
	// This enables real-time topology updates to propagate upstream through the hierarchy
	p.hunterManager.SetTopologyPublisher(p.proxyManager)
	p.downstreamManager.SetTopologyPublisher(p.proxyManager)
	logger.Debug("Topology event flow wired",
		"hunter_manager", "connected",
		"downstream_manager", "connected")

	return p, nil
}

// SetProxyTLSCredentials sets TLS credentials on the proxy manager for authorization token signing.
// This method is primarily used for testing to configure TLS credentials after processor creation.
func (p *Processor) SetProxyTLSCredentials(cert, key []byte) {
	if p.proxyManager != nil {
		p.proxyManager.SetTLSCredentials(cert, key)
	}
}

// GetStats returns current statistics
func (p *Processor) GetStats() stats.Stats {
	return p.statsCollector.Get()
}
