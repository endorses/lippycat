package processor

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/downstream"
	"github.com/endorses/lippycat/internal/pkg/processor/enrichment"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/flow"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/stats"
	"github.com/endorses/lippycat/internal/pkg/processor/subscriber"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
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
	PcapWriterConfig *PcapWriterConfig // Per-call PCAP writing configuration
	EnableDetection  bool              // Enable centralized protocol detection
	FilterFile       string            // Path to filter persistence file (YAML)
	// TLS settings
	TLSEnabled    bool   // Enable TLS encryption for gRPC server
	TLSCertFile   string // Path to TLS certificate file
	TLSKeyFile    string // Path to TLS key file
	TLSCAFile     string // Path to CA certificate file (for mutual TLS)
	TLSClientAuth bool   // Require client certificate authentication (mutual TLS)
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

	// Packet counters (shared with stats collector and flow controller)
	packetsReceived  atomic.Uint64
	packetsForwarded atomic.Uint64

	// Per-call PCAP writer (separate from main PCAP writer)
	perCallPcapWriter *PcapWriterManager

	// Protocol aggregators
	callAggregator *voip.CallAggregator // VoIP call state aggregation
	callCorrelator *CallCorrelator      // Cross-B2BUA call correlation

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

	return p, nil
}

// Start begins processor operation
func (p *Processor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	defer p.cancel()

	logger.Info("Processor starting", "processor_id", p.config.ProcessorID, "listen_addr", p.config.ListenAddr)

	// Load filters from persistence file
	if err := p.filterManager.Load(); err != nil {
		logger.Warn("Failed to load filters from file", "error", err)
		// Continue anyway - not a fatal error
	}

	// Initialize PCAP writer if configured
	if p.config.WriteFile != "" {
		writer, err := pcap.NewWriter(p.config.WriteFile)
		if err != nil {
			return fmt.Errorf("failed to initialize PCAP writer: %w", err)
		}
		p.pcapWriter = writer
		p.pcapWriter.Start(p.ctx)

		// Configure flow controller with PCAP queue metrics
		p.flowController.SetPCAPQueue(p.pcapWriter.QueueDepth, p.pcapWriter.QueueCapacity)

		defer p.pcapWriter.Stop()
	}

	// Create listener with SO_REUSEADDR for fast restarts
	listener, err := createReuseAddrListener("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	p.listener = listener

	// Create gRPC server with TLS if configured
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(constants.MaxGRPCMessageSize),
		// Configure server-side keepalive enforcement
		// Lenient settings to survive network interruptions (laptop standby, etc.)
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second, // Minimum time between client pings
			PermitWithoutStream: true,             // Allow pings without active streams
		}),
		// Configure server keepalive parameters
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second, // Send ping if no activity for 30s
			Timeout: 20 * time.Second, // Wait 20s for ping ack before closing connection
		}),
	}

	// Check for production mode (via environment variable)
	productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"

	if p.config.TLSEnabled {
		tlsCreds, err := p.buildTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(tlsCreds))

		if p.config.TLSClientAuth {
			logger.Info("gRPC server using TLS with mutual authentication (mTLS)",
				"security", "strong authentication via client certificates")
		} else {
			logger.Warn("gRPC server using TLS WITHOUT mutual authentication",
				"security_risk", "hunters can connect without authentication",
				"recommendation", "enable TLSClientAuth for production deployments",
				"impact", "any network client can register as hunter and access packet data")

			if productionMode {
				return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLSClientAuth=true for mutual TLS authentication")
			}
		}
	} else {
		logger.Warn("gRPC server using insecure connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext, no authentication",
			"recommendation", "enable TLS with mutual authentication for production deployments",
			"severity", "CRITICAL")

		if productionMode {
			return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS to be enabled")
		}
	}

	p.grpcServer = grpc.NewServer(serverOpts...)

	// Register services
	data.RegisterDataServiceServer(p.grpcServer, p)
	management.RegisterManagementServiceServer(p.grpcServer, p)

	logger.Info("gRPC server created",
		"addr", listener.Addr().String(),
		"services", []string{"DataService", "ManagementService"},
		"tls", p.config.TLSEnabled)

	// Start server in background
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.grpcServer.Serve(listener); err != nil {
			logger.Error("gRPC server failed", "error", err)
		}
	}()

	// Connect to upstream if configured (hierarchical mode)
	if p.upstreamManager != nil {
		if err := p.upstreamManager.Connect(); err != nil {
			return fmt.Errorf("failed to connect to upstream: %w", err)
		}
		defer p.upstreamManager.Disconnect()
	}

	// Start hunter monitor (heartbeat monitoring and cleanup)
	p.hunterMonitor.Start(p.ctx)

	logger.Info("Processor started", "listen_addr", p.config.ListenAddr)

	// Wait for shutdown
	<-p.ctx.Done()

	// Graceful shutdown
	logger.Info("Shutting down processor")
	p.grpcServer.GracefulStop()

	// Stop hunter monitor
	p.hunterMonitor.Stop()

	p.wg.Wait()

	logger.Info("Processor stopped")
	return nil
}

// Shutdown gracefully shuts down the processor
// This method is primarily used for testing and programmatic shutdown
func (p *Processor) Shutdown() error {
	logger.Info("Shutting down processor")

	if p.cancel != nil {
		p.cancel()
	}

	// Shutdown detector to stop background goroutines
	if p.detector != nil {
		p.detector.Shutdown()
	}

	// Shutdown call correlator to stop cleanup goroutine
	if p.callCorrelator != nil {
		p.callCorrelator.Stop()
	}

	// Close per-call PCAP writer
	if p.perCallPcapWriter != nil {
		if err := p.perCallPcapWriter.Close(); err != nil {
			logger.Warn("Failed to close per-call PCAP writer", "error", err)
		}
	}

	// Give time for graceful shutdown
	if p.grpcServer != nil {
		p.grpcServer.GracefulStop()
	}

	// Wait for all goroutines to complete
	p.wg.Wait()

	logger.Info("Processor shutdown complete")
	return nil
}

// StreamPackets handles packet streaming from hunters (Data Service)
func (p *Processor) StreamPackets(stream data.DataService_StreamPacketsServer) error {
	var hunterID string // Track which hunter this stream belongs to

	defer func() {
		if hunterID != "" {
			logger.Info("Packet stream closed", "hunter_id", hunterID)
		}
	}()

	for {
		batch, err := stream.Recv()
		if err != nil {
			logger.Debug("Stream ended", "error", err, "hunter_id", hunterID)
			return err
		}

		// Track hunter ID from first batch
		if hunterID == "" {
			hunterID = batch.HunterId
			logger.Info("Packet stream started", "hunter_id", hunterID)
		}

		// Process batch
		p.processBatch(batch)

		// Determine flow control state based on processor load
		flowControl := p.flowController.Determine()

		// Send acknowledgment with flow control signal
		ack := &data.StreamControl{
			AckSequence: batch.Sequence,
			FlowControl: flowControl,
		}

		if err := stream.Send(ack); err != nil {
			// Log error but don't close stream - hunter may recover
			// Closing stream would disconnect the hunter unnecessarily
			logger.Warn("Failed to send flow control acknowledgment, continuing",
				"error", err,
				"sequence", batch.Sequence,
				"hunter_id", batch.HunterId)
			// Continue processing - don't return error
		}
	}
}

// processBatch processes a received packet batch
func (p *Processor) processBatch(batch *data.PacketBatch) {
	hunterID := batch.HunterId

	logger.Debug("Received packet batch",
		"hunter_id", hunterID,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	// Update hunter statistics
	p.hunterManager.UpdatePacketStats(hunterID, uint64(len(batch.Packets)), batch.TimestampNs)

	// Queue packets for async PCAP write if configured
	if p.pcapWriter != nil {
		p.pcapWriter.QueuePackets(batch.Packets)
	}

	// Update processor statistics (atomic increment)
	p.packetsReceived.Add(uint64(len(batch.Packets)))

	// Enrich packets with protocol detection if enabled
	if p.enricher != nil {
		p.enricher.Enrich(batch.Packets)
	}

	// Aggregate VoIP call state from packet metadata
	if p.callAggregator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil) {
				p.callAggregator.ProcessPacket(packet, hunterID)
			}
		}
	}

	// Correlate SIP calls across B2BUA boundaries
	if p.callCorrelator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && packet.Metadata.Sip != nil {
				p.callCorrelator.ProcessPacket(packet, hunterID)
			}
		}
	}

	// Write VoIP packets to per-call PCAP files if configured
	// Writes separate SIP and RTP files for each call
	if p.perCallPcapWriter != nil {
		for _, packet := range batch.Packets {
			// Check if packet has SIP metadata with call-id
			if packet.Metadata != nil && packet.Metadata.Sip != nil && packet.Metadata.Sip.CallId != "" {
				callID := packet.Metadata.Sip.CallId
				from := packet.Metadata.Sip.FromUser
				to := packet.Metadata.Sip.ToUser

				// Get or create writer for this call
				writer, err := p.perCallPcapWriter.GetOrCreateWriter(callID, from, to)
				if err != nil {
					logger.Warn("Failed to get/create PCAP writer for call",
						"call_id", callID,
						"error", err)
					continue
				}

				// Write packet to appropriate file (SIP or RTP) using raw packet data
				if len(packet.Data) > 0 {
					timestamp := time.Unix(0, packet.TimestampNs)

					// Check if this is an RTP packet (has RTP metadata)
					if packet.Metadata.Rtp != nil {
						// Write to RTP PCAP file
						if err := writer.WriteRTPPacket(timestamp, packet.Data); err != nil {
							logger.Warn("Failed to write RTP packet to call PCAP",
								"call_id", callID,
								"error", err)
						}
					} else {
						// Write to SIP PCAP file
						if err := writer.WriteSIPPacket(timestamp, packet.Data); err != nil {
							logger.Warn("Failed to write SIP packet to call PCAP",
								"call_id", callID,
								"error", err)
						}
					}
				}
			}
		}
	}

	// Forward to upstream in hierarchical mode
	if p.upstreamManager != nil {
		p.upstreamManager.Forward(batch)
	}

	// Broadcast to monitoring subscribers (TUI clients)
	p.subscriberManager.Broadcast(batch)
}

// RegisterHunter registers a hunter node with the processor (Management Service).
//
// SECURITY NOTE: Hunter authentication relies on the gRPC server's TLS configuration.
//   - When TLSClientAuth=true (mutual TLS): Hunters must present valid client certificates.
//     This provides strong authentication and is REQUIRED for production deployments.
//   - When TLSClientAuth=false: Any network client can register as a hunter with any ID.
//     This is INSECURE - malicious clients can impersonate legitimate hunters.
//   - When TLSEnabled=false: All traffic is unencrypted and unauthenticated (CRITICAL risk).
//
// For production deployments, set LIPPYCAT_PRODUCTION=true to enforce mutual TLS.
func (p *Processor) RegisterHunter(ctx context.Context, req *management.HunterRegistration) (*management.RegistrationResponse, error) {
	hunterID := req.HunterId

	logger.Info("Hunter registration request",
		"hunter_id", hunterID,
		"hostname", req.Hostname,
		"interfaces", req.Interfaces,
		"capabilities", req.Capabilities)

	// Register hunter with manager
	_, isReconnect, err := p.hunterManager.Register(hunterID, req.Hostname, req.Interfaces, req.Capabilities)
	if err != nil {
		if err == hunter.ErrMaxHuntersReached {
			logger.Warn("Max hunters limit reached", "limit", p.config.MaxHunters)
			return nil, status.Errorf(codes.ResourceExhausted,
				"maximum number of hunters reached: limit %d", p.config.MaxHunters)
		}
		return nil, status.Errorf(codes.Internal, "failed to register hunter: %v", err)
	}

	logger.Info("Hunter registered successfully", "hunter_id", hunterID, "reconnect", isReconnect)

	// Get applicable filters for this hunter
	filters := p.filterManager.GetForHunter(hunterID)

	return &management.RegistrationResponse{
		Accepted:   true,
		AssignedId: hunterID,
		Filters:    filters,
		Config: &management.ProcessorConfig{
			BatchSize:            64,
			BatchTimeoutMs:       100,
			ReconnectIntervalSec: 5,
			MaxReconnectAttempts: 0, // infinite
			ProcessorId:          p.config.ProcessorID,
		},
	}, nil
}

// Heartbeat handles bidirectional heartbeat stream (Management Service)
func (p *Processor) Heartbeat(stream management.ManagementService_HeartbeatServer) error {
	logger.Debug("New heartbeat stream")

	for {
		hb, err := stream.Recv()
		if err != nil {
			logger.Debug("Heartbeat stream ended", "error", err)
			return err
		}

		hunterID := hb.HunterId

		// Update hunter status and stats
		statsChanged := p.hunterManager.UpdateHeartbeat(hunterID, hb.TimestampNs, hb.Status, hb.Stats)

		// Log heartbeat with stats (DEBUG level for normal operation, WARN if missing)
		if hb.Stats != nil {
			logger.Debug("Heartbeat received with stats",
				"hunter_id", hunterID,
				"active_filters", hb.Stats.ActiveFilters,
				"packets_captured", hb.Stats.PacketsCaptured,
				"packets_forwarded", hb.Stats.PacketsForwarded,
				"stats_changed", statsChanged)
		} else {
			logger.Warn("Heartbeat received WITHOUT stats (proto3 issue?)",
				"hunter_id", hunterID,
				"timestamp_ns", hb.TimestampNs,
				"status", hb.Status)
		}

		// Send response
		processorStats := p.statsCollector.GetProto()
		resp := &management.ProcessorHeartbeat{
			TimestampNs:      hb.TimestampNs,
			Status:           management.ProcessorStatus_PROCESSOR_HEALTHY,
			HuntersConnected: processorStats.TotalHunters,
			ProcessorId:      p.config.ProcessorID,
		}

		if err := stream.Send(resp); err != nil {
			logger.Error("Failed to send heartbeat response", "error", err)
			return err
		}
	}
}

// GetFilters retrieves filters for a hunter (Management Service)
func (p *Processor) GetFilters(ctx context.Context, req *management.FilterRequest) (*management.FilterResponse, error) {
	filters := p.filterManager.GetForHunter(req.HunterId)

	return &management.FilterResponse{
		Filters: filters,
	}, nil
}

// SubscribeFilters streams filter updates to hunters (Management Service)
func (p *Processor) SubscribeFilters(req *management.FilterRequest, stream management.ManagementService_SubscribeFiltersServer) error {
	hunterID := req.HunterId
	logger.Debug("SubscribeFilters called", "hunter_id", hunterID, "stream_context", stream.Context().Err())
	logger.Info("Filter subscription started", "hunter_id", hunterID)

	// Create filter update channel for this hunter
	filterChan := p.filterManager.AddChannel(hunterID)

	// Cleanup on disconnect
	defer func() {
		p.filterManager.RemoveChannel(hunterID)
		logger.Debug("SubscribeFilters exiting", "hunter_id", hunterID, "stream_context", stream.Context().Err())
		logger.Info("Filter subscription ended", "hunter_id", hunterID)
	}()

	// Send current filters immediately
	currentFilters := p.filterManager.GetForHunter(hunterID)
	for _, filter := range currentFilters {
		update := &management.FilterUpdate{
			UpdateType: management.FilterUpdateType_UPDATE_ADD,
			Filter:     filter,
		}
		if err := stream.Send(update); err != nil {
			logger.Error("Failed to send initial filter", "error", err, "filter_id", filter.Id)
			return err
		}
	}

	logger.Info("Sent initial filters", "hunter_id", hunterID, "count", len(currentFilters))

	// Stream filter updates
	for {
		select {
		case <-stream.Context().Done():
			logger.Debug("SubscribeFilters: stream context cancelled", "hunter_id", hunterID, "error", stream.Context().Err())
			return nil
		case update, ok := <-filterChan:
			if !ok {
				logger.Debug("SubscribeFilters: filter channel closed", "hunter_id", hunterID)
				return nil
			}

			logger.Debug("Sending filter update",
				"hunter_id", hunterID,
				"update_type", update.UpdateType,
				"filter_id", update.Filter.Id)

			if err := stream.Send(update); err != nil {
				logger.Error("Failed to send filter update", "hunter_id", hunterID, "error", err)
				return err
			}
			logger.Debug("Filter update sent successfully", "hunter_id", hunterID, "update_type", update.UpdateType)
		}
	}
}

// GetHunterStatus retrieves status of connected hunters (Management Service)
func (p *Processor) GetHunterStatus(ctx context.Context, req *management.StatusRequest) (*management.StatusResponse, error) {
	hunters := p.hunterManager.GetAll(req.HunterId)

	connectedHunters := make([]*management.ConnectedHunter, 0, len(hunters))
	for _, h := range hunters {
		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		connectedHunters = append(connectedHunters, &management.ConnectedHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			RemoteAddr:           h.RemoteAddr,
			Status:               h.Status,
			ConnectedDurationSec: durationSec,
			LastHeartbeatNs:      h.LastHeartbeat,
			Stats: &management.HunterStats{
				PacketsCaptured:  h.PacketsCaptured,  // From hunter's heartbeat stats
				PacketsForwarded: h.PacketsForwarded, // From hunter's heartbeat stats
				ActiveFilters:    h.ActiveFilters,
			},
			Interfaces:   h.Interfaces,
			Capabilities: h.Capabilities, // Hunter capabilities (filter types, etc.)
		})
	}

	processorStats := p.statsCollector.GetProto()

	return &management.StatusResponse{
		Hunters:        connectedHunters,
		ProcessorStats: processorStats,
	}, nil
}

// ListAvailableHunters returns list of all hunters connected to this processor (for TUI hunter selection)
func (p *Processor) ListAvailableHunters(ctx context.Context, req *management.ListHuntersRequest) (*management.ListHuntersResponse, error) {
	hunters := p.hunterManager.GetAll("")

	availableHunters := make([]*management.AvailableHunter, 0, len(hunters))
	for _, h := range hunters {
		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		availableHunters = append(availableHunters, &management.AvailableHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			Interfaces:           h.Interfaces,
			Status:               h.Status,
			RemoteAddr:           h.RemoteAddr,
			ConnectedDurationSec: durationSec,
			Capabilities:         h.Capabilities, // Hunter capabilities (filter types, etc.)
		})
	}

	logger.Debug("ListAvailableHunters request", "hunter_count", len(availableHunters))

	return &management.ListHuntersResponse{
		Hunters: availableHunters,
	}, nil
}

// RegisterProcessor registers a downstream processor that forwards packets to this processor
func (p *Processor) RegisterProcessor(ctx context.Context, req *management.ProcessorRegistration) (*management.ProcessorRegistrationResponse, error) {
	logger.Info("Downstream processor registration",
		"processor_id", req.ProcessorId,
		"listen_address", req.ListenAddress,
		"version", req.Version)

	err := p.downstreamManager.Register(req.ProcessorId, req.ListenAddress, req.Version)
	if err != nil {
		return &management.ProcessorRegistrationResponse{
			Accepted: false,
			Error:    err.Error(),
		}, nil
	}

	return &management.ProcessorRegistrationResponse{
		Accepted: true,
	}, nil
}

// GetTopology returns the complete downstream topology (processors and hunters)
func (p *Processor) GetTopology(ctx context.Context, req *management.TopologyRequest) (*management.TopologyResponse, error) {
	logger.Debug("GetTopology request")

	// Get hunters for this processor
	hunters := p.hunterManager.GetAll("")
	connectedHunters := make([]*management.ConnectedHunter, 0, len(hunters))
	for _, h := range hunters {
		durationNs := time.Now().UnixNano() - h.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		connectedHunters = append(connectedHunters, &management.ConnectedHunter{
			HunterId:             h.ID,
			Hostname:             h.Hostname,
			RemoteAddr:           h.RemoteAddr,
			Status:               h.Status,
			ConnectedDurationSec: durationSec,
			LastHeartbeatNs:      h.LastHeartbeat,
			Stats: &management.HunterStats{
				PacketsCaptured:  h.PacketsCaptured,
				PacketsForwarded: h.PacketsForwarded,
				ActiveFilters:    h.ActiveFilters,
			},
			Interfaces:   h.Interfaces,
			Capabilities: h.Capabilities,
		})
	}

	// Get processor stats
	processorStats := p.statsCollector.GetProto()

	// Recursively query downstream processors
	node, err := p.downstreamManager.GetTopology(
		ctx,
		p.config.ProcessorID,
		processorStats.Status,
		p.config.UpstreamAddr,
		connectedHunters,
	)
	if err != nil {
		return nil, err
	}

	return &management.TopologyResponse{
		Processor: node,
	}, nil
}

// UpdateFilter adds or modifies a filter (Management Service)
func (p *Processor) UpdateFilter(ctx context.Context, filter *management.Filter) (*management.FilterUpdateResult, error) {
	logger.Info("Update filter request", "filter_id", filter.Id, "type", filter.Type, "pattern", filter.Pattern)

	huntersUpdated, err := p.filterManager.Update(filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update filter: %v", err)
	}

	logger.Info("Filter updated",
		"filter_id", filter.Id,
		"hunters_updated", huntersUpdated)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// DeleteFilter removes a filter (Management Service)
func (p *Processor) DeleteFilter(ctx context.Context, req *management.FilterDeleteRequest) (*management.FilterUpdateResult, error) {
	logger.Info("Delete filter request", "filter_id", req.FilterId)

	huntersUpdated, err := p.filterManager.Delete(req.FilterId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "filter not found: %s", req.FilterId)
	}

	logger.Info("Filter deleted",
		"filter_id", req.FilterId,
		"hunters_updated", huntersUpdated)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// GetStats returns current statistics
func (p *Processor) GetStats() stats.Stats {
	return p.statsCollector.Get()
}

// buildTLSCredentials creates TLS credentials for gRPC server
func (p *Processor) buildTLSCredentials() (credentials.TransportCredentials, error) {
	return tlsutil.BuildServerCredentials(tlsutil.ServerConfig{
		CertFile:   p.config.TLSCertFile,
		KeyFile:    p.config.TLSKeyFile,
		CAFile:     p.config.TLSCAFile,
		ClientAuth: p.config.TLSClientAuth,
	})
}

// SubscribePackets allows TUI/monitoring clients to subscribe to packet streams.
//
// SECURITY NOTE: Subscriber authentication relies on the gRPC server's TLS configuration.
//   - When TLSClientAuth=true (mutual TLS): Subscribers must present valid client certificates.
//     This provides strong authentication and is REQUIRED for production deployments.
//   - When TLSClientAuth=false: Any network client can subscribe and view packet data.
//     This is INSECURE and should only be used in trusted development environments.
//   - When TLSEnabled=false: All traffic is unencrypted and unauthenticated (CRITICAL risk).
//
// For production deployments, set LIPPYCAT_PRODUCTION=true to enforce mutual TLS.
func (p *Processor) SubscribePackets(req *data.SubscribeRequest, stream data.DataService_SubscribePacketsServer) error {
	clientID := req.ClientId
	if clientID == "" {
		nextID := p.subscriberManager.NextID()
		clientID = fmt.Sprintf("subscriber-%d", nextID)
	}

	// Check subscriber limit to prevent DoS
	if p.subscriberManager.CheckLimit() {
		count := p.subscriberManager.Count()
		logger.Warn("Subscriber limit reached, rejecting new subscriber",
			"client_id", clientID,
			"current_subscribers", count,
			"max_subscribers", p.config.MaxSubscribers)
		return status.Errorf(codes.ResourceExhausted,
			"maximum number of subscribers (%d) reached", p.config.MaxSubscribers)
	}

	// Store hunter subscription filter for this client
	// has_hunter_filter = false: subscribe to all hunters (default/backward compatibility)
	// has_hunter_filter = true + empty list: subscribe to no hunters (explicit opt-out)
	// has_hunter_filter = true + non-empty list: subscribe to specified hunters only
	if req.HasHunterFilter {
		p.subscriberManager.SetFilter(clientID, req.HunterIds)
		if len(req.HunterIds) > 0 {
			logger.Info("New packet subscriber with hunter filter",
				"client_id", clientID,
				"subscribed_hunters", req.HunterIds)
		} else {
			logger.Info("New packet subscriber (no hunters - empty filter)",
				"client_id", clientID)
		}
	} else {
		logger.Info("New packet subscriber (all hunters - no filter)", "client_id", clientID)
	}

	// Create channel for this subscriber
	subChan := p.subscriberManager.Add(clientID)

	// Cleanup on disconnect
	defer func() {
		p.subscriberManager.Remove(clientID)
		logger.Info("Packet subscriber disconnected", "client_id", clientID)
	}()

	// Stream packets to client
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case batch, ok := <-subChan:
			if !ok {
				return nil
			}

			// Apply BPF filter if specified
			if req.BpfFilter != "" {
				// TODO: Implement server-side BPF filtering
				// For now, send all packets
			}

			// Filter by hunter IDs if filter is explicitly set
			// has_hunter_filter = false: send all packets (no filter)
			// has_hunter_filter = true + empty list: send no packets (explicit opt-out)
			// has_hunter_filter = true + non-empty list: send only matching packets
			if req.HasHunterFilter {
				if len(req.HunterIds) == 0 {
					// Empty filter = subscribe to no hunters, don't send this packet
					continue
				}

				// Non-empty filter = check if this hunter matches
				found := false
				for _, hunterID := range req.HunterIds {
					if batch.HunterId == hunterID {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			if err := stream.Send(batch); err != nil {
				logger.Error("Failed to send batch to subscriber", "error", err, "client_id", clientID)
				return err
			}
		}
	}
}

// SubscribeCorrelatedCalls streams correlated call updates to monitoring clients (Data Service)
func (p *Processor) SubscribeCorrelatedCalls(req *data.SubscribeRequest, stream data.DataService_SubscribeCorrelatedCallsServer) error {
	clientID := req.ClientId
	if clientID == "" {
		clientID = fmt.Sprintf("correlation-subscriber-%d", time.Now().UnixNano())
	}

	logger.Info("New correlated calls subscriber", "client_id", clientID)

	// Create a ticker to send periodic updates
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Send initial snapshot of all correlated calls
	calls := p.callCorrelator.GetCorrelatedCalls()
	for _, call := range calls {
		update := correlatedCallToProto(call)
		if err := stream.Send(update); err != nil {
			logger.Error("Failed to send initial correlated call", "client_id", clientID, "error", err)
			return err
		}
	}

	logger.Info("Sent initial correlated calls", "client_id", clientID, "count", len(calls))

	// Stream periodic updates
	for {
		select {
		case <-stream.Context().Done():
			logger.Debug("SubscribeCorrelatedCalls: stream context cancelled", "client_id", clientID)
			return nil
		case <-ticker.C:
			// Send updated state for all active calls
			calls := p.callCorrelator.GetCorrelatedCalls()
			for _, call := range calls {
				update := correlatedCallToProto(call)
				if err := stream.Send(update); err != nil {
					logger.Error("Failed to send correlated call update", "client_id", clientID, "error", err)
					return err
				}
			}
		}
	}
}

// correlatedCallToProto converts a CorrelatedCall to protobuf CorrelatedCallUpdate
func correlatedCallToProto(call *CorrelatedCall) *data.CorrelatedCallUpdate {
	// Convert call legs to protobuf
	legs := make([]*data.CallLegInfo, 0, len(call.CallLegs))
	for _, leg := range call.CallLegs {
		legInfo := &data.CallLegInfo{
			CallId:       leg.CallID,
			HunterId:     leg.HunterID,
			SrcIp:        leg.SrcIP,
			DstIp:        leg.DstIP,
			Method:       leg.Method,
			ResponseCode: leg.ResponseCode,
			PacketCount:  int32(leg.PacketCount),
			StartTimeNs:  leg.StartTime.UnixNano(),
			LastSeenNs:   leg.LastSeen.UnixNano(),
		}
		legs = append(legs, legInfo)
	}

	return &data.CorrelatedCallUpdate{
		CorrelationId: call.CorrelationID,
		TagPair:       call.TagPair[:],
		FromUser:      call.FromUser,
		ToUser:        call.ToUser,
		Legs:          legs,
		StartTimeNs:   call.StartTime.UnixNano(),
		LastSeenNs:    call.LastSeen.UnixNano(),
		State:         call.State.String(),
	}
}

// createReuseAddrListener creates a TCP listener with SO_REUSEADDR enabled
// for fast restarts without waiting for TIME_WAIT
func createReuseAddrListener(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockOptErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow immediate rebind after restart
				sockOptErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return sockOptErr
		},
	}
	return lc.Listen(context.Background(), network, address)
}
