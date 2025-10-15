package processor

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/flow"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
	"github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/stats"
	"github.com/endorses/lippycat/internal/pkg/processor/subscriber"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

	// Packet counters (shared with stats collector and flow controller)
	packetsReceived  atomic.Uint64
	packetsForwarded atomic.Uint64

	// Per-call PCAP writer (separate from main PCAP writer)
	perCallPcapWriter *PcapWriterManager

	// Upstream connection (hierarchical mode)
	upstreamConn   *grpc.ClientConn
	upstreamClient data.DataServiceClient
	upstreamStream data.DataService_StreamPacketsClient
	upstreamMu     sync.Mutex

	// Protocol aggregators
	callAggregator *CallAggregator // VoIP call state aggregation

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
		callAggregator: NewCallAggregator(), // Initialize call aggregator
	}

	// Initialize protocol detector if enabled
	if config.EnableDetection {
		p.detector = detector.InitDefault()
		logger.Info("Protocol detection enabled on processor")
	}

	// Initialize stats collector (needs to be created first as it's used by other managers)
	p.statsCollector = stats.NewCollector(config.ProcessorID, &p.packetsReceived, &p.packetsForwarded)

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
	p.filterManager = filtering.NewManager(config.FilterFile, persistence, onFilterFailure, nil)

	// Initialize flow controller
	hasUpstream := config.UpstreamAddr != ""
	p.flowController = flow.NewController(&p.packetsReceived, &p.packetsForwarded, hasUpstream)

	// Initialize subscriber manager
	p.subscriberManager = subscriber.NewManager(config.MaxSubscribers)

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

	// Create listener
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	p.listener = listener

	// Create gRPC server with TLS if configured
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(constants.MaxGRPCMessageSize),
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
	if p.config.UpstreamAddr != "" {
		if err := p.connectToUpstream(); err != nil {
			return fmt.Errorf("failed to connect to upstream: %w", err)
		}
		defer p.disconnectUpstream()
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
	logger.Info("New packet stream connection")

	for {
		batch, err := stream.Recv()
		if err != nil {
			logger.Debug("Stream ended", "error", err)
			return err
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
			logger.Error("Failed to send acknowledgment", "error", err)
			return err
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
	if p.config.EnableDetection && p.detector != nil {
		p.enrichPackets(batch.Packets)
	}

	// Aggregate VoIP call state from packet metadata
	if p.callAggregator != nil {
		for _, packet := range batch.Packets {
			if packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil) {
				p.callAggregator.ProcessPacket(packet, hunterID)
			}
		}
	}

	// Forward to upstream in hierarchical mode
	if p.upstreamStream != nil {
		p.forwardToUpstream(batch)
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
		"interfaces", req.Interfaces)

	// Register hunter with manager
	_, isReconnect, err := p.hunterManager.Register(hunterID, req.Hostname, req.Interfaces)
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

		// Log heartbeat with stats (INFO level for debugging)
		if hb.Stats != nil {
			logger.Info("Heartbeat received with stats",
				"hunter_id", hunterID,
				"active_filters", hb.Stats.ActiveFilters,
				"stats_changed", statsChanged)
		} else {
			logger.Warn("Heartbeat received WITHOUT stats",
				"hunter_id", hunterID)
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
	logger.Info("Filter subscription started", "hunter_id", hunterID)

	// Create filter update channel for this hunter
	filterChan := p.filterManager.AddChannel(hunterID)

	// Cleanup on disconnect
	defer func() {
		p.filterManager.RemoveChannel(hunterID)
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
			return nil
		case update, ok := <-filterChan:
			if !ok {
				return nil
			}

			logger.Debug("Sending filter update",
				"hunter_id", hunterID,
				"update_type", update.UpdateType,
				"filter_id", update.Filter.Id)

			if err := stream.Send(update); err != nil {
				logger.Error("Failed to send filter update", "error", err)
				return err
			}
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
				PacketsCaptured:  h.PacketsReceived,
				PacketsForwarded: h.PacketsReceived,
				ActiveFilters:    h.ActiveFilters,
			},
			Interfaces: h.Interfaces,
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
		})
	}

	logger.Debug("ListAvailableHunters request", "hunter_count", len(availableHunters))

	return &management.ListHuntersResponse{
		Hunters: availableHunters,
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

// buildClientTLSCredentials creates TLS credentials for gRPC client (upstream connection)
func (p *Processor) buildClientTLSCredentials() (credentials.TransportCredentials, error) {
	return tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile:   p.config.TLSCAFile,
		CertFile: p.config.TLSCertFile,
		KeyFile:  p.config.TLSKeyFile,
	})
}

// connectToUpstream establishes connection to upstream processor
func (p *Processor) connectToUpstream() error {
	logger.Info("Connecting to upstream processor", "addr", p.config.UpstreamAddr)

	// Create gRPC connection with TLS if enabled
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(constants.MaxGRPCMessageSize)),
	}

	if p.config.TLSEnabled {
		tlsCreds, err := p.buildClientTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials for upstream: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
		logger.Info("Using TLS for upstream connection")
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Warn("Using insecure upstream connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext")
	}

	conn, err := grpc.Dial(p.config.UpstreamAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial upstream: %w", err)
	}

	p.upstreamConn = conn
	p.upstreamClient = data.NewDataServiceClient(conn)

	// Create streaming connection
	stream, err := p.upstreamClient.StreamPackets(p.ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to create upstream stream: %w", err)
	}

	p.upstreamMu.Lock()
	p.upstreamStream = stream
	p.upstreamMu.Unlock()

	// Start goroutine to receive upstream acks
	p.wg.Add(1)
	go p.receiveUpstreamAcks()

	logger.Info("Connected to upstream processor", "addr", p.config.UpstreamAddr)
	return nil
}

// disconnectUpstream closes upstream connection
func (p *Processor) disconnectUpstream() {
	p.upstreamMu.Lock()
	if p.upstreamStream != nil {
		_ = p.upstreamStream.CloseSend()
		p.upstreamStream = nil
	}
	p.upstreamMu.Unlock()

	if p.upstreamConn != nil {
		_ = p.upstreamConn.Close()
		p.upstreamConn = nil
	}

	logger.Info("Disconnected from upstream processor")
}

// forwardToUpstream forwards packet batch to upstream processor
func (p *Processor) forwardToUpstream(batch *data.PacketBatch) {
	p.upstreamMu.Lock()
	stream := p.upstreamStream
	p.upstreamMu.Unlock()

	if stream == nil {
		logger.Warn("Upstream stream not available, dropping batch")
		return
	}

	// Forward batch (keeping original hunter ID for traceability)
	if err := stream.Send(batch); err != nil {
		logger.Error("Failed to forward batch to upstream", "error", err)
		return
	}

	// Update forwarded stats (atomic increment)
	p.packetsForwarded.Add(uint64(len(batch.Packets)))

	logger.Debug("Forwarded batch to upstream",
		"hunter_id", batch.HunterId,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))
}

// receiveUpstreamAcks receives acknowledgments from upstream
func (p *Processor) receiveUpstreamAcks() {
	defer p.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in receiveUpstreamAcks", "panic", r)
		}
	}()

	p.upstreamMu.Lock()
	stream := p.upstreamStream
	p.upstreamMu.Unlock()

	if stream == nil {
		logger.Error("Upstream stream not available for receiving acks")
		return
	}

	for {
		// Check context before each Recv to avoid blocking on closed stream
		select {
		case <-p.ctx.Done():
			logger.Debug("receiveUpstreamAcks: context cancelled, exiting")
			return
		default:
		}

		ack, err := stream.Recv()
		if err != nil {
			// Check if we're shutting down
			if p.ctx.Err() != nil {
				logger.Debug("receiveUpstreamAcks: error during shutdown, exiting gracefully", "error", err)
				return
			}
			logger.Error("Upstream ack receive error", "error", err)
			return
		}

		logger.Debug("Received upstream ack",
			"ack_sequence", ack.AckSequence,
			"flow_control", ack.FlowControl)

		// TODO: Implement flow control from upstream (pause forwarding if FLOW_PAUSE)
	}
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

// enrichPackets performs centralized protocol detection and enriches packet metadata
func (p *Processor) enrichPackets(packets []*data.CapturedPacket) {
	for _, pkt := range packets {
		// Decode packet from raw bytes (safe: link type is small enum from proto, values < 300)
		goPacket := gopacket.NewPacket(pkt.Data, layers.LinkType(pkt.LinkType), gopacket.Default) // #nosec G115

		// Run centralized detection
		result := p.detector.Detect(goPacket)

		if result != nil && result.Protocol != "unknown" {
			// Initialize metadata if not exists
			if pkt.Metadata == nil {
				pkt.Metadata = &data.PacketMetadata{}
			}

			// Populate protocol
			pkt.Metadata.Protocol = result.Protocol

			// Build info string for display (same logic as TUI bridge)
			pkt.Metadata.Info = buildInfoString(result.Protocol, result.Metadata)

			// Extract network layer info
			if netLayer := goPacket.NetworkLayer(); netLayer != nil {
				switch net := netLayer.(type) {
				case *layers.IPv4:
					pkt.Metadata.SrcIp = net.SrcIP.String()
					pkt.Metadata.DstIp = net.DstIP.String()
				case *layers.IPv6:
					pkt.Metadata.SrcIp = net.SrcIP.String()
					pkt.Metadata.DstIp = net.DstIP.String()
				}
			}

			// Extract transport layer info
			if transLayer := goPacket.TransportLayer(); transLayer != nil {
				switch trans := transLayer.(type) {
				case *layers.TCP:
					pkt.Metadata.Transport = "TCP"
					pkt.Metadata.SrcPort = uint32(trans.SrcPort)
					pkt.Metadata.DstPort = uint32(trans.DstPort)
				case *layers.UDP:
					pkt.Metadata.Transport = "UDP"
					pkt.Metadata.SrcPort = uint32(trans.SrcPort)
					pkt.Metadata.DstPort = uint32(trans.DstPort)
				}
			}

			// Populate protocol-specific metadata
			switch result.Protocol {
			case "SIP":
				if pkt.Metadata.Sip == nil {
					pkt.Metadata.Sip = &data.SIPMetadata{}
				}
				if method, ok := result.Metadata["method"].(string); ok {
					pkt.Metadata.Sip.Method = method
				}
				if fromUser, ok := result.Metadata["from_user"].(string); ok {
					pkt.Metadata.Sip.FromUser = fromUser
				}
				if toUser, ok := result.Metadata["to_user"].(string); ok {
					pkt.Metadata.Sip.ToUser = toUser
				}
				if callID, ok := result.Metadata["call_id"].(string); ok {
					pkt.Metadata.Sip.CallId = callID
				}
				if respCode, ok := result.Metadata["response_code"].(uint32); ok {
					pkt.Metadata.Sip.ResponseCode = respCode
				}

			case "RTP":
				if pkt.Metadata.Rtp == nil {
					pkt.Metadata.Rtp = &data.RTPMetadata{}
				}
				if ssrc, ok := result.Metadata["ssrc"].(uint32); ok {
					pkt.Metadata.Rtp.Ssrc = ssrc
				}
				if seqNum, ok := result.Metadata["sequence_number"].(uint16); ok {
					pkt.Metadata.Rtp.Sequence = uint32(seqNum)
				}
				if payloadType, ok := result.Metadata["payload_type"].(uint8); ok {
					pkt.Metadata.Rtp.PayloadType = uint32(payloadType)
				}
				if timestamp, ok := result.Metadata["timestamp"].(uint32); ok {
					pkt.Metadata.Rtp.Timestamp = timestamp
				}
			}
		}
	}
}

// buildInfoString creates display info string from detection metadata
func buildInfoString(protocol string, metadata map[string]interface{}) string {
	switch protocol {
	case "SSH":
		if versionStr, ok := metadata["version_string"].(string); ok {
			return versionStr
		}
		return "SSH"

	case "ICMP":
		if typeName, ok := metadata["type_name"].(string); ok {
			info := typeName
			if codeName, ok := metadata["code_name"].(string); ok && codeName != "" {
				info += " - " + codeName
			}
			return info
		}
		return "ICMP"

	case "DNS":
		return "DNS Query/Response"

	case "gRPC", "HTTP2":
		return "gRPC/HTTP2"

	case "DHCP", "BOOTP":
		if msgType, ok := metadata["message_type"].(string); ok {
			return msgType
		}
		return protocol

	case "NTP":
		if mode, ok := metadata["mode"].(string); ok {
			return "NTP " + mode
		}
		return "NTP"

	case "ARP":
		if op, ok := metadata["operation"].(string); ok {
			return op
		}
		return "ARP"

	case "OpenVPN":
		if typeName, ok := metadata["type_name"].(string); ok {
			return typeName
		}
		return "OpenVPN"

	case "WireGuard":
		if typeName, ok := metadata["type_name"].(string); ok {
			return typeName
		}
		return "WireGuard"

	case "L2TP":
		if packetType, ok := metadata["packet_type"].(string); ok {
			return packetType
		}
		return "L2TP"

	case "PPTP":
		if ctrlType, ok := metadata["control_type_name"].(string); ok {
			return ctrlType
		}
		return "PPTP"

	case "IKEv2", "IKEv1", "IKE":
		if exchangeName, ok := metadata["exchange_name"].(string); ok {
			if isResp, ok := metadata["is_response"].(bool); ok {
				if isResp {
					return exchangeName + " (response)"
				}
				return exchangeName + " (request)"
			}
			return exchangeName
		}
		return protocol

	default:
		return protocol
	}
}
