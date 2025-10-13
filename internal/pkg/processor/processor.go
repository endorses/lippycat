package processor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

	// Connected hunters
	huntersMu sync.RWMutex
	hunters   map[string]*ConnectedHunter

	// PCAP writer (async with single writer goroutine)
	pcapFile            *os.File
	pcapWriter          *pcapgo.Writer
	pcapWriteQueue      chan []*data.CapturedPacket
	pcapWriterWg        sync.WaitGroup
	perCallPcapWriter   *PcapWriterManager // Per-call PCAP writer
	pcapWriteErrors     atomic.Uint64      // Track total write errors
	pcapConsecErrors    atomic.Uint64      // Track consecutive write errors
	pcapLastErrorLogged atomic.Int64       // Timestamp of last error log

	// Statistics - use atomic.Value for lock-free reads
	statsCache       atomic.Value  // stores *cachedStats
	statsUpdates     atomic.Uint64 // incremented on every stats change
	packetsReceived  atomic.Uint64 // incremental counter
	packetsForwarded atomic.Uint64 // incremental counter

	// Subscriber backpressure tracking
	subscriberBroadcasts atomic.Uint64 // total broadcast attempts
	subscriberDrops      atomic.Uint64 // drops due to full channels

	// Filters
	filtersMu      sync.RWMutex
	filters        map[string]*management.Filter
	filterChannels map[string]chan *management.FilterUpdate // hunterID -> channel

	// Upstream connection (hierarchical mode)
	upstreamConn   *grpc.ClientConn
	upstreamClient data.DataServiceClient
	upstreamStream data.DataService_StreamPacketsClient
	upstreamMu     sync.Mutex

	// Monitoring subscribers (TUI clients) - uses sync.Map for efficient concurrent access
	subscribers      sync.Map // map[string]chan *data.PacketBatch
	subscriberFilter sync.Map // map[string][]string (clientID -> hunterIDs subscription list)
	nextSubID        atomic.Uint64

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Embed gRPC service implementations
	data.UnimplementedDataServiceServer
	management.UnimplementedManagementServiceServer
}

// ConnectedHunter represents a connected hunter node
type ConnectedHunter struct {
	ID                      string
	Hostname                string
	RemoteAddr              string
	Interfaces              []string
	ConnectedAt             int64
	LastHeartbeat           int64
	PacketsReceived         uint64
	ActiveFilters           uint32 // Active filter count from hunter stats
	Status                  management.HunterStatus
	FilterUpdateFailures    uint32 // Consecutive filter update send failures
	LastFilterUpdateFailure int64  // Timestamp of last filter update failure
}

// Stats contains processor statistics
type Stats struct {
	TotalHunters          uint32
	HealthyHunters        uint32
	WarningHunters        uint32
	ErrorHunters          uint32
	TotalPacketsReceived  uint64
	TotalPacketsForwarded uint64
	TotalFilters          uint32
}

// cachedStats holds incrementally updated statistics
type cachedStats struct {
	stats      Stats
	lastUpdate int64 // Unix timestamp
}

// New creates a new processor instance
func New(config Config) (*Processor, error) {
	if config.ListenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	p := &Processor{
		config:         config,
		hunters:        make(map[string]*ConnectedHunter),
		filters:        make(map[string]*management.Filter),
		filterChannels: make(map[string]chan *management.FilterUpdate),
	}

	// Initialize protocol detector if enabled
	if config.EnableDetection {
		p.detector = detector.InitDefault()
		logger.Info("Protocol detection enabled on processor")
	}

	// Note: subscribers sync.Map requires no initialization

	// Initialize stats cache
	p.statsCache.Store(&cachedStats{
		stats:      Stats{},
		lastUpdate: time.Now().Unix(),
	})

	return p, nil
}

// Start begins processor operation
func (p *Processor) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)
	defer p.cancel()

	logger.Info("Processor starting", "processor_id", p.config.ProcessorID, "listen_addr", p.config.ListenAddr)

	// Load filters from persistence file
	if err := p.loadFilters(); err != nil {
		logger.Warn("Failed to load filters from file", "error", err)
		// Continue anyway - not a fatal error
	}

	// Initialize PCAP writer if configured
	if p.config.WriteFile != "" {
		if err := p.initPCAPWriter(); err != nil {
			return fmt.Errorf("failed to initialize PCAP writer: %w", err)
		}
		defer p.closePCAPWriter()
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

	// Start heartbeat monitor
	p.wg.Add(1)
	go p.monitorHeartbeats()

	// Start hunter cleanup janitor
	p.wg.Add(1)
	go p.cleanupStaleHunters()

	logger.Info("Processor started", "listen_addr", p.config.ListenAddr)

	// Wait for shutdown
	<-p.ctx.Done()

	// Graceful shutdown
	logger.Info("Shutting down processor")
	p.grpcServer.GracefulStop()
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
		flowControl := p.determineFlowControl()

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

// determineFlowControl determines appropriate flow control signal based on processor load
// Checks all pressure sources and returns the most severe signal (PAUSE > SLOW > RESUME > CONTINUE)
func (p *Processor) determineFlowControl() data.FlowControl {
	mostSevere := data.FlowControl_FLOW_CONTINUE

	// Check PCAP write queue depth if configured
	if p.pcapWriteQueue != nil {
		queueDepth := len(p.pcapWriteQueue)
		queueCapacity := cap(p.pcapWriteQueue)

		utilizationPct := float64(queueDepth) / float64(queueCapacity) * 100

		// Pause if queue is critically full (>90%)
		if utilizationPct > 90 {
			logger.Warn("PCAP write queue critically full - requesting pause",
				"queue_depth", queueDepth,
				"capacity", queueCapacity,
				"utilization", utilizationPct)
			mostSevere = data.FlowControl_FLOW_PAUSE
		} else if utilizationPct > 70 {
			// Slow down if queue is getting full (>70%)
			logger.Debug("PCAP write queue filling - requesting slowdown",
				"queue_depth", queueDepth,
				"capacity", queueCapacity,
				"utilization", utilizationPct)
			if mostSevere < data.FlowControl_FLOW_SLOW {
				mostSevere = data.FlowControl_FLOW_SLOW
			}
		} else if utilizationPct < 30 {
			// Resume if queue has drained (< 30%)
			if mostSevere < data.FlowControl_FLOW_RESUME {
				mostSevere = data.FlowControl_FLOW_RESUME
			}
		}
	}

	// NOTE: We do NOT check subscriber backpressure here!
	// TUI client drops should NOT pause hunters because:
	// 1. Hunters serve multiple consumers (other TUI clients, file writes, upstream processors)
	// 2. TUI disconnects/reconnects cause temporary drops that shouldn't affect hunters
	// 3. Slow TUI clients are already handled by per-subscriber channel buffering & drops
	// Hunters should only pause for processor-level overload (PCAP write queue, upstream backlog)

	// Check overall packet processing load (only if upstream forwarding is configured)
	// If no upstream processor, packets are only consumed by TUI subscribers, not forwarded
	if p.config.UpstreamAddr != "" {
		packetsReceived := p.packetsReceived.Load()
		packetsForwarded := p.packetsForwarded.Load()

		// If we're significantly behind in forwarding, slow down
		if packetsReceived > packetsForwarded {
			backlog := packetsReceived - packetsForwarded
			if backlog > 10000 {
				logger.Warn("Large packet backlog detected - requesting slowdown",
					"backlog", backlog)
				if mostSevere < data.FlowControl_FLOW_SLOW {
					mostSevere = data.FlowControl_FLOW_SLOW
				}
			}
		}
	}

	return mostSevere
}

// processBatch processes a received packet batch
func (p *Processor) processBatch(batch *data.PacketBatch) {
	hunterID := batch.HunterId

	logger.Debug("Received packet batch",
		"hunter_id", hunterID,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	// Update hunter statistics
	p.huntersMu.Lock()
	if hunter, exists := p.hunters[hunterID]; exists {
		hunter.PacketsReceived += uint64(len(batch.Packets))
		hunter.LastHeartbeat = batch.TimestampNs
	}
	p.huntersMu.Unlock()

	// Queue packets for async PCAP write if configured
	if p.pcapWriteQueue != nil {
		select {
		case p.pcapWriteQueue <- batch.Packets:
			// Queued successfully
		default:
			// Queue full - log warning but don't block
			logger.Warn("PCAP write queue full, dropping batch", "packets", len(batch.Packets))
		}
	}

	// Update processor statistics (atomic increment)
	p.packetsReceived.Add(uint64(len(batch.Packets)))

	// Enrich packets with protocol detection if enabled
	if p.config.EnableDetection && p.detector != nil {
		p.enrichPackets(batch.Packets)
	}

	// Forward to upstream in hierarchical mode
	if p.upstreamStream != nil {
		p.forwardToUpstream(batch)
	}

	// Broadcast to monitoring subscribers (TUI clients)
	// IMPORTANT: Make a copy of the batch before broadcasting to avoid race conditions
	// The same batch structure will be serialized by multiple goroutines concurrently
	// (one per TUI client), which can corrupt the protobuf wire format
	batchCopy := proto.Clone(batch).(*data.PacketBatch)
	p.broadcastToSubscribers(batchCopy)
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

	// Check if hunter already exists
	p.huntersMu.Lock()
	isReconnect := false
	if _, exists := p.hunters[hunterID]; exists {
		logger.Info("Hunter re-registering (replacing old connection)", "hunter_id", hunterID)
		isReconnect = true
		// Allow re-registration (old connection will be replaced)
	} else {
		// Check max hunters limit (only for new hunters)
		if len(p.hunters) >= p.config.MaxHunters {
			p.huntersMu.Unlock()
			logger.Warn("Max hunters limit reached", "limit", p.config.MaxHunters)
			return nil, status.Errorf(codes.ResourceExhausted,
				"maximum number of hunters reached: limit %d", p.config.MaxHunters)
		}
	}

	// Register/re-register hunter
	hunter := &ConnectedHunter{
		ID:          hunterID,
		Hostname:    req.Hostname,
		Interfaces:  req.Interfaces,
		ConnectedAt: time.Now().UnixNano(),
		Status:      management.HunterStatus_STATUS_HEALTHY,
	}
	p.hunters[hunterID] = hunter

	// Update stats cache (while still holding huntersMu)
	if !isReconnect {
		p.updateHealthStats()
	}

	p.huntersMu.Unlock()

	logger.Info("Hunter registered successfully", "hunter_id", hunterID)

	// Get applicable filters for this hunter
	filters := p.getFiltersForHunter(hunterID)

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
		p.huntersMu.Lock()
		statsChanged := false
		if hunter, exists := p.hunters[hunterID]; exists {
			hunter.LastHeartbeat = hb.TimestampNs
			hunter.Status = hb.Status
			if hb.Stats != nil {
				// Check if filter count changed
				if hunter.ActiveFilters != hb.Stats.ActiveFilters {
					hunter.ActiveFilters = hb.Stats.ActiveFilters
					statsChanged = true
				}
			}
		}
		// Update aggregated stats immediately if filter count changed
		if statsChanged {
			p.updateHealthStats()
		}
		p.huntersMu.Unlock()

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
		stats := p.GetStats()
		resp := &management.ProcessorHeartbeat{
			TimestampNs:      hb.TimestampNs,
			Status:           management.ProcessorStatus_PROCESSOR_HEALTHY,
			HuntersConnected: stats.TotalHunters,
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
	filters := p.getFiltersForHunter(req.HunterId)

	return &management.FilterResponse{
		Filters: filters,
	}, nil
}

// SubscribeFilters streams filter updates to hunters (Management Service)
func (p *Processor) SubscribeFilters(req *management.FilterRequest, stream management.ManagementService_SubscribeFiltersServer) error {
	hunterID := req.HunterId
	logger.Info("Filter subscription started", "hunter_id", hunterID)

	// Create filter update channel for this hunter
	filterChan := make(chan *management.FilterUpdate, constants.FilterUpdateChannelBuffer)

	p.filtersMu.Lock()
	p.filterChannels[hunterID] = filterChan
	p.filtersMu.Unlock()

	// Cleanup on disconnect
	defer func() {
		p.filtersMu.Lock()
		delete(p.filterChannels, hunterID)
		close(filterChan)
		p.filtersMu.Unlock()
		logger.Info("Filter subscription ended", "hunter_id", hunterID)
	}()

	// Send current filters immediately
	currentFilters := p.getFiltersForHunter(hunterID)
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
	p.huntersMu.RLock()
	defer p.huntersMu.RUnlock()

	connectedHunters := make([]*management.ConnectedHunter, 0, len(p.hunters))

	for _, hunter := range p.hunters {
		// Skip if filtering by hunter ID
		if req.HunterId != "" && hunter.ID != req.HunterId {
			continue
		}

		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - hunter.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		connectedHunters = append(connectedHunters, &management.ConnectedHunter{
			HunterId:             hunter.ID,
			Hostname:             hunter.Hostname,
			RemoteAddr:           hunter.RemoteAddr,
			Status:               hunter.Status,
			ConnectedDurationSec: durationSec,
			LastHeartbeatNs:      hunter.LastHeartbeat,
			Stats: &management.HunterStats{
				PacketsCaptured:  hunter.PacketsReceived,
				PacketsForwarded: hunter.PacketsReceived,
				ActiveFilters:    hunter.ActiveFilters,
			},
			Interfaces: hunter.Interfaces,
		})
	}

	stats := p.GetStats()

	return &management.StatusResponse{
		Hunters: connectedHunters,
		ProcessorStats: &management.ProcessorStats{
			TotalHunters:          stats.TotalHunters,
			HealthyHunters:        stats.HealthyHunters,
			WarningHunters:        stats.WarningHunters,
			ErrorHunters:          stats.ErrorHunters,
			TotalPacketsReceived:  stats.TotalPacketsReceived,
			TotalPacketsForwarded: stats.TotalPacketsForwarded,
			TotalFilters:          stats.TotalFilters,
			ProcessorId:           p.config.ProcessorID,
		},
	}, nil
}

// ListAvailableHunters returns list of all hunters connected to this processor (for TUI hunter selection)
func (p *Processor) ListAvailableHunters(ctx context.Context, req *management.ListHuntersRequest) (*management.ListHuntersResponse, error) {
	p.huntersMu.RLock()
	defer p.huntersMu.RUnlock()

	hunters := make([]*management.AvailableHunter, 0, len(p.hunters))

	for _, hunter := range p.hunters {
		// Calculate connection duration (safe: duration won't overflow, max ~292 years)
		durationNs := time.Now().UnixNano() - hunter.ConnectedAt
		durationSec := uint64(durationNs / 1e9) // #nosec G115

		hunters = append(hunters, &management.AvailableHunter{
			HunterId:             hunter.ID,
			Hostname:             hunter.Hostname,
			Interfaces:           hunter.Interfaces,
			Status:               hunter.Status,
			RemoteAddr:           hunter.RemoteAddr,
			ConnectedDurationSec: durationSec,
		})
	}

	logger.Debug("ListAvailableHunters request", "hunter_count", len(hunters))

	return &management.ListHuntersResponse{
		Hunters: hunters,
	}, nil
}

// UpdateFilter adds or modifies a filter (Management Service)
func (p *Processor) UpdateFilter(ctx context.Context, filter *management.Filter) (*management.FilterUpdateResult, error) {
	logger.Info("Update filter request", "filter_id", filter.Id, "type", filter.Type, "pattern", filter.Pattern)

	// Generate ID for new filters
	p.filtersMu.Lock()
	if filter.Id == "" {
		filter.Id = fmt.Sprintf("filter-%d", time.Now().UnixNano())
		logger.Info("Generated filter ID", "filter_id", filter.Id)
	}

	// Determine if this is add or modify
	_, exists := p.filters[filter.Id]
	p.filters[filter.Id] = filter

	updateType := management.FilterUpdateType_UPDATE_ADD
	if exists {
		updateType = management.FilterUpdateType_UPDATE_MODIFY
	}
	p.filtersMu.Unlock()

	// Push filter update to affected hunters
	update := &management.FilterUpdate{
		UpdateType: updateType,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := p.saveFilters(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already in memory
	}

	logger.Info("Filter updated",
		"filter_id", filter.Id,
		"hunters_updated", huntersUpdated,
		"update_type", updateType)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// DeleteFilter removes a filter (Management Service)
func (p *Processor) DeleteFilter(ctx context.Context, req *management.FilterDeleteRequest) (*management.FilterUpdateResult, error) {
	logger.Info("Delete filter request", "filter_id", req.FilterId)

	p.filtersMu.Lock()
	filter, exists := p.filters[req.FilterId]
	if !exists {
		p.filtersMu.Unlock()
		return nil, status.Errorf(codes.NotFound,
			"filter not found: %s", req.FilterId)
	}
	delete(p.filters, req.FilterId)
	p.filtersMu.Unlock()

	// Push filter deletion to affected hunters
	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_DELETE,
		Filter:     filter,
	}

	huntersUpdated := p.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := p.saveFilters(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already removed from memory
	}

	logger.Info("Filter deleted",
		"filter_id", req.FilterId,
		"hunters_updated", huntersUpdated)

	return &management.FilterUpdateResult{
		Success:        true,
		HuntersUpdated: huntersUpdated,
	}, nil
}

// getFiltersForHunter returns filters applicable to a hunter
func (p *Processor) getFiltersForHunter(hunterID string) []*management.Filter {
	p.filtersMu.RLock()
	defer p.filtersMu.RUnlock()

	filters := make([]*management.Filter, 0)

	for _, filter := range p.filters {
		// If no target hunters specified, apply to all
		if len(filter.TargetHunters) == 0 {
			filters = append(filters, filter)
			continue
		}

		// Check if this hunter is targeted
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				filters = append(filters, filter)
				break
			}
		}
	}

	return filters
}

// GetStats returns current statistics
func (p *Processor) GetStats() Stats {
	// Lock-free read from cache (hunter health stats)
	cached := p.statsCache.Load().(*cachedStats)
	stats := cached.stats

	// Add atomic packet counters
	stats.TotalPacketsReceived = p.packetsReceived.Load()
	stats.TotalPacketsForwarded = p.packetsForwarded.Load()

	return stats
}

// initPCAPWriter initializes PCAP file writer with async worker pool
func (p *Processor) initPCAPWriter() error {
	logger.Info("Initializing async PCAP writer", "file", p.config.WriteFile)

	file, err := os.Create(p.config.WriteFile)
	if err != nil {
		return fmt.Errorf("failed to create PCAP file: %w", err)
	}

	p.pcapFile = file
	p.pcapWriter = pcapgo.NewWriter(file)

	// Write PCAP header (Ethernet link type)
	if err := p.pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write PCAP header: %w", err)
	}

	// Create write queue (buffered channel)
	p.pcapWriteQueue = make(chan []*data.CapturedPacket, constants.PCAPWriteQueueBuffer)

	// Start single writer goroutine
	// Note: PCAP writes are inherently serial (file format requires sequential writes)
	// Multiple workers would just compete for mutex with no benefit
	p.pcapWriterWg.Add(1)
	go p.pcapWriteWorker()

	logger.Info("Async PCAP writer initialized", "file", p.config.WriteFile)
	return nil
}

// pcapWriteWorker processes PCAP write queue asynchronously (single writer)
func (p *Processor) pcapWriteWorker() {
	defer p.pcapWriterWg.Done()

	logger.Debug("PCAP write worker started")

	for {
		select {
		case <-p.ctx.Done():
			logger.Debug("PCAP write worker stopping")
			return

		case packets, ok := <-p.pcapWriteQueue:
			if !ok {
				logger.Debug("PCAP write queue closed")
				return
			}

			// Write batch to PCAP file (single writer - no mutex needed)
			p.writePacketBatchToPCAP(packets)
		}
	}
}

// writePacketBatchToPCAP writes a batch of packets to PCAP file (called by single writer)
func (p *Processor) writePacketBatchToPCAP(packets []*data.CapturedPacket) {
	// No mutex needed - single writer goroutine ensures serial access

	batchErrors := 0
	for _, pkt := range packets {
		// Convert timestamp
		timestamp := time.Unix(0, pkt.TimestampNs)

		// Create capture info
		ci := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: int(pkt.CaptureLength),
			Length:        int(pkt.OriginalLength),
		}

		// Write packet
		if err := p.pcapWriter.WritePacket(ci, pkt.Data); err != nil {
			batchErrors++
			p.pcapWriteErrors.Add(1)
			consecErrors := p.pcapConsecErrors.Add(1)

			// Log errors with rate limiting (max once per 10 seconds)
			now := time.Now().Unix()
			lastLogged := p.pcapLastErrorLogged.Load()
			if now-lastLogged >= 10 {
				if p.pcapLastErrorLogged.CompareAndSwap(lastLogged, now) {
					logger.Error("Failed to write packet to PCAP",
						"error", err,
						"consecutive_errors", consecErrors,
						"total_errors", p.pcapWriteErrors.Load())

					// Emit critical warning if many consecutive failures
					if consecErrors >= 100 {
						logger.Warn("PCAP writing may be failing due to disk full or permissions",
							"consecutive_errors", consecErrors,
							"recommendation", "check disk space and file permissions")
					}
				}
			}
		} else {
			// Successful write - reset consecutive error counter
			if p.pcapConsecErrors.Load() > 0 {
				p.pcapConsecErrors.Store(0)
			}
		}
	}

	// Log batch summary if there were errors
	if batchErrors > 0 && len(packets) > 0 {
		logger.Warn("PCAP batch write completed with errors",
			"batch_size", len(packets),
			"errors", batchErrors,
			"success_rate", float64(len(packets)-batchErrors)/float64(len(packets))*100)
	}
}

// closePCAPWriter closes PCAP file and waits for workers
func (p *Processor) closePCAPWriter() {
	// Close queue to signal workers
	if p.pcapWriteQueue != nil {
		close(p.pcapWriteQueue)
	}

	// Wait for all workers to finish
	logger.Info("Waiting for PCAP writers to finish")
	p.pcapWriterWg.Wait()

	// Close file
	if p.pcapFile != nil {
		_ = p.pcapFile.Close()
		logger.Info("PCAP file closed", "file", p.config.WriteFile)
	}
}

// pushFilterUpdate sends filter update to affected hunters
func (p *Processor) pushFilterUpdate(filter *management.Filter, update *management.FilterUpdate) uint32 {
	p.filtersMu.RLock()
	defer p.filtersMu.RUnlock()

	var huntersUpdated uint32
	const sendTimeout = 2 * time.Second
	const maxConsecutiveFailures = 5
	const circuitBreakerThreshold = 10 // Disconnect after this many failures

	// Helper to send with timeout and track failures
	sendUpdate := func(hunterID string, ch chan *management.FilterUpdate) bool {
		timer := time.NewTimer(sendTimeout)
		defer timer.Stop()

		select {
		case ch <- update:
			// Success - reset failure counter
			p.huntersMu.Lock()
			if hunter, exists := p.hunters[hunterID]; exists {
				hunter.FilterUpdateFailures = 0
			}
			p.huntersMu.Unlock()
			logger.Debug("Sent filter update", "hunter_id", hunterID, "filter_id", filter.Id)
			return true

		case <-timer.C:
			// Timeout - track failure
			p.huntersMu.Lock()
			if hunter, exists := p.hunters[hunterID]; exists {
				hunter.FilterUpdateFailures++
				hunter.LastFilterUpdateFailure = time.Now().UnixNano()

				if hunter.FilterUpdateFailures >= circuitBreakerThreshold {
					// Circuit breaker: disconnect permanently failed hunter
					logger.Error("Circuit breaker triggered - disconnecting hunter",
						"hunter_id", hunterID,
						"consecutive_failures", hunter.FilterUpdateFailures,
						"threshold", circuitBreakerThreshold,
						"action", "removing hunter from processor")
					hunter.Status = management.HunterStatus_STATUS_ERROR

					// Schedule immediate removal (will be picked up by cleanup)
					hunter.LastHeartbeat = time.Now().Add(-60 * time.Minute).UnixNano()
				} else if hunter.FilterUpdateFailures >= maxConsecutiveFailures {
					logger.Error("Hunter not receiving filter updates - marking as error",
						"hunter_id", hunterID,
						"consecutive_failures", hunter.FilterUpdateFailures,
						"recommendation", "hunter may be overloaded or network issue")
					hunter.Status = management.HunterStatus_STATUS_ERROR
				} else {
					logger.Warn("Filter update send timeout",
						"hunter_id", hunterID,
						"consecutive_failures", hunter.FilterUpdateFailures,
						"max_failures", maxConsecutiveFailures)
				}
			}
			p.huntersMu.Unlock()
			return false
		}
	}

	// If no target hunters specified, send to all
	if len(filter.TargetHunters) == 0 {
		for hunterID, ch := range p.filterChannels {
			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
		return huntersUpdated
	}

	// Send to specific hunters
	for _, targetID := range filter.TargetHunters {
		if ch, exists := p.filterChannels[targetID]; exists {
			if sendUpdate(targetID, ch) {
				huntersUpdated++
			}
		}
	}

	return huntersUpdated
}

// monitorHeartbeats monitors hunter heartbeats and marks stale hunters
func (p *Processor) monitorHeartbeats() {
	defer p.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	logger.Info("Heartbeat monitor started")

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Heartbeat monitor stopped")
			return

		case <-ticker.C:
			p.huntersMu.Lock()
			now := time.Now().UnixNano()
			staleThreshold := int64(30 * time.Second) // 30 seconds without heartbeat

			for hunterID, hunter := range p.hunters {
				if hunter.LastHeartbeat > 0 {
					timeSinceHeartbeat := now - hunter.LastHeartbeat

					if timeSinceHeartbeat > staleThreshold {
						if hunter.Status != management.HunterStatus_STATUS_ERROR {
							logger.Warn("Hunter heartbeat timeout",
								"hunter_id", hunterID,
								"last_heartbeat_sec", timeSinceHeartbeat/int64(time.Second))
							hunter.Status = management.HunterStatus_STATUS_ERROR
						}
					}
				}
			}

			// Update stats based on hunter statuses
			p.updateHealthStats()

			p.huntersMu.Unlock()
		}
	}
}

// updateHealthStats updates processor health statistics based on hunter statuses
// Assumes huntersMu is already locked by caller
func (p *Processor) updateHealthStats() {
	var healthy, warning, errCount uint32
	var totalFilters uint32

	for _, hunter := range p.hunters {
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			healthy++
		case management.HunterStatus_STATUS_WARNING:
			warning++
		case management.HunterStatus_STATUS_ERROR:
			errCount++
		}
		// Aggregate active filters from all hunters
		totalFilters += hunter.ActiveFilters
	}

	// Get current cache, update, and store back (copy-on-write)
	oldCache := p.statsCache.Load().(*cachedStats)
	newStats := oldCache.stats // Copy current stats

	// Update hunter health stats (safe: hunter count won't exceed uint32 max)
	newStats.TotalHunters = uint32(len(p.hunters)) // #nosec G115
	newStats.HealthyHunters = healthy
	newStats.WarningHunters = warning
	newStats.ErrorHunters = errCount
	newStats.TotalFilters = totalFilters

	// Store updated cache
	p.statsCache.Store(&cachedStats{
		stats:      newStats,
		lastUpdate: time.Now().Unix(),
	})
	p.statsUpdates.Add(1)
}

// cleanupStaleHunters periodically removes hunters that have been in ERROR state for too long
func (p *Processor) cleanupStaleHunters() {
	defer p.wg.Done()

	// Cleanup interval: check every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	// Grace period: remove hunters that have been in ERROR state for 30 minutes
	const gracePeriod = 30 * time.Minute

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			p.huntersMu.Lock()

			var toRemove []string
			for hunterID, hunter := range p.hunters {
				if hunter.Status == management.HunterStatus_STATUS_ERROR {
					// Check how long it's been in ERROR state
					lastHeartbeat := time.Unix(0, hunter.LastHeartbeat)
					timeSinceError := now.Sub(lastHeartbeat)

					if timeSinceError > gracePeriod {
						toRemove = append(toRemove, hunterID)
					}
				}
			}

			// Remove stale hunters
			for _, hunterID := range toRemove {
				logger.Info("Removing stale hunter from map",
					"hunter_id", hunterID,
					"reason", "in ERROR state beyond grace period")
				delete(p.hunters, hunterID)

				// Also remove from filter channels
				delete(p.filterChannels, hunterID)
			}

			p.huntersMu.Unlock()

			if len(toRemove) > 0 {
				logger.Info("Cleaned up stale hunters",
					"count", len(toRemove),
					"grace_period", gracePeriod)
			}
		}
	}
}

// buildTLSCredentials creates TLS credentials for gRPC server
func (p *Processor) buildTLSCredentials() (credentials.TransportCredentials, error) {
	if p.config.TLSCertFile == "" || p.config.TLSKeyFile == "" {
		return nil, fmt.Errorf("TLS enabled but certificate or key file not specified")
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Configure client certificate authentication if enabled
	if p.config.TLSClientAuth {
		if p.config.TLSCAFile == "" {
			return nil, fmt.Errorf("client auth enabled but CA file not specified")
		}

		// Load CA certificate for verifying client certificates
		caCert, err := os.ReadFile(p.config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = certPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		logger.Info("Mutual TLS enabled - requiring client certificates",
			"ca_file", p.config.TLSCAFile)
	}

	logger.Info("TLS credentials loaded",
		"cert", p.config.TLSCertFile,
		"key", p.config.TLSKeyFile,
		"min_version", "TLS 1.3")

	return credentials.NewTLS(tlsConfig), nil
}

// buildClientTLSCredentials creates TLS credentials for gRPC client (upstream connection)
func (p *Processor) buildClientTLSCredentials() (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load CA certificate if provided
	if p.config.TLSCAFile != "" {
		caCert, err := os.ReadFile(p.config.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = certPool
		logger.Info("Loaded CA certificate for upstream connection", "file", p.config.TLSCAFile)
	}

	// Load client certificate for mutual TLS if provided
	if p.config.TLSCertFile != "" && p.config.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		logger.Info("Loaded client certificate for mutual TLS to upstream",
			"cert", p.config.TLSCertFile,
			"key", p.config.TLSKeyFile)
	}

	return credentials.NewTLS(tlsConfig), nil
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
		nextID := p.nextSubID.Add(1)
		clientID = fmt.Sprintf("subscriber-%d", nextID)
	}

	// Check subscriber limit to prevent DoS
	if p.config.MaxSubscribers > 0 {
		// Count current subscribers
		count := 0
		p.subscribers.Range(func(key, value interface{}) bool {
			count++
			return true
		})
		if count >= p.config.MaxSubscribers {
			logger.Warn("Subscriber limit reached, rejecting new subscriber",
				"client_id", clientID,
				"current_subscribers", count,
				"max_subscribers", p.config.MaxSubscribers)
			return status.Errorf(codes.ResourceExhausted,
				"maximum number of subscribers (%d) reached", p.config.MaxSubscribers)
		}
	}

	// Store hunter subscription filter for this client
	// has_hunter_filter = false: subscribe to all hunters (default/backward compatibility)
	// has_hunter_filter = true + empty list: subscribe to no hunters (explicit opt-out)
	// has_hunter_filter = true + non-empty list: subscribe to specified hunters only
	if req.HasHunterFilter {
		p.subscriberFilter.Store(clientID, req.HunterIds)
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
	subChan := make(chan *data.PacketBatch, constants.SubscriberChannelBuffer)

	// Add subscriber using copy-on-write
	p.addSubscriber(clientID, subChan)

	// Cleanup on disconnect
	defer func() {
		p.removeSubscriber(clientID)
		p.subscriberFilter.Delete(clientID) // Clean up filter
		close(subChan)
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

// addSubscriber adds a subscriber using sync.Map (O(1) operation)
func (p *Processor) addSubscriber(clientID string, ch chan *data.PacketBatch) {
	p.subscribers.Store(clientID, ch)
}

// removeSubscriber removes a subscriber using sync.Map (O(1) operation)
func (p *Processor) removeSubscriber(clientID string) {
	p.subscribers.Delete(clientID)
}

// broadcastToSubscribers broadcasts a packet batch to all monitoring subscribers
// Uses sync.Map for lock-free concurrent iteration
// Tracks broadcast attempts and drops for backpressure calculation
func (p *Processor) broadcastToSubscribers(batch *data.PacketBatch) {
	// Lock-free iteration over subscribers
	p.subscribers.Range(func(key, value interface{}) bool {
		clientID := key.(string)
		ch := value.(chan *data.PacketBatch)

		p.subscriberBroadcasts.Add(1)

		select {
		case ch <- batch:
			logger.Debug("Broadcasted batch to subscriber", "client_id", clientID, "packets", len(batch.Packets))
		default:
			p.subscriberDrops.Add(1)
			logger.Warn("Subscriber channel full, dropping batch", "client_id", clientID)
		}
		return true // Continue iteration
	})
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
