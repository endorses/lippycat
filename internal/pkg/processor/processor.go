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
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config contains processor configuration
type Config struct {
	ListenAddr       string
	ProcessorID      string
	UpstreamAddr     string
	MaxHunters       int
	WriteFile        string
	DisplayStats     bool
	PcapWriterConfig *PcapWriterConfig // Per-call PCAP writing configuration
	EnableDetection  bool              // Enable centralized protocol detection
	FilterFile       string            // Path to filter persistence file (YAML)
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

	// PCAP writer (async)
	pcapFile          *os.File
	pcapWriter        *pcapgo.Writer
	pcapWriteQueue    chan []*data.CapturedPacket
	pcapWriterWg      sync.WaitGroup
	pcapWriterMu      sync.Mutex // Protects pcapWriter (not thread-safe)
	perCallPcapWriter *PcapWriterManager // Per-call PCAP writer

	// Statistics - use atomic.Value for lock-free reads
	statsCache           atomic.Value  // stores *cachedStats
	statsUpdates         atomic.Uint64 // incremented on every stats change
	packetsReceived      atomic.Uint64 // incremental counter
	packetsForwarded     atomic.Uint64 // incremental counter

	// Filters
	filtersMu      sync.RWMutex
	filters        map[string]*management.Filter
	filterChannels map[string]chan *management.FilterUpdate // hunterID -> channel

	// Upstream connection (hierarchical mode)
	upstreamConn   *grpc.ClientConn
	upstreamClient data.DataServiceClient
	upstreamStream data.DataService_StreamPacketsClient
	upstreamMu     sync.Mutex

	// Monitoring subscribers (TUI clients) - uses copy-on-write for lock-free reads
	subscribersMu    sync.Mutex
	subscribersAtomic atomic.Value // stores *subscriberMap
	nextSubID         atomic.Uint64

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
	ID             string
	Hostname       string
	RemoteAddr     string
	Interfaces     []string
	ConnectedAt    int64
	LastHeartbeat  int64
	PacketsReceived uint64
	Status         management.HunterStatus
}

// Stats contains processor statistics
type Stats struct {
	TotalHunters           uint32
	HealthyHunters         uint32
	WarningHunters         uint32
	ErrorHunters           uint32
	TotalPacketsReceived   uint64
	TotalPacketsForwarded  uint64
	TotalFilters           uint32
}

// cachedStats holds incrementally updated statistics
type cachedStats struct {
	stats      Stats
	lastUpdate int64 // Unix timestamp
}

// subscriberMap holds the current set of subscribers
// Used with atomic.Value for copy-on-write pattern
type subscriberMap struct {
	subscribers map[string]chan *data.PacketBatch
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

	// Initialize subscriber map with copy-on-write
	p.subscribersAtomic.Store(&subscriberMap{
		subscribers: make(map[string]chan *data.PacketBatch),
	})

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

	// Create gRPC server
	p.grpcServer = grpc.NewServer(
		grpc.MaxRecvMsgSize(10*1024*1024), // 10MB
	)

	// Register services
	data.RegisterDataServiceServer(p.grpcServer, p)
	management.RegisterManagementServiceServer(p.grpcServer, p)

	logger.Info("gRPC server created",
		"addr", listener.Addr().String(),
		"services", []string{"DataService", "ManagementService"})

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

		// Send acknowledgment
		ack := &data.StreamControl{
			AckSequence: batch.Sequence,
			FlowControl: data.FlowControl_FLOW_CONTINUE,
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
	p.broadcastToSubscribers(batch)
}

// RegisterHunter handles hunter registration (Management Service)
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
			return &management.RegistrationResponse{
				Accepted: false,
				Error:    "maximum number of hunters reached",
			}, nil
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
			BatchSize:             64,
			BatchTimeoutMs:        100,
			ReconnectIntervalSec:  5,
			MaxReconnectAttempts:  0, // infinite
			ProcessorId:           p.config.ProcessorID,
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

		// Update hunter status
		p.huntersMu.Lock()
		if hunter, exists := p.hunters[hunterID]; exists {
			hunter.LastHeartbeat = hb.TimestampNs
			hunter.Status = hb.Status
		}
		p.huntersMu.Unlock()

		logger.Debug("Heartbeat received", "hunter_id", hunterID)

		// Send response
		stats := p.GetStats()
		resp := &management.ProcessorHeartbeat{
			TimestampNs:       hb.TimestampNs,
			Status:            management.ProcessorStatus_PROCESSOR_HEALTHY,
			HuntersConnected:  stats.TotalHunters,
			ProcessorId:       p.config.ProcessorID,
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
	filterChan := make(chan *management.FilterUpdate, 10)

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

		// Calculate connection duration
		durationNs := time.Now().UnixNano() - hunter.ConnectedAt
		durationSec := uint64(durationNs / 1e9)

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
			},
			Interfaces: hunter.Interfaces,
		})
	}

	stats := p.GetStats()

	return &management.StatusResponse{
		Hunters: connectedHunters,
		ProcessorStats: &management.ProcessorStats{
			TotalHunters:           stats.TotalHunters,
			HealthyHunters:         stats.HealthyHunters,
			WarningHunters:         stats.WarningHunters,
			ErrorHunters:           stats.ErrorHunters,
			TotalPacketsReceived:   stats.TotalPacketsReceived,
			TotalPacketsForwarded:  stats.TotalPacketsForwarded,
			TotalFilters:           stats.TotalFilters,
			ProcessorId:            p.config.ProcessorID,
		},
	}, nil
}

// UpdateFilter adds or modifies a filter (Management Service)
func (p *Processor) UpdateFilter(ctx context.Context, filter *management.Filter) (*management.FilterUpdateResult, error) {
	logger.Info("Update filter request", "filter_id", filter.Id, "type", filter.Type, "pattern", filter.Pattern)

	// Determine if this is add or modify
	p.filtersMu.Lock()
	_, exists := p.filters[filter.Id]
	p.filters[filter.Id] = filter
	p.filtersMu.Unlock()

	updateType := management.FilterUpdateType_UPDATE_ADD
	if exists {
		updateType = management.FilterUpdateType_UPDATE_MODIFY
	}

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
		return &management.FilterUpdateResult{
			Success: false,
			Error:   "filter not found",
		}, nil
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
		file.Close()
		return fmt.Errorf("failed to write PCAP header: %w", err)
	}

	// Create write queue (buffered channel)
	p.pcapWriteQueue = make(chan []*data.CapturedPacket, 1000)

	// Start worker pool (2-4 workers for parallel writes)
	numWorkers := 2
	for i := 0; i < numWorkers; i++ {
		p.pcapWriterWg.Add(1)
		go p.pcapWriteWorker(i)
	}

	logger.Info("Async PCAP writer initialized", "file", p.config.WriteFile, "workers", numWorkers)
	return nil
}

// pcapWriteWorker processes PCAP write queue asynchronously
func (p *Processor) pcapWriteWorker(workerID int) {
	defer p.pcapWriterWg.Done()

	logger.Debug("PCAP write worker started", "worker_id", workerID)

	for {
		select {
		case <-p.ctx.Done():
			logger.Debug("PCAP write worker stopping", "worker_id", workerID)
			return

		case packets, ok := <-p.pcapWriteQueue:
			if !ok {
				logger.Debug("PCAP write queue closed", "worker_id", workerID)
				return
			}

			// Write batch to PCAP file
			// Note: gopacket's pcapgo.Writer is NOT thread-safe
			// We need a mutex here, but it's only contended by workers, not the hot path
			p.writePacketBatchToPCAP(packets)
		}
	}
}

// writePacketBatchToPCAP writes a batch of packets to PCAP file (called by workers)
func (p *Processor) writePacketBatchToPCAP(packets []*data.CapturedPacket) {
	// pcapgo.Writer is not thread-safe, so we need synchronization between workers
	// This mutex is only contended by workers, not the main packet processing path
	p.pcapWriterMu.Lock()
	defer p.pcapWriterMu.Unlock()

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
			logger.Error("Failed to write packet to PCAP", "error", err)
		}
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
		p.pcapFile.Close()
		logger.Info("PCAP file closed", "file", p.config.WriteFile)
	}
}

// pushFilterUpdate sends filter update to affected hunters
func (p *Processor) pushFilterUpdate(filter *management.Filter, update *management.FilterUpdate) uint32 {
	p.filtersMu.RLock()
	defer p.filtersMu.RUnlock()

	var huntersUpdated uint32

	// If no target hunters specified, send to all
	if len(filter.TargetHunters) == 0 {
		for hunterID, ch := range p.filterChannels {
			select {
			case ch <- update:
				huntersUpdated++
				logger.Debug("Sent filter update", "hunter_id", hunterID, "filter_id", filter.Id)
			default:
				logger.Warn("Filter channel full, dropping update", "hunter_id", hunterID)
			}
		}
		return huntersUpdated
	}

	// Send to specific hunters
	for _, targetID := range filter.TargetHunters {
		if ch, exists := p.filterChannels[targetID]; exists {
			select {
			case ch <- update:
				huntersUpdated++
				logger.Debug("Sent filter update", "hunter_id", targetID, "filter_id", filter.Id)
			default:
				logger.Warn("Filter channel full, dropping update", "hunter_id", targetID)
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

	for _, hunter := range p.hunters {
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			healthy++
		case management.HunterStatus_STATUS_WARNING:
			warning++
		case management.HunterStatus_STATUS_ERROR:
			errCount++
		}
	}

	// Get current cache, update, and store back (copy-on-write)
	oldCache := p.statsCache.Load().(*cachedStats)
	newStats := oldCache.stats // Copy current stats

	// Update hunter health stats
	newStats.TotalHunters = uint32(len(p.hunters))
	newStats.HealthyHunters = healthy
	newStats.WarningHunters = warning
	newStats.ErrorHunters = errCount

	// Store updated cache
	p.statsCache.Store(&cachedStats{
		stats:      newStats,
		lastUpdate: time.Now().Unix(),
	})
	p.statsUpdates.Add(1)
}

// connectToUpstream establishes connection to upstream processor
func (p *Processor) connectToUpstream() error {
	logger.Info("Connecting to upstream processor", "addr", p.config.UpstreamAddr)

	// Create gRPC connection
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10 * 1024 * 1024)), // 10MB
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
		conn.Close()
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
		p.upstreamStream.CloseSend()
		p.upstreamStream = nil
	}
	p.upstreamMu.Unlock()

	if p.upstreamConn != nil {
		p.upstreamConn.Close()
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

	p.upstreamMu.Lock()
	stream := p.upstreamStream
	p.upstreamMu.Unlock()

	if stream == nil {
		logger.Error("Upstream stream not available for receiving acks")
		return
	}

	for {
		ack, err := stream.Recv()
		if err != nil {
			if p.ctx.Err() != nil {
				logger.Info("Upstream ack receiver closed")
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

// SubscribePackets allows monitoring clients (TUI) to receive packet stream (Data Service)
func (p *Processor) SubscribePackets(req *data.SubscribeRequest, stream data.DataService_SubscribePacketsServer) error {
	clientID := req.ClientId
	if clientID == "" {
		nextID := p.nextSubID.Add(1)
		clientID = fmt.Sprintf("subscriber-%d", nextID)
	}

	logger.Info("New packet subscriber", "client_id", clientID)

	// Create channel for this subscriber
	subChan := make(chan *data.PacketBatch, 100)

	// Add subscriber using copy-on-write
	p.addSubscriber(clientID, subChan)

	// Cleanup on disconnect
	defer func() {
		p.removeSubscriber(clientID)
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

			// Filter by hunter IDs if specified
			if len(req.HunterIds) > 0 {
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

// addSubscriber adds a subscriber using copy-on-write
func (p *Processor) addSubscriber(clientID string, ch chan *data.PacketBatch) {
	p.subscribersMu.Lock()
	defer p.subscribersMu.Unlock()

	// Get current map
	oldMap := p.subscribersAtomic.Load().(*subscriberMap)

	// Create new map with added subscriber
	newSubs := make(map[string]chan *data.PacketBatch, len(oldMap.subscribers)+1)
	for k, v := range oldMap.subscribers {
		newSubs[k] = v
	}
	newSubs[clientID] = ch

	// Atomically replace the map
	p.subscribersAtomic.Store(&subscriberMap{subscribers: newSubs})
}

// removeSubscriber removes a subscriber using copy-on-write
func (p *Processor) removeSubscriber(clientID string) {
	p.subscribersMu.Lock()
	defer p.subscribersMu.Unlock()

	// Get current map
	oldMap := p.subscribersAtomic.Load().(*subscriberMap)

	// Create new map without the subscriber
	newSubs := make(map[string]chan *data.PacketBatch, len(oldMap.subscribers)-1)
	for k, v := range oldMap.subscribers {
		if k != clientID {
			newSubs[k] = v
		}
	}

	// Atomically replace the map
	p.subscribersAtomic.Store(&subscriberMap{subscribers: newSubs})
}

// broadcastToSubscribers broadcasts a packet batch to all monitoring subscribers
// Uses lock-free read from atomic value
func (p *Processor) broadcastToSubscribers(batch *data.PacketBatch) {
	// Lock-free read of subscriber map
	subMap := p.subscribersAtomic.Load().(*subscriberMap)

	// Iterate over snapshot - no locks needed
	for clientID, ch := range subMap.subscribers {
		select {
		case ch <- batch:
			logger.Debug("Broadcasted batch to subscriber", "client_id", clientID, "packets", len(batch.Packets))
		default:
			logger.Warn("Subscriber channel full, dropping batch", "client_id", clientID)
		}
	}
}

// enrichPackets performs centralized protocol detection and enriches packet metadata
func (p *Processor) enrichPackets(packets []*data.CapturedPacket) {
	for _, pkt := range packets {
		// Decode packet from raw bytes
		goPacket := gopacket.NewPacket(pkt.Data, layers.LinkType(pkt.LinkType), gopacket.Default)

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
