package hunter

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/tcpassembly"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config contains hunter configuration
type Config struct {
	ProcessorAddr string
	HunterID      string
	Interfaces    []string
	BPFFilter     string
	BufferSize    int
	BatchSize     int
	BatchTimeout  time.Duration
}

// Hunter represents a hunter node
type Hunter struct {
	config Config

	// gRPC connections
	dataConn       *grpc.ClientConn
	managementConn *grpc.ClientConn
	dataClient     data.DataServiceClient
	mgmtClient     management.ManagementServiceClient

	// Packet capture
	packetBuffer  *capture.PacketBuffer
	captureCtx    context.Context
	captureCancel context.CancelFunc

	// Packet streaming
	stream         data.DataService_StreamPacketsClient
	streamMu       sync.Mutex

	// Packet batching
	batchMu       sync.Mutex
	currentBatch  []*data.CapturedPacket
	batchSequence uint64

	// Statistics
	stats Stats
	mu    sync.RWMutex

	// Filters
	filters []*management.Filter

	// Reconnection
	reconnectAttempts int
	maxReconnectAttempts int
	reconnecting     bool
	reconnectMu      sync.Mutex

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Stats contains hunter statistics
type Stats struct {
	PacketsCaptured  uint64
	PacketsMatched   uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	BufferBytes      uint64
}

// New creates a new hunter instance
func New(config Config) (*Hunter, error) {
	if config.ProcessorAddr == "" {
		return nil, fmt.Errorf("processor address is required")
	}

	if config.HunterID == "" {
		return nil, fmt.Errorf("hunter ID is required")
	}

	h := &Hunter{
		config:               config,
		currentBatch:         make([]*data.CapturedPacket, 0, config.BatchSize),
		maxReconnectAttempts: 10, // Max 10 reconnect attempts
		reconnectAttempts:    0,
		reconnecting:         false,
	}

	return h, nil
}

// Start begins hunter operation
func (h *Hunter) Start(ctx context.Context) error {
	h.ctx, h.cancel = context.WithCancel(ctx)
	defer h.cancel()

	logger.Info("Hunter starting", "hunter_id", h.config.HunterID)

	// Initial connection
	if err := h.connectAndRegister(); err != nil {
		return fmt.Errorf("failed initial connection: %w", err)
	}
	defer h.cleanup()

	// Start packet capture (only once, persists through reconnections)
	if err := h.startCapture(); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// Start packet forwarder and control handlers
	h.wg.Add(5)
	go h.forwardPackets()
	go h.handleStreamControl()
	go h.subscribeToFilters()
	go h.sendHeartbeats()
	go h.monitorConnection() // New: monitor for disconnections

	logger.Info("Hunter started successfully", "hunter_id", h.config.HunterID)

	// Wait for shutdown
	<-h.ctx.Done()

	// Stop capture
	if h.captureCancel != nil {
		h.captureCancel()
	}

	// Wait for goroutines
	h.wg.Wait()

	logger.Info("Hunter stopped", "hunter_id", h.config.HunterID)
	return nil
}

// connectAndRegister connects to processor and registers
func (h *Hunter) connectAndRegister() error {
	// Connect to processor
	if err := h.connectToProcessor(); err != nil {
		return fmt.Errorf("failed to connect to processor: %w", err)
	}

	// Register with processor
	if err := h.register(); err != nil {
		return fmt.Errorf("failed to register with processor: %w", err)
	}

	// Start packet streaming
	if err := h.startStreaming(); err != nil {
		return fmt.Errorf("failed to start streaming: %w", err)
	}

	// Reset reconnect attempts on successful connection
	h.reconnectMu.Lock()
	h.reconnectAttempts = 0
	h.reconnecting = false
	h.reconnectMu.Unlock()

	return nil
}

// connectToProcessor establishes gRPC connections
func (h *Hunter) connectToProcessor() error {
	logger.Info("Connecting to processor", "addr", h.config.ProcessorAddr)

	// For now, use insecure connection (TLS can be added later)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10 * 1024 * 1024)), // 10MB
	}

	// Connect data channel
	dataConn, err := grpc.Dial(h.config.ProcessorAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial processor data: %w", err)
	}
	h.dataConn = dataConn
	h.dataClient = data.NewDataServiceClient(dataConn)

	// Connect management channel (same address for now, different service)
	mgmtConn, err := grpc.Dial(h.config.ProcessorAddr, opts...)
	if err != nil {
		dataConn.Close()
		return fmt.Errorf("failed to dial processor management: %w", err)
	}
	h.managementConn = mgmtConn
	h.mgmtClient = management.NewManagementServiceClient(mgmtConn)

	logger.Info("Connected to processor", "addr", h.config.ProcessorAddr)
	return nil
}

// register registers hunter with processor
func (h *Hunter) register() error {
	logger.Info("Registering with processor", "hunter_id", h.config.HunterID)

	req := &management.HunterRegistration{
		HunterId:   h.config.HunterID,
		Hostname:   h.config.HunterID, // TODO: get actual hostname
		Interfaces: h.config.Interfaces,
		Version:    "0.1.0", // TODO: version from build
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"sip_user", "phone_number", "ip_address"},
			MaxBufferSize:   uint64(h.config.BufferSize * 2048), // Assume 2KB avg packet
			GpuAcceleration: false,                              // TODO: detect GPU
			AfXdp:           false,                              // TODO: detect AF_XDP
		},
	}

	resp, err := h.mgmtClient.RegisterHunter(h.ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Error)
	}

	logger.Info("Registration accepted",
		"assigned_id", resp.AssignedId,
		"initial_filters", len(resp.Filters))

	// Store initial filters
	h.filters = resp.Filters

	return nil
}

// startStreaming establishes the bidirectional packet stream
func (h *Hunter) startStreaming() error {
	logger.Info("Starting packet stream to processor")

	stream, err := h.dataClient.StreamPackets(h.ctx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	h.streamMu.Lock()
	h.stream = stream
	h.streamMu.Unlock()

	logger.Info("Packet stream established")
	return nil
}

// startCapture begins packet capture
func (h *Hunter) startCapture() error {
	logger.Info("Starting packet capture",
		"interfaces", h.config.Interfaces,
		"filter", h.config.BPFFilter)

	// Create capture context
	h.captureCtx, h.captureCancel = context.WithCancel(h.ctx)

	// Create packet buffer
	h.packetBuffer = capture.NewPacketBuffer(h.captureCtx, h.config.BufferSize)

	// Create PCAP interfaces
	var devices []pcaptypes.PcapInterface
	for _, iface := range h.config.Interfaces {
		for _, device := range strings.Split(iface, ",") {
			devices = append(devices, pcaptypes.CreateLiveInterface(device))
		}
	}

	// Start capture in background
	go func() {
		// Use simplified packet processor
		processor := func(ch <-chan capture.PacketInfo, asm *tcpassembly.Assembler) {
			for pkt := range ch {
				// Forward to packet buffer
				h.packetBuffer.Send(pkt)
			}
		}

		capture.InitWithContext(h.captureCtx, devices, h.config.BPFFilter, processor, nil)
	}()

	logger.Info("Packet capture started", "interfaces", h.config.Interfaces)
	return nil
}

// forwardPackets reads from packet buffer and forwards batches to processor
func (h *Hunter) forwardPackets() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.BatchTimeout)
	defer ticker.Stop()

	logger.Info("Packet forwarding started",
		"batch_size", h.config.BatchSize,
		"batch_timeout", h.config.BatchTimeout)

	for {
		select {
		case <-h.ctx.Done():
			// Send remaining batch before shutdown
			h.sendBatch()
			return

		case pktInfo, ok := <-h.packetBuffer.Receive():
			if !ok {
				// Channel closed
				h.sendBatch()
				return
			}

			h.mu.Lock()
			h.stats.PacketsCaptured++
			h.mu.Unlock()

			// Convert to protobuf packet
			pbPkt := h.convertPacket(pktInfo)

			// Add to current batch
			h.batchMu.Lock()
			h.currentBatch = append(h.currentBatch, pbPkt)
			shouldSend := len(h.currentBatch) >= h.config.BatchSize
			h.batchMu.Unlock()

			if shouldSend {
				h.sendBatch()
			}

		case <-ticker.C:
			// Send batch on timeout
			h.sendBatch()
		}
	}
}

// sendBatch sends the current batch to processor
func (h *Hunter) sendBatch() {
	h.batchMu.Lock()
	if len(h.currentBatch) == 0 {
		h.batchMu.Unlock()
		return
	}

	// Create batch message
	h.batchSequence++
	batch := &data.PacketBatch{
		HunterId:    h.config.HunterID,
		Sequence:    h.batchSequence,
		TimestampNs: time.Now().UnixNano(),
		Packets:     h.currentBatch,
		Stats: &data.BatchStats{
			TotalCaptured:   h.stats.PacketsCaptured,
			FilteredMatched: h.stats.PacketsMatched,
			Dropped:         h.stats.PacketsDropped,
			BufferUsage:     uint32(len(h.packetBuffer.Receive()) * 100 / h.config.BufferSize),
		},
	}

	// Reset batch
	h.currentBatch = make([]*data.CapturedPacket, 0, h.config.BatchSize)
	h.batchMu.Unlock()

	// Send via stream
	h.streamMu.Lock()
	stream := h.stream
	h.streamMu.Unlock()

	if stream == nil {
		logger.Warn("Stream not available, dropping batch")
		return
	}

	if err := stream.Send(batch); err != nil {
		logger.Error("Failed to send batch", "error", err, "sequence", batch.Sequence)
		h.mu.Lock()
		h.stats.PacketsDropped += uint64(len(batch.Packets))
		h.mu.Unlock()
		return
	}

	logger.Debug("Sent packet batch",
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	h.mu.Lock()
	h.stats.PacketsForwarded += uint64(len(batch.Packets))
	h.mu.Unlock()
}

// handleStreamControl receives flow control messages from processor
func (h *Hunter) handleStreamControl() {
	defer h.wg.Done()

	h.streamMu.Lock()
	stream := h.stream
	h.streamMu.Unlock()

	if stream == nil {
		logger.Error("Stream not available for control messages")
		return
	}

	for {
		ctrl, err := stream.Recv()
		if err == io.EOF {
			logger.Info("Stream closed by processor")
			h.markDisconnected()
			return
		}
		if err != nil {
			if h.ctx.Err() != nil {
				// Context canceled, normal shutdown
				return
			}
			logger.Error("Stream control error", "error", err)
			h.markDisconnected()
			return
		}

		logger.Debug("Received flow control",
			"ack_sequence", ctrl.AckSequence,
			"flow_control", ctrl.FlowControl)

		// TODO: Implement flow control logic
		// For now, just log acknowledgments
	}
}

// convertPacket converts capture.PacketInfo to protobuf format
func (h *Hunter) convertPacket(pktInfo capture.PacketInfo) *data.CapturedPacket {
	pkt := pktInfo.Packet

	captureLen := 0
	originalLen := 0
	var packetData []byte

	if pkt != nil {
		if pkt.Data() != nil {
			packetData = pkt.Data()
			captureLen = len(packetData)
		}
		if meta := pkt.Metadata(); meta != nil {
			captureLen = meta.CaptureLength
			originalLen = meta.Length
		}
	}

	return &data.CapturedPacket{
		Data:           packetData,
		TimestampNs:    time.Now().UnixNano(),
		CaptureLength:  uint32(captureLen),
		OriginalLength: uint32(originalLen),
		InterfaceIndex: 0,
		LinkType:       uint32(pktInfo.LinkType),
		// TODO: Add metadata extraction (SIP, RTP, etc.)
	}
}

// cleanup closes connections
func (h *Hunter) cleanup() {
	if h.packetBuffer != nil {
		h.packetBuffer.Close()
	}

	h.streamMu.Lock()
	if h.stream != nil {
		h.stream.CloseSend()
	}
	h.streamMu.Unlock()

	if h.dataConn != nil {
		h.dataConn.Close()
	}

	if h.managementConn != nil {
		h.managementConn.Close()
	}
}

// subscribeToFilters subscribes to filter updates from processor
func (h *Hunter) subscribeToFilters() {
	defer h.wg.Done()

	logger.Info("Subscribing to filter updates")

	req := &management.FilterRequest{
		HunterId: h.config.HunterID,
	}

	stream, err := h.mgmtClient.SubscribeFilters(h.ctx, req)
	if err != nil {
		logger.Error("Failed to subscribe to filters", "error", err)
		return
	}

	logger.Info("Filter subscription established")

	for {
		update, err := stream.Recv()
		if err == io.EOF {
			logger.Info("Filter subscription closed by processor")
			h.markDisconnected()
			return
		}
		if err != nil {
			if h.ctx.Err() != nil {
				logger.Info("Filter subscription closed")
				return
			}
			logger.Error("Filter subscription error", "error", err)
			h.markDisconnected()
			return
		}

		h.handleFilterUpdate(update)
	}
}

// handleFilterUpdate applies filter updates from processor
func (h *Hunter) handleFilterUpdate(update *management.FilterUpdate) {
	logger.Info("Received filter update",
		"type", update.UpdateType,
		"filter_id", update.Filter.Id,
		"filter_type", update.Filter.Type)

	h.mu.Lock()
	defer h.mu.Unlock()

	switch update.UpdateType {
	case management.FilterUpdateType_UPDATE_ADD:
		// Add new filter
		h.filters = append(h.filters, update.Filter)
		logger.Info("Filter added",
			"filter_id", update.Filter.Id,
			"pattern", update.Filter.Pattern)

	case management.FilterUpdateType_UPDATE_MODIFY:
		// Modify existing filter
		for i, f := range h.filters {
			if f.Id == update.Filter.Id {
				h.filters[i] = update.Filter
				logger.Info("Filter modified",
					"filter_id", update.Filter.Id,
					"pattern", update.Filter.Pattern)
				return
			}
		}
		logger.Warn("Filter to modify not found", "filter_id", update.Filter.Id)

	case management.FilterUpdateType_UPDATE_DELETE:
		// Delete filter
		for i, f := range h.filters {
			if f.Id == update.Filter.Id {
				h.filters = append(h.filters[:i], h.filters[i+1:]...)
				logger.Info("Filter deleted", "filter_id", update.Filter.Id)
				return
			}
		}
		logger.Warn("Filter to delete not found", "filter_id", update.Filter.Id)
	}

	// TODO: Apply filters to packet processing logic
	// For now, filters are just stored and logged
	logger.Debug("Active filters count", "count", len(h.filters))
}

// sendHeartbeats sends periodic heartbeat to processor
func (h *Hunter) sendHeartbeats() {
	defer h.wg.Done()

	logger.Info("Starting heartbeat stream to processor")

	stream, err := h.mgmtClient.Heartbeat(h.ctx)
	if err != nil {
		logger.Error("Failed to create heartbeat stream", "error", err)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	logger.Info("Heartbeat stream established")

	for {
		select {
		case <-h.ctx.Done():
			logger.Info("Heartbeat stream closed")
			return

		case <-ticker.C:
			// Determine hunter status based on current state
			status := h.calculateStatus()

			// Send heartbeat
			hb := &management.HunterHeartbeat{
				HunterId:    h.config.HunterID,
				TimestampNs: time.Now().UnixNano(),
				Status:      status,
				Stats: &management.HunterStats{
					PacketsCaptured:  h.stats.PacketsCaptured,
					PacketsMatched:   h.stats.PacketsMatched,
					PacketsForwarded: h.stats.PacketsForwarded,
					PacketsDropped:   h.stats.PacketsDropped,
					BufferBytes:      h.stats.BufferBytes,
					ActiveFilters:    uint32(len(h.filters)),
				},
			}

			if err := stream.Send(hb); err != nil {
				if h.ctx.Err() != nil {
					return
				}
				logger.Error("Failed to send heartbeat", "error", err)
				h.markDisconnected()
				return
			}

			// Receive response
			resp, err := stream.Recv()
			if err != nil {
				if h.ctx.Err() != nil {
					return
				}
				logger.Error("Failed to receive heartbeat response", "error", err)
				h.markDisconnected()
				return
			}

			logger.Debug("Heartbeat acknowledged",
				"processor_status", resp.Status,
				"hunters_connected", resp.HuntersConnected)
		}
	}
}

// calculateStatus determines hunter health status
func (h *Hunter) calculateStatus() management.HunterStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Check if we're shutting down
	if h.ctx.Err() != nil {
		return management.HunterStatus_STATUS_STOPPING
	}

	// Check buffer usage
	if h.packetBuffer != nil {
		bufferChan := h.packetBuffer.Receive()
		bufferUsage := len(bufferChan)
		bufferCapacity := cap(bufferChan)

		if bufferCapacity > 0 {
			usagePercent := (bufferUsage * 100) / bufferCapacity

			// Buffer filling up (>80%)
			if usagePercent > 80 {
				return management.HunterStatus_STATUS_WARNING
			}
		}
	}

	// Check for excessive drops
	if h.stats.PacketsCaptured > 0 {
		dropRate := (h.stats.PacketsDropped * 100) / h.stats.PacketsCaptured
		if dropRate > 10 {
			return management.HunterStatus_STATUS_WARNING
		}
	}

	return management.HunterStatus_STATUS_HEALTHY
}

// monitorConnection monitors for disconnections and triggers reconnection
func (h *Hunter) monitorConnection() {
	defer h.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-ticker.C:
			// Check if we need to reconnect
			h.reconnectMu.Lock()
			needsReconnect := h.reconnecting
			h.reconnectMu.Unlock()

			if needsReconnect {
				h.attemptReconnect()
			}
		}
	}
}

// attemptReconnect attempts to reconnect to processor with exponential backoff
func (h *Hunter) attemptReconnect() {
	h.reconnectMu.Lock()

	// Check if we've exceeded max attempts
	if h.reconnectAttempts >= h.maxReconnectAttempts {
		h.reconnectMu.Unlock()
		logger.Error("Max reconnection attempts reached, giving up",
			"attempts", h.reconnectAttempts,
			"max", h.maxReconnectAttempts)
		h.cancel() // Trigger shutdown
		return
	}

	h.reconnectAttempts++
	attempts := h.reconnectAttempts
	h.reconnectMu.Unlock()

	// Exponential backoff: 2^attempt seconds, max 60s
	backoff := time.Duration(1<<uint(attempts-1)) * time.Second
	if backoff > 60*time.Second {
		backoff = 60 * time.Second
	}

	logger.Info("Attempting reconnection",
		"attempt", attempts,
		"max", h.maxReconnectAttempts,
		"backoff", backoff)

	// Wait for backoff period
	select {
	case <-time.After(backoff):
	case <-h.ctx.Done():
		return
	}

	// Cleanup old connections
	h.cleanup()

	// Attempt to reconnect
	if err := h.connectAndRegister(); err != nil {
		logger.Error("Reconnection failed", "error", err, "attempt", attempts)
		return
	}

	logger.Info("Reconnection successful", "attempt", attempts)

	// Restart goroutines that depend on connection
	h.wg.Add(3)
	go h.handleStreamControl()
	go h.subscribeToFilters()
	go h.sendHeartbeats()
}

// markDisconnected marks the hunter as disconnected and triggers reconnection
func (h *Hunter) markDisconnected() {
	h.reconnectMu.Lock()
	defer h.reconnectMu.Unlock()

	if h.reconnecting {
		// Already reconnecting
		return
	}

	h.reconnecting = true
	logger.Warn("Connection lost, will attempt reconnection")
}

// GetStats returns current statistics
func (h *Hunter) GetStats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}
