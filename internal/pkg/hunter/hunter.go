package hunter

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
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
	// Flow control settings
	MaxBufferedBatches int           // Max batches to buffer before blocking (0 = unlimited)
	SendTimeout        time.Duration // Timeout for sending batches (0 = no timeout)
	// VoIP filtering
	EnableVoIPFilter bool   // Enable VoIP filtering with GPU acceleration
	GPUBackend       string // GPU backend: "auto", "cuda", "opencl", "cpu-simd"
	GPUBatchSize     int    // Batch size for GPU processing
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

	// Flow control
	batchQueue     chan []*data.CapturedPacket
	batchQueueSize atomic.Int32

	// Statistics
	stats Stats
	mu    sync.RWMutex

	// Filters
	filters    []*management.Filter
	voipFilter *VoIPFilter // GPU-accelerated VoIP filter

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
// All fields use atomic operations - no mutex required
type Stats struct {
	PacketsCaptured  atomic.Uint64
	PacketsMatched   atomic.Uint64
	PacketsForwarded atomic.Uint64
	PacketsDropped   atomic.Uint64
	BufferBytes      atomic.Uint64
}

// New creates a new hunter instance
func New(config Config) (*Hunter, error) {
	if config.ProcessorAddr == "" {
		return nil, fmt.Errorf("processor address is required")
	}

	if config.HunterID == "" {
		return nil, fmt.Errorf("hunter ID is required")
	}

	// Set defaults for flow control if not configured
	if config.MaxBufferedBatches == 0 {
		config.MaxBufferedBatches = 10 // Default: buffer up to 10 batches
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = 5 * time.Second // Default: 5s timeout
	}

	h := &Hunter{
		config:               config,
		currentBatch:         make([]*data.CapturedPacket, 0, config.BatchSize),
		maxReconnectAttempts: 0, // 0 = infinite reconnect attempts
		reconnectAttempts:    0,
		reconnecting:         false,
		batchQueue:           make(chan []*data.CapturedPacket, config.MaxBufferedBatches),
	}

	return h, nil
}

// Start begins hunter operation
func (h *Hunter) Start(ctx context.Context) error {
	h.ctx, h.cancel = context.WithCancel(ctx)
	defer h.cancel()

	logger.Info("Hunter starting", "hunter_id", h.config.HunterID)

	// Initialize VoIP filter if enabled
	if h.config.EnableVoIPFilter {
		gpuConfig := &voip.GPUConfig{
			Enabled:      true,
			DeviceID:     0,
			Backend:      h.config.GPUBackend,
			MaxBatchSize: h.config.GPUBatchSize,
			PinnedMemory: true,
			StreamCount:  4,
		}

		voipFilter, err := NewVoIPFilter(gpuConfig)
		if err != nil {
			logger.Warn("Failed to initialize VoIP filter, continuing without it", "error", err)
		} else {
			h.voipFilter = voipFilter
			logger.Info("VoIP filter initialized",
				"gpu_backend", h.config.GPUBackend,
				"batch_size", h.config.GPUBatchSize)
		}
	}
	defer func() {
		if h.voipFilter != nil {
			h.voipFilter.Close()
		}
	}()

	// Start packet capture first (works independently of processor connection)
	if err := h.startCapture(); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}
	defer func() {
		if h.captureCancel != nil {
			h.captureCancel()
		}
	}()

	// Start connection manager (handles initial connect and reconnections)
	h.wg.Add(1)
	go h.connectionManager()

	logger.Info("Hunter started successfully", "hunter_id", h.config.HunterID)

	// Wait for shutdown
	<-h.ctx.Done()

	// Wait for goroutines
	h.wg.Wait()

	// Cleanup connections
	h.cleanup()

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

	// Get local IP address - prefer the capture interface IP
	hostname := getInterfaceIP(h.config.Interfaces)
	logger.Info("Detected IP from capture interface", "ip", hostname)

	if hostname == "" {
		// Fallback to connection-based detection
		hostname = getConnectionLocalIP(h.managementConn)
		logger.Info("Using connection local IP", "ip", hostname)
	}

	if hostname == "" {
		logger.Warn("Failed to detect local IP, using hunter ID as hostname")
		hostname = h.config.HunterID // Final fallback to hunter ID
	}

	req := &management.HunterRegistration{
		HunterId:   h.config.HunterID,
		Hostname:   hostname,
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

			// Use atomic increment - no mutex needed
			h.stats.PacketsCaptured.Add(1)

			// Apply VoIP filter if enabled
			if h.voipFilter != nil {
				if !h.voipFilter.MatchPacket(pktInfo.Packet) {
					// Packet didn't match VoIP filter - skip it
					continue
				}
				// Packet matched - count it
				h.stats.PacketsMatched.Add(1)
			}

			// Convert to protobuf packet
			pbPkt := h.convertPacket(pktInfo)

			// Add to current batch with minimal lock duration
			h.batchMu.Lock()
			h.currentBatch = append(h.currentBatch, pbPkt)
			batchLen := len(h.currentBatch)
			h.batchMu.Unlock()

			// Check size outside lock
			if batchLen >= h.config.BatchSize {
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
			TotalCaptured:   h.stats.PacketsCaptured.Load(),
			FilteredMatched: h.stats.PacketsMatched.Load(),
			Dropped:         h.stats.PacketsDropped.Load(),
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
		// Use atomic add - no mutex needed
		h.stats.PacketsDropped.Add(uint64(len(batch.Packets)))
		return
	}

	logger.Debug("Sent packet batch",
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))

	// Use atomic add - no mutex needed
	h.stats.PacketsForwarded.Add(uint64(len(batch.Packets)))
}

// batchSender sends queued batches to the processor with flow control
func (h *Hunter) batchSender() {
	defer h.wg.Done()

	for {
		select {
		case <-h.ctx.Done():
			return

		case packets := <-h.batchQueue:
			h.batchQueueSize.Add(-1)

			// Get stream
			h.streamMu.Lock()
			stream := h.stream
			h.streamMu.Unlock()

			if stream == nil {
				logger.Warn("Stream not available, dropping queued batch")
				h.stats.PacketsDropped.Add(uint64(len(packets)))
				continue
			}

			// Build batch for sending
			batch := &data.PacketBatch{
				HunterId:    h.config.HunterID,
				Sequence:    h.batchSequence,
				TimestampNs: time.Now().UnixNano(),
				Packets:     packets,
			}

			if err := stream.Send(batch); err != nil {
				logger.Error("Failed to send batch", "error", err)
				h.stats.PacketsDropped.Add(uint64(len(packets)))
				continue
			}

			logger.Debug("Sent packet batch", "packets", len(packets))
			h.stats.PacketsForwarded.Add(uint64(len(packets)))
		}
	}
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

	// Use a channel with timeout to prevent goroutine leak
	updateCh := make(chan *management.FilterUpdate, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			update, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			updateCh <- update
		}
	}()

	// Read with periodic timeout check
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			logger.Info("Filter subscription closed (context)")
			return

		case err := <-errCh:
			if err == io.EOF {
				logger.Info("Filter subscription closed by processor")
			} else {
				logger.Error("Filter subscription error", "error", err)
			}
			h.markDisconnected()
			return

		case update := <-updateCh:
			h.handleFilterUpdate(update)

		case <-ticker.C:
			// Periodic keepalive check
			if h.ctx.Err() != nil {
				return
			}
		}
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

	// Separate goroutine for receiving responses to prevent blocking
	respCh := make(chan *management.ProcessorHeartbeat, 1)
	respErrCh := make(chan error, 1)

	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				respErrCh <- err
				return
			}
			respCh <- resp
		}
	}()

	for {
		select {
		case <-h.ctx.Done():
			logger.Info("Heartbeat stream closed")
			return

		case err := <-respErrCh:
			if h.ctx.Err() != nil {
				return
			}
			logger.Error("Heartbeat stream error", "error", err)
			h.markDisconnected()
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
					PacketsCaptured:  h.stats.PacketsCaptured.Load(),
					PacketsMatched:   h.stats.PacketsMatched.Load(),
					PacketsForwarded: h.stats.PacketsForwarded.Load(),
					PacketsDropped:   h.stats.PacketsDropped.Load(),
					BufferBytes:      h.stats.BufferBytes.Load(),
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

		case resp := <-respCh:
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
	captured := h.stats.PacketsCaptured.Load()
	if captured > 0 {
		dropped := h.stats.PacketsDropped.Load()
		dropRate := (dropped * 100) / captured
		if dropRate > 10 {
			return management.HunterStatus_STATUS_WARNING
		}
	}

	return management.HunterStatus_STATUS_HEALTHY
}

// connectionManager manages processor connection lifecycle
func (h *Hunter) connectionManager() {
	defer h.wg.Done()

	logger.Info("Connection manager started")

	// Attempt initial connection with retries
	for {
		select {
		case <-h.ctx.Done():
			return
		default:
		}

		err := h.connectAndRegister()
		if err == nil {
			// Successfully connected
			logger.Info("Connected to processor")

			// Start connection-dependent goroutines
			h.wg.Add(5)
			go h.forwardPackets()
			go h.handleStreamControl()
			go h.subscribeToFilters()
			go h.sendHeartbeats()
			go h.batchSender() // Flow-controlled batch sender

			// Monitor for disconnection
			h.monitorConnection()

			// If we get here, connection was lost
			logger.Warn("Connection to processor lost, will retry")
			continue
		}

		// Connection failed
		logger.Error("Failed to connect to processor", "error", err)

		// Exponential backoff
		h.reconnectMu.Lock()
		h.reconnectAttempts++
		attempts := h.reconnectAttempts
		h.reconnectMu.Unlock()

		if h.maxReconnectAttempts > 0 && attempts >= h.maxReconnectAttempts {
			logger.Error("Max reconnection attempts reached, giving up",
				"attempts", attempts,
				"max", h.maxReconnectAttempts)
			h.cancel()
			return
		}

		backoff := time.Duration(1<<uint(min(attempts-1, 6))) * time.Second
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}

		logger.Info("Retrying connection",
			"attempt", attempts,
			"backoff", backoff)

		select {
		case <-time.After(backoff):
		case <-h.ctx.Done():
			return
		}
	}
}

// monitorConnection monitors for disconnections
func (h *Hunter) monitorConnection() {
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
				// Cleanup old connections
				h.cleanup()
				// Return to let connectionManager retry
				return
			}
		}
	}
}

// min returns minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

// GetStats returns current statistics snapshot
func (h *Hunter) GetStats() Stats {
	// No mutex needed - atomic loads are safe
	// Return a snapshot with current values
	return Stats{
		PacketsCaptured:  atomic.Uint64{},
		PacketsMatched:   atomic.Uint64{},
		PacketsForwarded: atomic.Uint64{},
		PacketsDropped:   atomic.Uint64{},
		BufferBytes:      atomic.Uint64{},
	}
}

// GetStatsValues returns current statistics as plain uint64 values
func (h *Hunter) GetStatsValues() (captured, matched, forwarded, dropped, bufferBytes uint64) {
	return h.stats.PacketsCaptured.Load(),
		h.stats.PacketsMatched.Load(),
		h.stats.PacketsForwarded.Load(),
		h.stats.PacketsDropped.Load(),
		h.stats.BufferBytes.Load()
}

// getConnectionLocalIP returns the local IP address used for the gRPC connection
// This returns the IP address that the processor sees the hunter connecting from
func getConnectionLocalIP(conn *grpc.ClientConn) string {
	if conn == nil {
		logger.Debug("getConnectionLocalIP: conn is nil")
		return ""
	}

	// Parse the target address to determine what we're connecting to
	target := conn.Target()
	logger.Debug("getConnectionLocalIP: target", "target", target)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// Try to parse as just host (might not have port in Target())
		// Use a dummy port for the UDP dial
		logger.Debug("getConnectionLocalIP: failed to split host:port, using target as host", "error", err)
		host = target
		port = "1"
	}
	if port == "" {
		port = "1"
	}

	// Check if the target is a loopback address
	resolvedIPs, err := net.LookupIP(host)
	if err == nil && len(resolvedIPs) > 0 {
		targetIP := resolvedIPs[0]
		logger.Debug("getConnectionLocalIP: resolved target", "host", host, "ip", targetIP.String())

		// If connecting to loopback, we need to find our actual network IP
		if targetIP.IsLoopback() {
			logger.Debug("getConnectionLocalIP: target is loopback, finding non-loopback IP")
			return getFirstNonLoopbackIP()
		}
	}

	dialAddr := net.JoinHostPort(host, port)
	logger.Debug("getConnectionLocalIP: dialing UDP", "addr", dialAddr)

	// Dial a temporary UDP connection to see which local IP would be used
	// UDP doesn't actually send packets, so this is lightweight
	udpConn, err := net.Dial("udp", dialAddr)
	if err != nil {
		logger.Debug("getConnectionLocalIP: failed to dial UDP", "error", err)
		return ""
	}
	defer udpConn.Close()

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	// Double-check if we got a loopback IP even for non-loopback target
	if localAddr.IP.IsLoopback() {
		logger.Debug("getConnectionLocalIP: got loopback IP, finding non-loopback IP")
		return getFirstNonLoopbackIP()
	}

	logger.Debug("getConnectionLocalIP: detected IP", "ip", ip)
	return ip
}

// getFirstNonLoopbackIP returns the first non-loopback IPv4 address
func getFirstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger.Debug("getFirstNonLoopbackIP: failed to get interfaces", "error", err)
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			// Prefer IPv4
			if ipnet.IP.To4() != nil {
				logger.Debug("getFirstNonLoopbackIP: found IPv4", "ip", ipnet.IP.String())
				return ipnet.IP.String()
			}
		}
	}

	logger.Debug("getFirstNonLoopbackIP: no non-loopback IPv4 found")
	return ""
}

// getInterfaceIP returns the IP address of the capture interface
// If multiple interfaces or "any", returns the first non-loopback IP
func getInterfaceIP(interfaces []string) string {
	if len(interfaces) == 0 {
		logger.Debug("getInterfaceIP: no interfaces specified")
		return ""
	}

	// If interface is "any" or multiple interfaces, use first non-loopback IP
	if len(interfaces) > 1 || interfaces[0] == "any" {
		logger.Debug("getInterfaceIP: multiple interfaces or 'any', using first non-loopback IP")
		return getFirstNonLoopbackIP()
	}

	// Get the specific interface
	ifaceName := interfaces[0]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logger.Debug("getInterfaceIP: failed to get interface", "interface", ifaceName, "error", err)
		return ""
	}

	// Get addresses for this interface
	addrs, err := iface.Addrs()
	if err != nil {
		logger.Debug("getInterfaceIP: failed to get interface addresses", "interface", ifaceName, "error", err)
		return ""
	}

	// Find first IPv4 address
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				logger.Debug("getInterfaceIP: found IPv4 on interface", "interface", ifaceName, "ip", ipnet.IP.String())
				return ipnet.IP.String()
			}
		}
	}

	logger.Debug("getInterfaceIP: no IPv4 found on interface", "interface", ifaceName)
	return ""
}
