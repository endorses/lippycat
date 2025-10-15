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
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// PacketProcessor is an optional interface for custom packet processing
// before packets are forwarded to the processor. This allows VoIP mode
// to buffer and filter packets based on call state.
type PacketProcessor interface {
	// ProcessPacket processes a packet and returns true if it should be forwarded immediately.
	// If false, the packet may be buffered or dropped by the processor.
	ProcessPacket(pktInfo capture.PacketInfo) bool
}

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
	// TLS settings
	TLSEnabled            bool   // Enable TLS encryption for gRPC connections
	TLSCertFile           string // Path to TLS certificate file (for server verification)
	TLSKeyFile            string // Path to TLS key file (for mutual TLS)
	TLSCAFile             string // Path to CA certificate file
	TLSSkipVerify         bool   // Skip certificate verification (insecure, for testing only)
	TLSServerNameOverride string // Override server name for TLS verification (testing only)
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
	stream   data.DataService_StreamPacketsClient
	streamMu sync.Mutex

	// Packet batching
	batchMu       sync.Mutex
	currentBatch  []*data.CapturedPacket
	batchSequence uint64

	// Flow control
	batchQueue       chan []*data.CapturedPacket
	batchQueueSize   atomic.Int32
	flowControlState atomic.Int32 // FlowControl enum value
	paused           atomic.Bool  // Whether sending is paused

	// Statistics
	stats Stats
	mu    sync.RWMutex

	// Filters
	filters    []*management.Filter
	voipFilter *VoIPFilter // GPU-accelerated VoIP filter

	// Custom packet processing
	packetProcessor PacketProcessor // Optional custom processor for VoIP buffering, etc.

	// Reconnection
	reconnectAttempts    int
	maxReconnectAttempts int
	reconnecting         bool
	reconnectMu          sync.Mutex

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Connection-scoped control (for managing goroutine lifecycle during reconnects)
	connCtx    context.Context
	connCancel context.CancelFunc
	connWg     sync.WaitGroup
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

// SetPacketProcessor sets a custom packet processor for this hunter.
// This should be called before Start() to enable custom packet handling.
func (h *Hunter) SetPacketProcessor(processor PacketProcessor) {
	h.packetProcessor = processor
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

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(constants.MaxGRPCMessageSize)),
	}

	// Configure TLS or insecure credentials
	if h.config.TLSEnabled {
		tlsCreds, err := h.buildTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
		logger.Info("Using TLS for gRPC connection", "skip_verify", h.config.TLSSkipVerify)
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Warn("Using insecure gRPC connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext")
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
		_ = dataConn.Close()
		return fmt.Errorf("failed to dial processor management: %w", err)
	}
	h.managementConn = mgmtConn
	h.mgmtClient = management.NewManagementServiceClient(mgmtConn)

	logger.Info("Connected to processor", "addr", h.config.ProcessorAddr, "tls", h.config.TLSEnabled)
	return nil
}

// buildTLSCredentials creates TLS credentials for gRPC client
func (h *Hunter) buildTLSCredentials() (credentials.TransportCredentials, error) {
	return tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile:             h.config.TLSCAFile,
		CertFile:           h.config.TLSCertFile,
		KeyFile:            h.config.TLSKeyFile,
		SkipVerify:         h.config.TLSSkipVerify,
		ServerNameOverride: h.config.TLSServerNameOverride,
	})
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
			MaxBufferSize:   uint64(h.config.BufferSize * 2048), // #nosec G115 - Assume 2KB avg packet
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
	h.mu.Lock()
	h.filters = resp.Filters
	h.mu.Unlock()

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

	// Start goroutine to receive flow control messages from processor
	h.connWg.Add(1)
	go h.receiveStreamControl(stream)

	logger.Info("Packet stream established with flow control")
	return nil
}

// receiveStreamControl receives and processes flow control messages from processor
func (h *Hunter) receiveStreamControl(stream data.DataService_StreamPacketsClient) {
	defer h.connWg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in receiveStreamControl", "panic", r)
		}
	}()

	for {
		select {
		case <-h.connCtx.Done():
			logger.Debug("receiveStreamControl: connection context cancelled, exiting")
			return
		case <-h.ctx.Done():
			logger.Debug("receiveStreamControl: context cancelled, exiting")
			return
		default:
			ctrl, err := stream.Recv()
			if err != nil {
				// Check if we're shutting down
				if h.ctx.Err() != nil || h.connCtx.Err() != nil {
					logger.Debug("receiveStreamControl: error during shutdown, exiting gracefully", "error", err)
					return
				}
				logger.Error("Stream control receive error", "error", err)
				return
			}

			// Process flow control signal
			h.handleFlowControl(ctrl)
		}
	}
}

// handleFlowControl processes flow control signals from processor
func (h *Hunter) handleFlowControl(ctrl *data.StreamControl) {
	oldState := data.FlowControl(h.flowControlState.Load())
	newState := ctrl.FlowControl

	// Update flow control state
	h.flowControlState.Store(int32(newState))

	// Log state changes
	if oldState != newState {
		logger.Info("Flow control state changed",
			"old_state", oldState,
			"new_state", newState,
			"ack_sequence", ctrl.AckSequence)
	}

	// Handle specific flow control actions
	switch newState {
	case data.FlowControl_FLOW_PAUSE:
		if !h.paused.Load() {
			h.paused.Store(true)
			logger.Warn("Processor requested pause - buffering packets",
				"recommendation", "processor may be overloaded")
		}

	case data.FlowControl_FLOW_RESUME:
		if h.paused.Load() {
			h.paused.Store(false)
			logger.Info("Processor requested resume - sending packets")
		}

	case data.FlowControl_FLOW_SLOW:
		logger.Debug("Processor requested slow down",
			"current_queue_size", h.batchQueueSize.Load())

	case data.FlowControl_FLOW_CONTINUE:
		// Normal operation - no action needed
		logger.Debug("Flow control: continue",
			"ack_sequence", ctrl.AckSequence)
	}

	// Log errors if any
	if ctrl.Error != "" {
		logger.Error("Processor reported error",
			"error", ctrl.Error,
			"ack_sequence", ctrl.AckSequence)
	}
}

// startCapture begins packet capture
func (h *Hunter) startCapture() error {
	// Build combined BPF filter from config and dynamic filters
	bpfFilter := h.buildCombinedBPFFilter()

	logger.Info("Starting packet capture",
		"interfaces", h.config.Interfaces,
		"filter", bpfFilter)

	// Create capture context
	h.captureCtx, h.captureCancel = context.WithCancel(h.ctx)

	// Create packet buffer ONLY on first start
	// Don't recreate on restart - forwardPackets() is already reading from it
	// IMPORTANT: Use h.ctx (main context) not h.captureCtx, so buffer survives capture restarts
	if h.packetBuffer == nil {
		h.packetBuffer = capture.NewPacketBuffer(h.ctx, h.config.BufferSize)
	}

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

		capture.InitWithContext(h.captureCtx, devices, bpfFilter, processor, nil)
	}()

	logger.Info("Packet capture started", "interfaces", h.config.Interfaces)
	return nil
}

// restartCapture stops and restarts packet capture with updated filters
func (h *Hunter) restartCapture() error {
	logger.Info("Restarting packet capture to apply filter changes")

	// Cancel current capture
	if h.captureCancel != nil {
		h.captureCancel()
	}

	// Wait a moment for capture to clean up
	time.Sleep(100 * time.Millisecond)

	// Start new capture with updated filters
	return h.startCapture()
}

// buildCombinedBPFFilter builds a combined BPF filter from config and dynamic filters
func (h *Hunter) buildCombinedBPFFilter() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var dynamicFilters []string

	// Collect dynamic BPF filters (only enabled ones)
	for _, filter := range h.filters {
		if !filter.Enabled {
			continue
		}

		// Only BPF type filters are applied directly
		// Other filter types (SIP user, phone, IP, etc.) would need different handling
		if filter.Type == management.FilterType_FILTER_BPF {
			if filter.Pattern != "" {
				dynamicFilters = append(dynamicFilters, fmt.Sprintf("(%s)", filter.Pattern))
			}
		}
	}

	// Build final filter
	var finalFilter string

	if len(dynamicFilters) == 0 {
		// No dynamic filters - use base config filter only
		finalFilter = h.config.BPFFilter
	} else {
		// Combine dynamic filters with OR (capture matching ANY dynamic filter)
		dynamicPart := strings.Join(dynamicFilters, " or ")

		if h.config.BPFFilter != "" {
			// Combine with base filter using AND
			// Logic: (dynamic filters) AND (base exclusions)
			// Example: (port 443) and (not port 50051 and not port 50052)
			finalFilter = fmt.Sprintf("(%s) and (%s)", dynamicPart, h.config.BPFFilter)
		} else {
			// No base filter - just use dynamic filters
			finalFilter = dynamicPart
		}
	}

	return finalFilter
}

// forwardPackets reads from packet buffer and forwards batches to processor
func (h *Hunter) forwardPackets() {
	defer h.connWg.Done()

	ticker := time.NewTicker(h.config.BatchTimeout)
	defer ticker.Stop()

	logger.Info("Packet forwarding started",
		"batch_size", h.config.BatchSize,
		"batch_timeout", h.config.BatchTimeout)

	for {
		select {
		case <-h.connCtx.Done():
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

			// Apply custom packet processor if set (for VoIP buffering, etc.)
			// The processor returns true if packet should be forwarded immediately
			if h.packetProcessor != nil {
				if !h.packetProcessor.ProcessPacket(pktInfo) {
					// Packet was buffered or filtered out by processor
					continue
				}
				// Packet should be forwarded - count it as matched
				h.stats.PacketsMatched.Add(1)
			} else if h.voipFilter != nil {
				// Fall back to simple VoIP filter if no custom processor
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
	// Check if paused by processor
	if h.paused.Load() {
		logger.Debug("Skipping batch send - paused by processor")
		return
	}

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
			BufferUsage:     uint32(len(h.packetBuffer.Receive()) * 100 / h.config.BufferSize), // #nosec G115 - safe: percentage calculation
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

	// Send with context timeout to prevent blocking indefinitely
	// This avoids goroutine leak that would occur with timeout in select
	sendCtx, sendCancel := context.WithTimeout(h.connCtx, 5*time.Second)
	defer sendCancel()

	// Create a channel to receive the result
	sendDone := make(chan error, constants.ErrorChannelBuffer)
	go func() {
		sendDone <- stream.Send(batch)
	}()

	select {
	case err := <-sendDone:
		if err != nil {
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

	case <-sendCtx.Done():
		// Context cancelled or timed out
		logger.Error("Batch send timeout - processor may be unresponsive",
			"sequence", batch.Sequence,
			"packets", len(batch.Packets))
		h.stats.PacketsDropped.Add(uint64(len(batch.Packets)))
		// Note: The spawned goroutine will continue until stream.Send returns or
		// connCtx is cancelled (during reconnect). This is acceptable because:
		// 1. The goroutine will be cleaned up when the stream is closed during reconnection
		// 2. The buffered channel prevents blocking the goroutine indefinitely
		// 3. We can't force-kill goroutines in Go, this is the standard pattern
		return
	}
}

// batchSender sends queued batches to the processor with flow control
func (h *Hunter) batchSender() {
	defer h.connWg.Done()

	for {
		select {
		case <-h.connCtx.Done():
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
	defer h.connWg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in handleStreamControl", "panic", r)
		}
	}()

	h.streamMu.Lock()
	stream := h.stream
	h.streamMu.Unlock()

	if stream == nil {
		logger.Error("Stream not available for control messages")
		return
	}

	for {
		// Check context before each Recv to avoid blocking on closed stream
		select {
		case <-h.ctx.Done():
			logger.Debug("handleStreamControl: context cancelled, exiting")
			return
		case <-h.connCtx.Done():
			logger.Debug("handleStreamControl: connection context cancelled, exiting")
			return
		default:
		}

		ctrl, err := stream.Recv()
		if err == io.EOF {
			logger.Info("Stream closed by processor")
			h.markDisconnected()
			return
		}
		if err != nil {
			// Check if we're shutting down
			if h.ctx.Err() != nil || h.connCtx.Err() != nil {
				// Context canceled, normal shutdown
				logger.Debug("handleStreamControl: error during shutdown, exiting gracefully", "error", err)
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

	// Packet field conversions (safe: lengths are from pcap, LinkType is enum < 300)
	return &data.CapturedPacket{
		Data:           packetData,
		TimestampNs:    time.Now().UnixNano(),
		CaptureLength:  uint32(captureLen),  // #nosec G115
		OriginalLength: uint32(originalLen), // #nosec G115
		InterfaceIndex: 0,
		LinkType:       uint32(pktInfo.LinkType), // #nosec G115
		// TODO: Add metadata extraction (SIP, RTP, etc.)
	}
}

// ForwardPacketWithMetadata forwards a packet with embedded metadata to the processor
// This is used by TCP SIP handler to forward reassembled packets with extracted metadata
func (h *Hunter) ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata) error {
	if packet == nil {
		return fmt.Errorf("cannot forward nil packet")
	}

	captureLen := 0
	originalLen := 0
	var packetData []byte
	linkType := uint32(1) // Default to Ethernet (LinkTypeEthernet = 1)

	if packet.Data() != nil {
		packetData = packet.Data()
		captureLen = len(packetData)
	}
	if meta := packet.Metadata(); meta != nil {
		captureLen = meta.CaptureLength
		originalLen = meta.Length
	}
	// Get LinkType from link layer if available
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		linkType = uint32(linkLayer.LayerType()) // #nosec G115
	}

	// Create protobuf packet with embedded metadata
	pbPkt := &data.CapturedPacket{
		Data:           packetData,
		TimestampNs:    time.Now().UnixNano(),
		CaptureLength:  uint32(captureLen),  // #nosec G115
		OriginalLength: uint32(originalLen), // #nosec G115
		InterfaceIndex: 0,
		LinkType:       linkType,
		Metadata:       metadata, // Embedded metadata from TCP SIP handler
	}

	// Add to current batch
	h.batchMu.Lock()
	h.currentBatch = append(h.currentBatch, pbPkt)
	batchLen := len(h.currentBatch)
	h.batchMu.Unlock()

	// Send batch if full
	if batchLen >= h.config.BatchSize {
		h.sendBatch()
	}

	return nil
}

// cleanup closes connections
func (h *Hunter) cleanup() {
	// Cancel connection-scoped context to signal all goroutines to exit
	if h.connCancel != nil {
		h.connCancel()
	}

	// Wait for all connection-scoped goroutines to finish with timeout
	logger.Debug("Waiting for connection goroutines to finish...")

	done := make(chan struct{})
	go func() {
		h.connWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("All connection goroutines finished")
	case <-time.After(10 * time.Second):
		logger.Warn("Cleanup timeout - some goroutines may still be running, proceeding anyway")
	}

	// NOTE: Do NOT close packetBuffer here!
	// The packet buffer is for capturing packets, which should continue
	// even when disconnected from the processor. If we close it here,
	// the new forwardPackets() goroutine after reconnection will read
	// from a closed channel and immediately exit, causing packets to stop flowing.
	// The buffer will be cleaned up when the hunter stops completely (h.ctx canceled).

	h.streamMu.Lock()
	if h.stream != nil {
		_ = h.stream.CloseSend()
	}
	h.streamMu.Unlock()

	if h.dataConn != nil {
		_ = h.dataConn.Close()
	}

	if h.managementConn != nil {
		_ = h.managementConn.Close()
	}
}

// subscribeToFilters subscribes to filter updates from processor
func (h *Hunter) subscribeToFilters() {
	defer h.connWg.Done()

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
	updateCh := make(chan *management.FilterUpdate, constants.ErrorChannelBuffer)
	errCh := make(chan error, constants.ErrorChannelBuffer)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Recovered from panic in filter subscription receiver", "panic", r)
			}
		}()
		for {
			// Check context before Recv
			select {
			case <-h.ctx.Done():
				return
			case <-h.connCtx.Done():
				return
			default:
			}

			update, err := stream.Recv()
			if err != nil {
				// Only send error if not shutting down
				if h.ctx.Err() == nil && h.connCtx.Err() == nil {
					errCh <- err
				}
				return
			}
			select {
			case updateCh <- update:
			case <-h.ctx.Done():
				return
			case <-h.connCtx.Done():
				return
			}
		}
	}()

	// Read with periodic timeout check
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.connCtx.Done():
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
	filtersChanged := false

	switch update.UpdateType {
	case management.FilterUpdateType_UPDATE_ADD:
		// Check if filter already exists (prevent duplicates)
		exists := false
		for _, f := range h.filters {
			if f.Id == update.Filter.Id {
				exists = true
				logger.Debug("Filter already exists, skipping duplicate add",
					"filter_id", update.Filter.Id)
				break
			}
		}

		if !exists {
			// Add new filter
			h.filters = append(h.filters, update.Filter)
			filtersChanged = true
			logger.Info("Filter added",
				"filter_id", update.Filter.Id,
				"pattern", update.Filter.Pattern)
		}

	case management.FilterUpdateType_UPDATE_MODIFY:
		// Modify existing filter
		for i, f := range h.filters {
			if f.Id == update.Filter.Id {
				h.filters[i] = update.Filter
				filtersChanged = true
				logger.Info("Filter modified",
					"filter_id", update.Filter.Id,
					"pattern", update.Filter.Pattern)
				break
			}
		}
		if !filtersChanged {
			logger.Warn("Filter to modify not found", "filter_id", update.Filter.Id)
		}

	case management.FilterUpdateType_UPDATE_DELETE:
		// Delete filter
		for i, f := range h.filters {
			if f.Id == update.Filter.Id {
				h.filters = append(h.filters[:i], h.filters[i+1:]...)
				filtersChanged = true
				logger.Info("Filter deleted", "filter_id", update.Filter.Id)
				break
			}
		}
		if !filtersChanged {
			logger.Warn("Filter to delete not found", "filter_id", update.Filter.Id)
		}
	}

	h.mu.Unlock()

	// Apply filters by restarting capture with new BPF filter
	if filtersChanged {
		logger.Info("Filters changed, restarting capture", "active_filters", len(h.filters))
		if err := h.restartCapture(); err != nil {
			logger.Error("Failed to restart capture with new filters", "error", err)
		}
	}
}

// sendHeartbeats sends periodic heartbeat to processor
func (h *Hunter) sendHeartbeats() {
	defer h.connWg.Done()

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
	respCh := make(chan *management.ProcessorHeartbeat, constants.ErrorChannelBuffer)
	respErrCh := make(chan error, constants.ErrorChannelBuffer)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Recovered from panic in heartbeat receiver", "panic", r)
			}
		}()
		for {
			// Check context before Recv
			select {
			case <-h.ctx.Done():
				return
			case <-h.connCtx.Done():
				return
			default:
			}

			resp, err := stream.Recv()
			if err != nil {
				// Only send error if not shutting down
				if h.ctx.Err() == nil && h.connCtx.Err() == nil {
					respErrCh <- err
				}
				return
			}
			select {
			case respCh <- resp:
			case <-h.ctx.Done():
				return
			case <-h.connCtx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-h.connCtx.Done():
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
			// Get filter count with lock (safe: filter count won't exceed uint32 max)
			h.mu.RLock()
			activeFilters := uint32(len(h.filters)) // #nosec G115
			h.mu.RUnlock()

			logger.Debug("Sending heartbeat",
				"hunter_id", h.config.HunterID,
				"active_filters", activeFilters,
				"status", status)

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
					ActiveFilters:    activeFilters,
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

			// Reset reconnection state
			h.reconnectMu.Lock()
			h.reconnecting = false
			h.reconnectAttempts = 0
			h.reconnectMu.Unlock()

			// Create connection-scoped context for this connection's goroutines
			h.connCtx, h.connCancel = context.WithCancel(h.ctx)

			// Start connection-dependent goroutines with connection-scoped waitgroup
			h.connWg.Add(5)
			go h.forwardPackets()
			go h.handleStreamControl()
			go h.subscribeToFilters()
			go h.sendHeartbeats()
			go h.batchSender() // Flow-controlled batch sender

			// Monitor for disconnection
			h.monitorConnection()

			// If we get here, connection was lost - clean up before reconnecting
			logger.Warn("Connection to processor lost, cleaning up goroutines before retry")
			h.cleanup()
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

		backoff := time.Duration(1<<uint(min(attempts-1, 6))) * time.Second // #nosec G115 - safe: exponential backoff, max 6
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
	// Check frequently for faster reconnection (100ms polling)
	ticker := time.NewTicker(100 * time.Millisecond)
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
				// Return to let connectionManager retry
				// (cleanup will be called by connectionManager at line 1071)
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
