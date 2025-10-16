package hunter

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	huntercapture "github.com/endorses/lippycat/internal/pkg/hunter/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/filtering"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	captureManager *huntercapture.Manager

	// Filter management
	filterManager *filtering.Manager

	// Packet forwarding
	forwardingManager *forwarding.Manager

	// Packet streaming
	stream   data.DataService_StreamPacketsClient
	streamMu sync.Mutex

	// Statistics
	statsCollector *stats.Collector
	mu             sync.RWMutex

	// VoIP filtering (GPU-accelerated)
	voipFilter *VoIPFilter

	// Custom packet processing
	packetProcessor forwarding.PacketProcessor // Optional custom processor for VoIP buffering, etc.

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

	// Create main context for initialization (will be replaced in Start())
	// This is just for the capture manager constructor
	ctx := context.Background()

	// Create capture manager (will be recreated with proper context in Start())
	captureManager := huntercapture.New(huntercapture.Config{
		Interfaces: config.Interfaces,
		BaseFilter: config.BPFFilter,
		BufferSize: config.BufferSize,
	}, ctx)

	h := &Hunter{
		config:               config,
		maxReconnectAttempts: 0, // 0 = infinite reconnect attempts
		reconnectAttempts:    0,
		reconnecting:         false,
		statsCollector:       stats.New(),
		captureManager:       captureManager,
	}

	// Create filter manager with capture restarter interface
	h.filterManager = filtering.New(config.HunterID, captureManager, h)

	return h, nil
}

// SetPacketProcessor sets a custom packet processor for this hunter.
// This should be called before Start() to enable custom packet handling.
func (h *Hunter) SetPacketProcessor(processor forwarding.PacketProcessor) {
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

	// Update capture manager's main context (now that we have the real one)
	h.captureManager = huntercapture.New(huntercapture.Config{
		Interfaces: h.config.Interfaces,
		BaseFilter: h.config.BPFFilter,
		BufferSize: h.config.BufferSize,
	}, h.ctx)

	// Start packet capture first (works independently of processor connection)
	filters := h.filterManager.GetFilters()
	if err := h.captureManager.Start(filters); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}
	defer h.captureManager.Stop()

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

	// Store initial filters in filter manager
	h.filterManager.SetInitialFilters(resp.Filters)

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
	if h.forwardingManager != nil {
		h.forwardingManager.HandleFlowControl(ctrl)
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
			h.MarkDisconnected()
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
			h.MarkDisconnected()
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

	if h.forwardingManager == nil {
		return fmt.Errorf("forwarding manager not initialized")
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

	// Add to current batch and send if full
	if h.forwardingManager.AddPacketToBatch(pbPkt) {
		h.forwardingManager.SendBatch()
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
	h.filterManager.Subscribe(h.ctx, h.connCtx, h.mgmtClient)
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
			h.MarkDisconnected()
			return

		case <-ticker.C:
			// Determine hunter status based on current state
			status := h.calculateStatus()

			// Send heartbeat
			// Get filter count (safe: filter count won't exceed uint32 max)
			activeFilters := uint32(h.filterManager.GetFilterCount()) // #nosec G115

			// Collect stats for heartbeat
			packetsCaptured := h.statsCollector.GetCaptured()
			packetsForwarded := h.statsCollector.GetForwarded()

			logger.Debug("Sending heartbeat",
				"hunter_id", h.config.HunterID,
				"active_filters", activeFilters,
				"packets_captured", packetsCaptured,
				"packets_forwarded", packetsForwarded,
				"status", status)

			hb := &management.HunterHeartbeat{
				HunterId:    h.config.HunterID,
				TimestampNs: time.Now().UnixNano(),
				Status:      status,
				Stats:       h.statsCollector.ToProto(activeFilters),
			}

			if err := stream.Send(hb); err != nil {
				if h.ctx.Err() != nil {
					return
				}
				logger.Error("Failed to send heartbeat", "error", err)
				h.MarkDisconnected()
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
	if h.captureManager.GetPacketBuffer() != nil {
		bufferChan := h.captureManager.GetPacketBuffer().Receive()
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
	captured := h.statsCollector.GetCaptured()
	if captured > 0 {
		dropped := h.statsCollector.GetDropped()
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

			// Create forwarding manager for this connection
			h.forwardingManager = forwarding.New(
				forwarding.Config{
					HunterID:     h.config.HunterID,
					BatchSize:    h.config.BatchSize,
					BatchTimeout: h.config.BatchTimeout,
					BufferSize:   h.config.BufferSize,
				},
				h.statsCollector,
				h.captureManager,
				h.connCtx,
			)
			h.forwardingManager.SetStream(h.stream)
			if h.packetProcessor != nil {
				h.forwardingManager.SetPacketProcessor(h.packetProcessor)
			}
			if h.voipFilter != nil {
				h.forwardingManager.SetVoIPFilter(h.voipFilter)
			}

			// Start connection-dependent goroutines with connection-scoped waitgroup
			h.connWg.Add(4)
			go h.forwardingManager.ForwardPackets(&h.connWg)
			go h.handleStreamControl()
			go h.subscribeToFilters()
			go h.sendHeartbeats()

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

// MarkDisconnected marks the hunter as disconnected and triggers reconnection
// This method is exported so the filter manager can call it when connection is lost
func (h *Hunter) MarkDisconnected() {
	h.reconnectMu.Lock()
	defer h.reconnectMu.Unlock()

	if h.reconnecting {
		// Already reconnecting
		return
	}

	h.reconnecting = true
	logger.Warn("Connection lost, will attempt reconnection")
}

// GetStatsCollector returns the statistics collector
func (h *Hunter) GetStatsCollector() *stats.Collector {
	return h.statsCollector
}

// GetStatsValues returns current statistics as plain uint64 values
func (h *Hunter) GetStatsValues() (captured, matched, forwarded, dropped, bufferBytes uint64) {
	return h.statsCollector.GetAll()
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
