//go:build hunter || all

package hunter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	huntercapture "github.com/endorses/lippycat/internal/pkg/hunter/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/connection"
	"github.com/endorses/lippycat/internal/pkg/hunter/filtering"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
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

	// Managers
	captureManager    *huntercapture.Manager
	filterManager     *filtering.Manager
	connectionManager *connection.Manager
	statsCollector    *stats.Collector

	// VoIP filtering (GPU-accelerated)
	voipFilter *VoIPFilter

	// Custom packet processing
	packetProcessor forwarding.PacketProcessor // Optional custom processor for VoIP buffering, etc.

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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
		config:         config,
		statsCollector: stats.New(),
		captureManager: captureManager,
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

	// Create and start connection manager (handles initial connect and reconnections)
	h.connectionManager = connection.New(
		connection.Config{
			ProcessorAddr:         h.config.ProcessorAddr,
			HunterID:              h.config.HunterID,
			Interfaces:            h.config.Interfaces,
			BufferSize:            h.config.BufferSize,
			BatchSize:             h.config.BatchSize,
			BatchTimeout:          h.config.BatchTimeout,
			TLSEnabled:            h.config.TLSEnabled,
			TLSCertFile:           h.config.TLSCertFile,
			TLSKeyFile:            h.config.TLSKeyFile,
			TLSCAFile:             h.config.TLSCAFile,
			TLSSkipVerify:         h.config.TLSSkipVerify,
			TLSServerNameOverride: h.config.TLSServerNameOverride,
			MaxReconnectAttempts:  0, // 0 = infinite
		},
		h.statsCollector,
		h.filterManager,
		h.captureManager,
		h, // ForwardingManagerFactory interface
		h.handleFlowControl,
	)
	h.connectionManager.Start(h.ctx, &h.wg)

	logger.Info("Hunter started successfully", "hunter_id", h.config.HunterID)

	// Wait for shutdown
	<-h.ctx.Done()

	// Wait for goroutines
	h.wg.Wait()

	logger.Info("Hunter stopped", "hunter_id", h.config.HunterID)
	return nil
}

// CreateForwardingManager implements ForwardingManagerFactory interface
func (h *Hunter) CreateForwardingManager(connCtx context.Context, stream data.DataService_StreamPacketsClient) *forwarding.Manager {
	fwdMgr := forwarding.New(
		forwarding.Config{
			HunterID:     h.config.HunterID,
			BatchSize:    h.config.BatchSize,
			BatchTimeout: h.config.BatchTimeout,
			BufferSize:   h.config.BufferSize,
		},
		h.statsCollector,
		h.captureManager,
		connCtx,
	)
	fwdMgr.SetStream(stream)
	if h.packetProcessor != nil {
		fwdMgr.SetPacketProcessor(h.packetProcessor)
	}
	if h.voipFilter != nil {
		fwdMgr.SetVoIPFilter(h.voipFilter)
	}
	return fwdMgr
}

// handleFlowControl processes flow control signals from processor
// This is called by the connection manager and delegated to the forwarding manager
func (h *Hunter) handleFlowControl(ctrl *data.StreamControl) {
	if h.connectionManager != nil {
		if fwdMgr := h.connectionManager.GetForwardingManager(); fwdMgr != nil {
			fwdMgr.HandleFlowControl(ctrl)
		}
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

	if h.connectionManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	forwardingManager := h.connectionManager.GetForwardingManager()
	if forwardingManager == nil {
		return fmt.Errorf("forwarding manager not initialized")
	}

	captureLen := 0
	originalLen := 0
	var packetData []byte

	if packet.Data() != nil {
		packetData = packet.Data()
		captureLen = len(packetData)
	}
	if meta := packet.Metadata(); meta != nil {
		captureLen = meta.CaptureLength
		originalLen = meta.Length
	}

	// For packets with embedded metadata (already analyzed VoIP packets),
	// default to Ethernet LinkType (1) since the TUI will use metadata fields
	// instead of re-parsing the packet
	linkType := uint32(1) // LinkTypeEthernet

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
	if forwardingManager.AddPacketToBatch(pbPkt) {
		forwardingManager.SendBatch()
	}

	return nil
}

// MarkDisconnected marks the hunter as disconnected and triggers reconnection
// This method is exported so the filter manager can call it when connection is lost
func (h *Hunter) MarkDisconnected() {
	if h.connectionManager != nil {
		h.connectionManager.MarkDisconnected()
	}
}

// GetStatsCollector returns the statistics collector
func (h *Hunter) GetStatsCollector() *stats.Collector {
	return h.statsCollector
}

// GetStatsValues returns current statistics as plain uint64 values
func (h *Hunter) GetStatsValues() (captured, matched, forwarded, dropped, bufferBytes uint64) {
	return h.statsCollector.GetAll()
}
