//go:build hunter || all

package forwarding

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// PacketProcessor is an optional interface for custom packet processing
// before packets are forwarded to the processor. This allows VoIP mode
// to buffer and filter packets based on call state.
type PacketProcessor interface {
	ProcessPacket(pktInfo capture.PacketInfo) bool
}

// VoIPFilter provides simple VoIP packet filtering
type VoIPFilter interface {
	MatchPacket(packet gopacket.Packet) bool
}

// StatsCollector provides access to hunter statistics
type StatsCollector interface {
	IncrementCaptured()
	IncrementMatched()
	IncrementForwarded(count uint64)
	IncrementDropped(count uint64)
	GetCaptured() uint64
	GetMatched() uint64
	GetDropped() uint64
}

// PacketBufferProvider provides access to the packet buffer
type PacketBufferProvider interface {
	GetPacketBuffer() *capture.PacketBuffer
}

// Config contains forwarding configuration
type Config struct {
	HunterID     string
	BatchSize    int
	BatchTimeout time.Duration
	BufferSize   int
}

// Manager handles packet batching and forwarding to processor
type Manager struct {
	config Config

	// Streaming
	stream   data.DataService_StreamPacketsClient
	streamMu sync.Mutex

	// Batching
	batchMu       sync.Mutex
	currentBatch  []*data.CapturedPacket
	batchSequence uint64

	// Flow control
	flowControlState atomic.Int32 // FlowControl enum value
	paused           atomic.Bool  // Whether sending is paused

	// Optional packet processing
	packetProcessor PacketProcessor
	voipFilter      VoIPFilter

	// Dependencies
	statsCollector   StatsCollector
	packetBufferProv PacketBufferProvider

	// Context management
	connCtx context.Context
}

// New creates a new forwarding manager
func New(config Config, statsCollector StatsCollector, packetBufferProv PacketBufferProvider, connCtx context.Context) *Manager {
	return &Manager{
		config:           config,
		currentBatch:     make([]*data.CapturedPacket, 0, config.BatchSize),
		statsCollector:   statsCollector,
		packetBufferProv: packetBufferProv,
		connCtx:          connCtx,
	}
}

// SetStream sets the active data stream for forwarding
func (m *Manager) SetStream(stream data.DataService_StreamPacketsClient) {
	m.streamMu.Lock()
	m.stream = stream
	m.streamMu.Unlock()
}

// SetPacketProcessor sets an optional packet processor for custom filtering
func (m *Manager) SetPacketProcessor(processor PacketProcessor) {
	m.packetProcessor = processor
}

// SetVoIPFilter sets an optional VoIP filter
func (m *Manager) SetVoIPFilter(filter VoIPFilter) {
	m.voipFilter = filter
}

// HandleFlowControl updates flow control state based on processor signals
func (m *Manager) HandleFlowControl(ctrl *data.StreamControl) {
	oldState := data.FlowControl(m.flowControlState.Load())
	newState := ctrl.FlowControl

	// Update flow control state
	m.flowControlState.Store(int32(newState))

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
		if !m.paused.Load() {
			m.paused.Store(true)
			logger.Warn("Processor requested pause - buffering packets",
				"recommendation", "processor may be overloaded")
		}

	case data.FlowControl_FLOW_RESUME:
		if m.paused.Load() {
			m.paused.Store(false)
			logger.Info("Processor requested resume - sending packets")
		}

	case data.FlowControl_FLOW_SLOW:
		logger.Debug("Processor requested slow down")

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

// ForwardPackets reads from packet buffer and forwards batches to processor
func (m *Manager) ForwardPackets(wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(m.config.BatchTimeout)
	defer ticker.Stop()

	logger.Info("Packet forwarding started",
		"batch_size", m.config.BatchSize,
		"batch_timeout", m.config.BatchTimeout)

	for {
		select {
		case <-m.connCtx.Done():
			// Send remaining batch before shutdown
			m.SendBatch()
			return

		case pktInfo, ok := <-m.packetBufferProv.GetPacketBuffer().Receive():
			if !ok {
				// Channel closed
				m.SendBatch()
				return
			}

			// Increment captured counter
			m.statsCollector.IncrementCaptured()

			// Apply custom packet processor if set (for VoIP buffering, etc.)
			if m.packetProcessor != nil {
				if !m.packetProcessor.ProcessPacket(pktInfo) {
					// Packet was buffered or filtered out by processor
					continue
				}
				// Packet should be forwarded - count it as matched
				m.statsCollector.IncrementMatched()
			} else if m.voipFilter != nil {
				// Fall back to simple VoIP filter if no custom processor
				if !m.voipFilter.MatchPacket(pktInfo.Packet) {
					// Packet didn't match VoIP filter - skip it
					continue
				}
				// Packet matched - count it
				m.statsCollector.IncrementMatched()
			}

			// Convert to protobuf packet
			pbPkt := convertPacket(pktInfo)

			// Add to current batch with minimal lock duration
			m.batchMu.Lock()
			m.currentBatch = append(m.currentBatch, pbPkt)
			batchLen := len(m.currentBatch)
			m.batchMu.Unlock()

			// Check size outside lock
			if batchLen >= m.config.BatchSize {
				m.SendBatch()
			}

		case <-ticker.C:
			// Send batch on timeout
			m.SendBatch()
		}
	}
}

// SendBatch sends the current batch to processor
func (m *Manager) SendBatch() {
	// Check if paused by processor
	if m.paused.Load() {
		logger.Debug("Skipping batch send - paused by processor")
		return
	}

	m.batchMu.Lock()
	if len(m.currentBatch) == 0 {
		m.batchMu.Unlock()
		return
	}

	// Create batch message
	m.batchSequence++
	batch := &data.PacketBatch{
		HunterId:    m.config.HunterID,
		Sequence:    m.batchSequence,
		TimestampNs: time.Now().UnixNano(),
		Packets:     m.currentBatch,
		Stats: &data.BatchStats{
			TotalCaptured:   m.statsCollector.GetCaptured(),
			FilteredMatched: m.statsCollector.GetMatched(),
			Dropped:         m.statsCollector.GetDropped(),
			BufferUsage:     0, // Will be set by caller if needed
		},
	}

	// Reset batch
	m.currentBatch = make([]*data.CapturedPacket, 0, m.config.BatchSize)
	m.batchMu.Unlock()

	// Send via stream
	m.streamMu.Lock()
	stream := m.stream
	m.streamMu.Unlock()

	if stream == nil {
		logger.Warn("Stream not available, dropping batch")
		return
	}

	// Send with context timeout to prevent blocking indefinitely
	sendCtx, sendCancel := context.WithTimeout(m.connCtx, 5*time.Second)
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
			m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
			return
		}

		logger.Debug("Sent packet batch",
			"sequence", batch.Sequence,
			"packets", len(batch.Packets))

		m.statsCollector.IncrementForwarded(uint64(len(batch.Packets)))

	case <-sendCtx.Done():
		// Context cancelled or timed out
		logger.Error("Batch send timeout - processor may be unresponsive",
			"sequence", batch.Sequence,
			"packets", len(batch.Packets))
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		return
	}
}

// AddPacketToBatch adds a packet directly to the current batch
// Used by ForwardPacketWithMetadata for pre-constructed packets
func (m *Manager) AddPacketToBatch(pbPkt *data.CapturedPacket) bool {
	m.batchMu.Lock()
	m.currentBatch = append(m.currentBatch, pbPkt)
	batchLen := len(m.currentBatch)
	m.batchMu.Unlock()

	// Return true if batch is full
	return batchLen >= m.config.BatchSize
}

// convertPacket converts capture.PacketInfo to protobuf format
func convertPacket(pktInfo capture.PacketInfo) *data.CapturedPacket {
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
	}
}

// GetFlowControlState returns the current flow control state
func (m *Manager) GetFlowControlState() data.FlowControl {
	return data.FlowControl(m.flowControlState.Load())
}

// IsPaused returns whether sending is currently paused
func (m *Manager) IsPaused() bool {
	return m.paused.Load()
}
