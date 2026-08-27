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
	"github.com/endorses/lippycat/internal/pkg/hunter/buffer"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// PacketProcessor is an optional interface for custom packet processing
// before packets are forwarded to the processor. This allows VoIP mode
// to buffer and filter packets based on call state.
type PacketProcessor interface {
	ProcessPacket(pktInfo capture.PacketInfo) bool
}

// ApplicationFilter provides application-layer packet filtering (protocol-agnostic)
type ApplicationFilter interface {
	// MatchPacket checks if a packet matches any filter.
	MatchPacket(packet gopacket.Packet) bool

	// MatchPacketWithIDs checks if a packet matches any filters and returns the matched filter IDs.
	// Used for LI correlation to map matched filters back to intercept task XIDs.
	MatchPacketWithIDs(packet gopacket.Packet) (matched bool, filterIDs []string)
}

// ApplicationFilterReceiver is an interface for components that can receive ApplicationFilter updates.
// This allows Hunter to inject the ApplicationFilter into packet processors after initialization,
// supporting the pattern where processors are created before Hunter.Start() but need the filter
// that is created inside Start().
type ApplicationFilterReceiver interface {
	SetApplicationFilter(filter ApplicationFilter)
}

// DNSMetadataProvider provides DNS metadata for packets.
// Used for DNS tunneling detection at the hunter edge.
type DNSMetadataProvider interface {
	// ProcessPacket parses a DNS packet and returns proto-ready metadata.
	// Returns nil if the packet is not a DNS packet or parsing fails.
	ProcessPacket(packet gopacket.Packet) *data.DNSMetadata
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
	HunterID       string
	BatchSize      int
	BatchTimeout   time.Duration
	BufferSize     int
	BatchQueueSize int // Number of batches to buffer for async sending (0 = default)

	// Disk overflow buffer (optional)
	DiskBufferEnabled bool   // Enable disk overflow buffer
	DiskBufferDir     string // Directory for disk buffer (default: /var/tmp/lippycat-buffer)
	DiskBufferMaxSize uint64 // Maximum disk buffer size in bytes (default: 1GB)

	// SlowSendInterval paces sends while the processor requests FLOW_SLOW.
	// Zero uses the package default.
	SlowSendInterval time.Duration

	// Clock is injectable for deterministic pacing tests. Nil uses wall time.
	Clock Clock
}

// Ticker is the subset of time.Ticker used by the sender.
type Ticker interface {
	Chan() <-chan time.Time
	Stop()
}

// Clock creates reusable tickers without a timer or goroutine per batch.
type Clock interface {
	NewTicker(time.Duration) Ticker
}

type realClock struct{}
type realTicker struct{ *time.Ticker }

func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }
func (t realTicker) Chan() <-chan time.Time        { return t.C }

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

	// Batch sending (async)
	batchQueue chan *data.PacketBatch
	senderWg   sync.WaitGroup // tracks batch sender goroutine

	// Disk overflow buffer (optional)
	diskBuffer *buffer.DiskOverflowBuffer

	// Flow control
	flowControlState atomic.Int32  // FlowControl enum value
	paused           atomic.Bool   // Whether sending is paused
	flowChanged      chan struct{} // wakes the sender when transmission policy changes
	slowSendInterval time.Duration
	clock            Clock

	// Connection health tracking
	consecutiveFailures atomic.Int32 // Track consecutive send failures
	disconnectCallback  func()       // Called when connection appears dead
	disconnectOnce      sync.Once

	// Optional packet processing
	packetProcessor     PacketProcessor
	applicationFilter   ApplicationFilter
	dnsMetadataProvider DNSMetadataProvider

	// Dependencies
	statsCollector   StatsCollector
	packetBufferProv PacketBufferProvider

	// Context management
	connCtx context.Context
}

// New creates a new forwarding manager with a persistent batch queue
// The queue is provided externally to survive reconnections
func New(config Config, statsCollector StatsCollector, packetBufferProv PacketBufferProvider, connCtx context.Context, batchQueue chan *data.PacketBatch) *Manager {
	if config.SlowSendInterval <= 0 {
		config.SlowSendInterval = 25 * time.Millisecond
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	m := &Manager{
		config:           config,
		currentBatch:     make([]*data.CapturedPacket, 0, config.BatchSize),
		statsCollector:   statsCollector,
		packetBufferProv: packetBufferProv,
		connCtx:          connCtx,
		batchQueue:       batchQueue, // Use provided persistent queue
		flowChanged:      make(chan struct{}, 1),
		slowSendInterval: config.SlowSendInterval,
		clock:            config.Clock,
	}

	// Initialize disk overflow buffer if enabled
	if config.DiskBufferEnabled {
		diskBuf, err := buffer.New(buffer.Config{
			Dir:          config.DiskBufferDir,
			MaxDiskBytes: config.DiskBufferMaxSize,
		})
		if err != nil {
			logger.Error("Failed to initialize disk overflow buffer", "error", err)
		} else {
			m.diskBuffer = diskBuf
			logger.Info("Disk overflow buffer enabled",
				"dir", config.DiskBufferDir,
				"max_size_mb", config.DiskBufferMaxSize/(1024*1024))
		}
	}

	// Start async batch sender goroutine
	m.senderWg.Add(1)
	go m.batchSender()

	return m
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

// SetDisconnectCallback sets a callback to be invoked when connection appears dead
func (m *Manager) SetDisconnectCallback(callback func()) {
	m.disconnectCallback = callback
}

// SetApplicationFilter sets an optional application-layer filter
func (m *Manager) SetApplicationFilter(filter ApplicationFilter) {
	m.applicationFilter = filter
}

// SetDNSMetadataProvider sets the DNS metadata provider for DNS analysis.
func (m *Manager) SetDNSMetadataProvider(provider DNSMetadataProvider) {
	m.dnsMetadataProvider = provider
}

// SetVoIPFilter is a deprecated alias for SetApplicationFilter
// Maintained for backward compatibility
func (m *Manager) SetVoIPFilter(filter ApplicationFilter) {
	m.SetApplicationFilter(filter)
}

// HandleFlowControl updates flow control state based on processor signals
func (m *Manager) HandleFlowControl(ctrl *data.StreamControl) {
	oldState := data.FlowControl(m.flowControlState.Load())
	newState := ctrl.FlowControl

	// PAUSE is the only state that gates transmission. CONTINUE and RESUME both
	// release the gate; RESUME remains distinct so the transition is observable.
	m.flowControlState.Store(int32(newState))
	m.paused.Store(newState == data.FlowControl_FLOW_PAUSE)
	select {
	case m.flowChanged <- struct{}{}:
	default:
	}

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
		if oldState != data.FlowControl_FLOW_PAUSE {
			logger.Warn("Processor requested pause - buffering packets",
				"recommendation", "processor may be overloaded")
		}

	case data.FlowControl_FLOW_RESUME:
		if oldState == data.FlowControl_FLOW_PAUSE {
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

			// Track matched filter IDs for LI correlation
			var matchedFilterIDs []string

			// Apply custom packet processor if set (for VoIP buffering, etc.)
			if m.packetProcessor != nil {
				if !m.packetProcessor.ProcessPacket(pktInfo) {
					// Packet was buffered or filtered out by processor
					continue
				}
				// Packet should be forwarded - count it as matched
				m.statsCollector.IncrementMatched()
				// Note: VoIP processor doesn't provide filter IDs currently
			} else if m.applicationFilter != nil {
				// Fall back to application-layer filter if no custom processor
				// Use MatchPacketWithIDs to get filter IDs for LI correlation
				matched, filterIDs := m.applicationFilter.MatchPacketWithIDs(pktInfo.Packet)
				if !matched {
					// Packet didn't match application filter - skip it
					continue
				}
				// Packet matched - count it and save filter IDs
				m.statsCollector.IncrementMatched()
				matchedFilterIDs = filterIDs
			}

			// Convert to protobuf packet
			pbPkt := convertPacket(pktInfo, matchedFilterIDs)

			// Add DNS metadata if DNS processor is set
			if m.dnsMetadataProvider != nil {
				if dnsMetadata := m.dnsMetadataProvider.ProcessPacket(pktInfo.Packet); dnsMetadata != nil {
					if pbPkt.Metadata == nil {
						pbPkt.Metadata = &data.PacketMetadata{}
					}
					pbPkt.Metadata.Dns = dnsMetadata
				}
			}

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

// SendBatch queues the current batch for async sending
func (m *Manager) SendBatch() {
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

	// Queue batch for async sending (non-blocking)
	select {
	case m.batchQueue <- batch:
		// Successfully queued to memory
	default:
		// Memory queue full - try disk overflow buffer
		if m.diskBuffer != nil {
			if err := m.diskBuffer.Write(batch); err != nil {
				// Disk buffer also full or failed
				logger.Warn("Batch queue and disk buffer full, dropping batch",
					"sequence", batch.Sequence,
					"packets", len(batch.Packets),
					"error", err)
				m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
			} else {
				logger.Debug("Batch queued to disk overflow buffer",
					"sequence", batch.Sequence,
					"packets", len(batch.Packets))
			}
		} else {
			// No disk buffer - drop batch
			logger.Warn("Batch queue full, dropping batch (disk buffer disabled)",
				"sequence", batch.Sequence,
				"packets", len(batch.Packets))
			m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		}
	}
}

// batchSender goroutine sends batches from queue asynchronously
func (m *Manager) batchSender() {
	defer m.senderWg.Done()
	defer m.closeStream()
	slowTicker := m.clock.NewTicker(m.slowSendInterval)
	defer slowTicker.Stop()

	// Create ticker for checking disk buffer (only if enabled)
	var diskCheckTicker *time.Ticker
	var diskCheckChan <-chan time.Time
	if m.diskBuffer != nil {
		diskCheckTicker = time.NewTicker(100 * time.Millisecond) // Check disk every 100ms
		defer diskCheckTicker.Stop()
		diskCheckChan = diskCheckTicker.C
	}

	var pending *data.PacketBatch
	for {
		if pending != nil && !m.paused.Load() {
			if m.GetFlowControlState() == data.FlowControl_FLOW_SLOW {
				select {
				case <-m.connCtx.Done():
					return
				case <-m.flowChanged:
					continue
				case <-slowTicker.Chan():
				}
			}
			if !m.sendBatch(pending) {
				return
			}
			pending = nil
			continue
		}

		// A nil channel disables the dequeue case. PAUSE therefore leaves all
		// capture-side batching and bounded overflow behavior active while it
		// prevents the sole stream owner from taking another batch.
		var sendQueue <-chan *data.PacketBatch
		if !m.paused.Load() {
			sendQueue = m.batchQueue
		}
		select {
		case <-m.connCtx.Done():
			return

		case <-m.flowChanged:
			continue

		case batch := <-sendQueue:
			pending = batch

		case <-diskCheckChan:
			// Check if we have room in memory queue and batches on disk
			if len(m.batchQueue) < cap(m.batchQueue)/2 { // Only refill if queue is less than half full
				// Try to read from disk buffer
				if batch, err := m.diskBuffer.Read(); err != nil {
					logger.Error("Failed to read from disk buffer", "error", err)
				} else if batch != nil {
					// Successfully read batch from disk - queue it to memory
					select {
					case m.batchQueue <- batch:
						logger.Debug("Loaded batch from disk to memory queue",
							"sequence", batch.Sequence,
							"packets", len(batch.Packets))
					default:
						// Memory queue full again - write back to disk
						// This is rare but can happen if queue fills up between check and send
						if err := m.diskBuffer.Write(batch); err != nil {
							logger.Warn("Failed to write batch back to disk", "error", err)
							m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
						}
					}
				}
			}
		}
	}
}

// sendBatch is called only by batchSender, the sole Send/CloseSend owner.
func (m *Manager) sendBatch(batch *data.PacketBatch) bool {
	// Get stream
	m.streamMu.Lock()
	stream := m.stream
	m.streamMu.Unlock()

	if stream == nil {
		logger.Warn("Stream not available, dropping batch",
			"sequence", batch.Sequence)
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		return true
	}

	timedOut := atomic.Bool{}
	timer := time.AfterFunc(constants.DefaultSendTimeout, func() {
		timedOut.Store(true)
		m.signalDisconnect()
	})
	err := stream.Send(batch)
	timer.Stop()
	if err != nil {
		logger.Error("Failed to send batch", "error", err, "sequence", batch.Sequence,
			"timed_out", timedOut.Load())
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		m.recordSendFailure()
		return false
	}
	m.consecutiveFailures.Store(0)
	logger.Debug("Sent packet batch", "sequence", batch.Sequence, "packets", len(batch.Packets))
	m.statsCollector.IncrementForwarded(uint64(len(batch.Packets)))
	return true
}

func (m *Manager) signalDisconnect() {
	m.disconnectOnce.Do(func() {
		if m.disconnectCallback != nil {
			go m.disconnectCallback()
		}
	})
}

func (m *Manager) closeStream() {
	m.streamMu.Lock()
	stream := m.stream
	m.stream = nil
	m.streamMu.Unlock()
	if stream != nil {
		if err := stream.CloseSend(); err != nil {
			logger.Error("Failed to close packet stream", "error", err)
		}
	}
}

// Wait waits for the connection generation's stream owner to exit.
func (m *Manager) Wait() { m.senderWg.Wait() }

// recordSendFailure tracks consecutive send failures and triggers disconnect if threshold exceeded
func (m *Manager) recordSendFailure() {
	// Increment failure counter
	failures := m.consecutiveFailures.Add(1)

	// After N consecutive failures, assume connection is dead
	// This helps detect dead connections faster after laptop resume from standby
	if failures >= constants.MaxConsecutiveSendFailures {
		logger.Warn("Too many consecutive send failures, connection may be dead",
			"consecutive_failures", failures,
			"threshold", constants.MaxConsecutiveSendFailures)

		// Trigger disconnect callback if set
		m.signalDisconnect()

		// Reset counter to avoid repeated callbacks
		m.consecutiveFailures.Store(0)
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
// matchedFilterIDs contains IDs of filters that matched this packet (for LI correlation)
func convertPacket(pktInfo capture.PacketInfo, matchedFilterIDs []string) *data.CapturedPacket {
	pkt := pktInfo.Packet

	captureLen := 0
	originalLen := 0
	var packetData []byte
	timestamp := time.Now()
	hasCaptureTimestamp := false

	if pkt != nil {
		if pkt.Data() != nil {
			packetData = pkt.Data()
			captureLen = len(packetData)
		}
		if meta := pkt.Metadata(); meta != nil {
			captureLen = meta.CaptureLength
			originalLen = meta.Length
			if !meta.Timestamp.IsZero() {
				timestamp = meta.Timestamp
				hasCaptureTimestamp = true
			}
		}
	}
	if !hasCaptureTimestamp {
		logger.Debug("Packet has no capture timestamp; using forwarding time",
			"interface", pktInfo.Interface,
			"timestamp_source", "forwarding_fallback")
	}

	// Packet field conversions (safe: lengths are from pcap, LinkType is enum < 300)
	return &data.CapturedPacket{
		Data:             packetData,
		TimestampNs:      timestamp.UnixNano(),
		CaptureLength:    uint32(captureLen),  // #nosec G115
		OriginalLength:   uint32(originalLen), // #nosec G115
		InterfaceIndex:   0,
		LinkType:         uint32(pktInfo.LinkType), // #nosec G115
		InterfaceName:    pktInfo.Interface,
		MatchedFilterIds: matchedFilterIDs, // For LI correlation
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

// Close cleans up resources (disk buffer, etc.)
func (m *Manager) Close() error {
	if m.diskBuffer != nil {
		return m.diskBuffer.Close()
	}
	return nil
}

// GetDiskBufferMetrics returns disk buffer metrics (if enabled)
func (m *Manager) GetDiskBufferMetrics() *buffer.DiskBufferMetrics {
	if m.diskBuffer == nil {
		return nil
	}
	metrics := m.diskBuffer.GetMetrics()
	return &metrics
}
