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
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/types"
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
	ProcessPacket(packet gopacket.Packet) *types.DNSMetadata
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
	HunterID           string
	BatchSize          int
	BatchTimeout       time.Duration
	BufferSize         int
	BatchQueueSize     int // Number of batches to buffer for async sending (0 = default)
	IncludeHTTPHeaders bool

	// Disk overflow buffer (optional)
	DiskBufferEnabled bool   // Enable disk overflow buffer
	DiskBufferDir     string // Directory for disk buffer (default: /var/tmp/lippycat-buffer)
	DiskBufferMaxSize uint64 // Maximum disk buffer size in bytes (default: 1GB)

	// SlowSendInterval paces sends while the processor requests FLOW_SLOW.
	// Zero uses the package default.
	SlowSendInterval time.Duration

	// SendTimeout is the maximum time a generation may spend in stream.Send.
	// Zero uses constants.DefaultSendTimeout.
	SendTimeout time.Duration

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
	currentBatch  []*pipeline.PacketEnvelope
	batchSequence uint64

	// Batch sending (async)
	batchQueue chan *pipeline.PacketBatch
	senderWg   sync.WaitGroup // tracks batch sender goroutine

	// Disk overflow buffer (optional)
	diskBuffer  *buffer.DiskOverflowBuffer
	overflowMu  sync.Mutex
	diskBacklog bool

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
func New(config Config, statsCollector StatsCollector, packetBufferProv PacketBufferProvider, connCtx context.Context, batchQueue chan *pipeline.PacketBatch) *Manager {
	if config.SlowSendInterval <= 0 {
		config.SlowSendInterval = 25 * time.Millisecond
	}
	if config.SendTimeout <= 0 {
		config.SendTimeout = constants.DefaultSendTimeout
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	m := &Manager{
		config:           config,
		currentBatch:     make([]*pipeline.PacketEnvelope, 0, config.BatchSize),
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

			envelope := convertPacket(pktInfo, matchedFilterIDs)
			metadata := protocolmeta.Enrich(pktInfo.Packet, nil, m.config.IncludeHTTPHeaders)

			// Add DNS metadata if DNS processor is set
			if m.dnsMetadataProvider != nil {
				if dnsMetadata := m.dnsMetadataProvider.ProcessPacket(pktInfo.Packet); dnsMetadata != nil {
					if metadata == nil {
						metadata = &data.PacketMetadata{}
					}
					metadata.Dns = grpcadapter.DNSMetadataToProto(dnsMetadata)
				}
			}
			if metadata != nil {
				encoded, err := grpcadapter.MetadataFromProto(metadata)
				if err != nil {
					logger.Error("Failed to normalize packet metadata", "error", err)
					m.statsCollector.IncrementDropped(1)
					continue
				}
				envelope.Metadata = encoded
				envelope.Stages = envelope.Stages.With(pipeline.StageDetected).With(pipeline.StageAnalyzed)
			}

			// Add to current batch with minimal lock duration
			m.batchMu.Lock()
			m.currentBatch = append(m.currentBatch, envelope)
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
	batch := &pipeline.PacketBatch{
		Source:    pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, NodeID: m.config.HunterID},
		Sequence:  m.batchSequence,
		CreatedAt: time.Now(),
		Packets:   m.currentBatch,
		HasStats:  true,
		Stats: pipeline.BatchStats{
			TotalCaptured:   m.statsCollector.GetCaptured(),
			FilteredMatched: m.statsCollector.GetMatched(),
			Dropped:         m.statsCollector.GetDropped(),
			BufferUsage:     0, // Will be set by caller if needed
		},
	}

	// Reset batch
	m.currentBatch = make([]*pipeline.PacketEnvelope, 0, m.config.BatchSize)
	m.batchMu.Unlock()

	// Serialize admission across the memory and disk tiers. Once a batch spills
	// to disk, all later batches must follow it there until the sender drains the
	// disk backlog; otherwise newer memory batches can overtake older disk ones.
	m.overflowMu.Lock()
	defer m.overflowMu.Unlock()
	if m.diskBacklog {
		m.writeBatchToDisk(batch)
		return
	}

	// Queue batch for async sending (non-blocking).
	select {
	case m.batchQueue <- batch:
		// Successfully queued to memory
	default:
		m.writeBatchToDisk(batch)
	}
}

// writeBatchToDisk is called with overflowMu held.
func (m *Manager) writeBatchToDisk(batch *pipeline.PacketBatch) {
	if m.diskBuffer == nil {
		logger.Warn("Batch queue full, dropping batch (disk buffer disabled)",
			"sequence", batch.Sequence, "packets", len(batch.Packets))
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		return
	}
	wireBatch, err := grpcadapter.ToPacketBatch(batch)
	if err != nil {
		logger.Error("Failed to encode batch for disk overflow", "sequence", batch.Sequence, "error", err)
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		return
	}
	if err := m.diskBuffer.Write(wireBatch); err != nil {
		logger.Warn("Batch queue and disk buffer full, dropping batch",
			"sequence", batch.Sequence, "packets", len(batch.Packets), "error", err)
		m.statsCollector.IncrementDropped(uint64(len(batch.Packets)))
		return
	}
	m.diskBacklog = true
	logger.Debug("Batch queued to disk overflow buffer",
		"sequence", batch.Sequence, "packets", len(batch.Packets))
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

	var pending *pipeline.PacketBatch
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
		var sendQueue <-chan *pipeline.PacketBatch
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
			// Memory batches all predate the disk backlog, so drain them first.
			if len(m.batchQueue) != 0 {
				continue
			}
			m.overflowMu.Lock()
			wireBatch, err := m.diskBuffer.Read()
			var batch *pipeline.PacketBatch
			if err != nil {
				logger.Error("Failed to read from disk buffer", "error", err)
			} else if wireBatch == nil {
				// Admission is serialized by overflowMu, so no producer can append
				// between observing an empty disk and reopening the memory tier.
				m.diskBacklog = false
			} else {
				batch, err = grpcadapter.FromPacketBatch(wireBatch)
				if err != nil {
					logger.Error("Failed to normalize disk-buffered batch", "error", err)
				} else {
					batch.Source.Kind = pipeline.SourceLiveCapture
					for _, envelope := range batch.Packets {
						envelope.Source.Kind = pipeline.SourceLiveCapture
					}
				}
			}
			m.overflowMu.Unlock()
			if batch != nil {
				pending = batch
			}
		}
	}
}

// sendBatch is called only by batchSender, the sole Send/CloseSend owner.
func (m *Manager) sendBatch(batch *pipeline.PacketBatch) bool {
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
	timer := time.AfterFunc(m.config.SendTimeout, func() {
		timedOut.Store(true)
		m.signalDisconnect()
	})
	wireBatch, err := grpcadapter.ToPacketBatch(batch)
	if err == nil {
		err = stream.Send(wireBatch)
	}
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
func (m *Manager) AddPacketToBatch(envelope *pipeline.PacketEnvelope) bool {
	m.batchMu.Lock()
	m.currentBatch = append(m.currentBatch, envelope)
	batchLen := len(m.currentBatch)
	m.batchMu.Unlock()

	// Return true if batch is full
	return batchLen >= m.config.BatchSize
}

// convertPacket converts capture.PacketInfo to the normalized pipeline format.
// matchedFilterIDs contains IDs of filters that matched this packet (for LI correlation)
func convertPacket(pktInfo capture.PacketInfo, matchedFilterIDs []string) *pipeline.PacketEnvelope {
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
	stages := pipeline.StageProvenance(0)
	if len(matchedFilterIDs) > 0 {
		stages = stages.With(pipeline.StageFiltered)
	}
	return &pipeline.PacketEnvelope{
		Data:             packetData,
		CaptureTime:      timestamp,
		CaptureLength:    captureLen,
		OriginalLength:   originalLen,
		LinkType:         pktInfo.LinkType,
		Source:           pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, NodeID: "", InterfaceName: pktInfo.Interface},
		Stages:           stages,
		MatchedFilterIDs: matchedFilterIDs, // For LI correlation
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
