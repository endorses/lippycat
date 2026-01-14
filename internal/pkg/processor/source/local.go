// Package source - LocalSource Implementation
//
// LocalSource implements the PacketSource interface for capturing packets
// from local network interfaces. It is used for standalone "tap" mode where
// the processor captures packets directly without remote hunters.
//
// Architecture:
//
//	Interface → gopacket → LocalSource.captureLoop() → batching → Batches() channel → Processor
//
// The source reuses the capture package for packet capture and optionally
// supports application-layer filtering via ApplicationFilter (GPU/CPU).
package source

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
)

// ApplicationFilter provides application-layer packet filtering.
// This interface is satisfied by hunter.ApplicationFilter.
type ApplicationFilter interface {
	// MatchPacket checks if a packet matches any filter.
	MatchPacket(packet gopacket.Packet) bool

	// MatchPacketWithIDs checks if a packet matches any filters and returns the matched filter IDs.
	// Used for LI correlation to map matched filters back to intercept task XIDs.
	MatchPacketWithIDs(packet gopacket.Packet) (matched bool, filterIDs []string)
}

// VoIPProcessor is an alias for voipprocessor.SourceAdapter.
// It provides VoIP packet processing for SIP/RTP detection.
type VoIPProcessor = *voipprocessor.SourceAdapter

// LocalSource captures packets from local network interfaces.
// It implements the PacketSource interface for standalone capture mode.
type LocalSource struct {
	// Configuration
	config LocalSourceConfig

	// Capture state
	packetBuffer  *capture.PacketBuffer
	captureCtx    context.Context
	captureCancel context.CancelFunc

	// Batching
	batchMu      sync.Mutex
	currentBatch []*data.CapturedPacket
	batchSeq     uint64

	// Packet batch channel for processing
	batches chan *PacketBatch

	// Optional filtering
	appFilter ApplicationFilter

	// Optional VoIP processing for SIP/RTP metadata extraction
	voipProcessor VoIPProcessor

	// Optional DNS processing for DNS parsing and tunneling detection
	dnsProcessor DNSProcessor

	// Stats tracking
	stats *AtomicStats

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// State
	started bool
	mu      sync.Mutex
}

// LocalSourceConfig contains configuration for LocalSource.
type LocalSourceConfig struct {
	// Interfaces to capture from (e.g., "eth0", "eth0,eth1")
	Interfaces []string

	// BPFFilter is the initial BPF filter expression
	BPFFilter string

	// BatchSize is the number of packets per batch (default: 100)
	BatchSize int

	// BatchTimeout is the maximum time to wait before sending a partial batch
	BatchTimeout time.Duration

	// BufferSize is the packet buffer size (default: 10000)
	BufferSize int

	// BatchBuffer is the channel buffer size for batches (default: 1000)
	BatchBuffer int

	// ProcessorID is the processor's ID, used for virtual hunter ID generation.
	// When set, SourceID() returns "{ProcessorID}-local" instead of "local".
	ProcessorID string

	// ProtocolMode indicates the capture protocol mode (e.g., "generic", "voip", "dns", "email", "http", "tls").
	// Used for TUI display and filter validation.
	ProtocolMode string
}

// DefaultLocalSourceConfig returns a LocalSourceConfig with sensible defaults.
func DefaultLocalSourceConfig() LocalSourceConfig {
	return LocalSourceConfig{
		BatchSize:    100,
		BatchTimeout: 100 * time.Millisecond,
		BufferSize:   10000,
		BatchBuffer:  1000,
	}
}

// NewLocalSource creates a new LocalSource for local packet capture.
func NewLocalSource(cfg LocalSourceConfig) *LocalSource {
	// Apply defaults
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 100 * time.Millisecond
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 10000
	}
	if cfg.BatchBuffer == 0 {
		cfg.BatchBuffer = 1000
	}

	return &LocalSource{
		config:       cfg,
		currentBatch: make([]*data.CapturedPacket, 0, cfg.BatchSize),
		batches:      make(chan *PacketBatch, cfg.BatchBuffer),
		stats:        NewAtomicStats(),
	}
}

// SetApplicationFilter sets an optional application-layer filter.
// Packets not matching the filter will be dropped before batching.
// Pass nil to disable filtering (all packets pass through).
func (s *LocalSource) SetApplicationFilter(filter ApplicationFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appFilter = filter
}

// SetVoIPProcessor sets an optional VoIP processor for SIP/RTP detection.
// When set, packets are processed for VoIP metadata which is attached to
// the CapturedPacket.Metadata field for downstream per-call PCAP writing.
// Pass nil to disable VoIP processing.
func (s *LocalSource) SetVoIPProcessor(processor VoIPProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.voipProcessor = processor
}

// GetVoIPProcessor returns the VoIP processor if set.
// Returns nil if no VoIP processor is configured.
func (s *LocalSource) GetVoIPProcessor() VoIPProcessor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.voipProcessor
}

// SetDNSProcessor sets an optional DNS processor for DNS parsing and tunneling detection.
// When set, DNS packets are parsed and metadata is attached to the CapturedPacket.
// Pass nil to disable DNS processing.
func (s *LocalSource) SetDNSProcessor(processor DNSProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsProcessor = processor
}

// GetDNSProcessor returns the DNS processor if set.
// Returns nil if no DNS processor is configured.
func (s *LocalSource) GetDNSProcessor() DNSProcessor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsProcessor
}

// Start begins packet capture. Blocks until ctx is cancelled.
func (s *LocalSource) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	logger.Info("LocalSource starting",
		"interfaces", s.config.Interfaces,
		"bpf_filter", s.config.BPFFilter,
		"batch_size", s.config.BatchSize)

	// Create packet buffer
	s.packetBuffer = capture.NewPacketBuffer(s.ctx, s.config.BufferSize)

	// Create capture context (separate from main context for restart support)
	s.captureCtx, s.captureCancel = context.WithCancel(s.ctx)

	// Start capture goroutines
	s.wg.Add(1)
	go s.capturePackets()

	// Start batching goroutine
	s.wg.Add(1)
	go s.batchingLoop()

	// Wait for context cancellation
	<-s.ctx.Done()

	// Stop capture
	if s.captureCancel != nil {
		s.captureCancel()
	}

	// Close packet buffer to signal batchingLoop
	if s.packetBuffer != nil {
		s.packetBuffer.Close()
	}

	// Wait for goroutines
	s.wg.Wait()

	// Close batches channel
	close(s.batches)

	logger.Info("LocalSource stopped",
		"packets_captured", s.stats.packetsCaptured.Load(),
		"packets_forwarded", s.stats.packetsForwarded.Load(),
		"packets_dropped", s.stats.packetsDropped.Load())

	return nil
}

// capturePackets starts the gopacket capture loop.
func (s *LocalSource) capturePackets() {
	defer s.wg.Done()

	// Build interface list
	var devices []pcaptypes.PcapInterface
	for _, iface := range s.config.Interfaces {
		for _, device := range strings.Split(iface, ",") {
			device = strings.TrimSpace(device)
			if device != "" {
				devices = append(devices, pcaptypes.CreateLiveInterface(device))
			}
		}
	}

	if len(devices) == 0 {
		logger.Error("LocalSource: no interfaces configured")
		return
	}

	// Use InitWithBuffer to capture packets into our buffer
	// nil processor means we own the buffer and read from it externally
	capture.InitWithBuffer(s.captureCtx, devices, s.config.BPFFilter, s.packetBuffer, nil, nil)
}

// batchingLoop reads from packet buffer, applies filtering, and creates batches.
func (s *LocalSource) batchingLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Send remaining batch before shutdown
			s.sendBatch()
			return

		case pktInfo, ok := <-s.packetBuffer.Receive():
			if !ok {
				// Channel closed
				s.sendBatch()
				return
			}

			// Count ALL packets received from buffer (before filtering)
			s.stats.AddCaptured()

			s.mu.Lock()
			filter := s.appFilter
			voipProc := s.voipProcessor
			dnsProc := s.dnsProcessor
			s.mu.Unlock()

			// Convert to protobuf format first
			pbPkt := convertPacketInfo(pktInfo)

			// Apply VoIP processing BEFORE filtering
			// This ensures RTP packets associated with calls are detected
			// before the application filter can drop them
			var isVoIPPacket bool
			if voipProc != nil {
				if result := voipProc.Process(pktInfo.Packet); result != nil && result.IsVoIPPacket() {
					pbPkt.Metadata = result.GetMetadata()
					isVoIPPacket = true
				}
			}

			// Apply DNS processing if enabled and not a VoIP packet
			// DNS packets are not VoIP, so skip if already identified as VoIP
			if dnsProc != nil && !isVoIPPacket {
				if dnsMetadata := dnsProc.ProcessPacket(pktInfo.Packet); dnsMetadata != nil {
					// Create metadata if nil, then set DNS field
					if pbPkt.Metadata == nil {
						pbPkt.Metadata = &data.PacketMetadata{}
					}
					pbPkt.Metadata.Dns = dnsMetadata
				}
			}

			// Apply application filter if set
			// VoIP packets (SIP and associated RTP) bypass the filter
			// since they're already identified by the VoIP processor
			var matchedFilterIDs []string
			if filter != nil && !isVoIPPacket {
				matched, filterIDs := filter.MatchPacketWithIDs(pktInfo.Packet)
				if !matched {
					// Packet filtered out
					continue
				}
				matchedFilterIDs = filterIDs
			}

			// Set matched filter IDs for LI correlation
			if len(matchedFilterIDs) > 0 {
				pbPkt.MatchedFilterIds = matchedFilterIDs
			}

			// Update stats for packets that passed filtering
			s.stats.AddForwarded(uint64(len(pbPkt.Data)))

			// Add to batch
			s.batchMu.Lock()
			s.currentBatch = append(s.currentBatch, pbPkt)
			batchLen := len(s.currentBatch)
			s.batchMu.Unlock()

			// Send if batch is full
			if batchLen >= s.config.BatchSize {
				s.sendBatch()
			}

		case <-ticker.C:
			// Send batch on timeout
			s.sendBatch()
		}
	}
}

// sendBatch sends the current batch to the batches channel.
func (s *LocalSource) sendBatch() {
	s.batchMu.Lock()
	if len(s.currentBatch) == 0 {
		s.batchMu.Unlock()
		return
	}

	s.batchSeq++
	batch := &PacketBatch{
		SourceID:    s.SourceID(),
		Packets:     s.currentBatch,
		Sequence:    s.batchSeq,
		TimestampNs: time.Now().UnixNano(),
		Stats: &data.BatchStats{
			TotalCaptured:   s.stats.packetsCaptured.Load(),
			FilteredMatched: s.stats.packetsForwarded.Load(),
			Dropped:         s.stats.packetsDropped.Load(),
		},
	}

	// Reset batch
	s.currentBatch = make([]*data.CapturedPacket, 0, s.config.BatchSize)
	s.batchMu.Unlock()

	s.stats.AddBatch()

	// Non-blocking send
	select {
	case s.batches <- batch:
		// Successfully sent
	default:
		// Buffer full - drop batch
		s.stats.AddDropped(uint64(len(batch.Packets)))
		logger.Warn("LocalSource batch buffer full, dropping batch",
			"sequence", batch.Sequence,
			"packets", len(batch.Packets))
	}
}

// Batches returns the channel that receives packet batches.
func (s *LocalSource) Batches() <-chan *PacketBatch {
	return s.batches
}

// Stats returns current capture statistics.
func (s *LocalSource) Stats() Stats {
	return s.stats.Snapshot()
}

// SourceID returns the source identifier for this local capture.
// Returns "{ProcessorID}-local" if ProcessorID is configured, otherwise "local".
func (s *LocalSource) SourceID() string {
	if s.config.ProcessorID != "" {
		return s.config.ProcessorID + "-local"
	}
	return "local"
}

// GetProtocolMode returns the protocol mode for this local capture.
// Returns the configured ProtocolMode, or "generic" if not set.
func (s *LocalSource) GetProtocolMode() string {
	if s.config.ProtocolMode != "" {
		return s.config.ProtocolMode
	}
	return "generic"
}

// SetBPFFilter updates the BPF filter. This requires restarting capture.
// Returns nil on success, or an error if the filter update fails.
func (s *LocalSource) SetBPFFilter(filter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		// Not started yet, just update config
		s.config.BPFFilter = filter
		return nil
	}

	logger.Info("LocalSource updating BPF filter", "new_filter", filter)

	// Update config
	s.config.BPFFilter = filter

	// Cancel current capture
	if s.captureCancel != nil {
		s.captureCancel()
	}

	// Create new capture context
	s.captureCtx, s.captureCancel = context.WithCancel(s.ctx)

	// Start new capture goroutine
	s.wg.Add(1)
	go s.capturePackets()

	return nil
}

// Stop gracefully stops the source.
func (s *LocalSource) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	// Stop DNS processor if set
	if s.dnsProcessor != nil {
		s.dnsProcessor.Stop()
	}
}

// IsStarted returns whether the source has been started.
func (s *LocalSource) IsStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// Interfaces returns the configured capture interfaces.
func (s *LocalSource) Interfaces() []string {
	return s.config.Interfaces
}

// convertPacketInfo converts capture.PacketInfo to protobuf CapturedPacket.
// This is similar to forwarding.convertPacket but works with capture.PacketInfo.
func convertPacketInfo(pktInfo capture.PacketInfo) *data.CapturedPacket {
	pkt := pktInfo.Packet

	captureLen := 0
	originalLen := 0
	var packetData []byte
	var timestampNs int64

	if pkt != nil {
		if pkt.Data() != nil {
			packetData = pkt.Data()
			captureLen = len(packetData)
		}
		if meta := pkt.Metadata(); meta != nil {
			captureLen = meta.CaptureLength
			originalLen = meta.Length
			// Use actual packet capture timestamp, not current time
			timestampNs = meta.Timestamp.UnixNano()
		}
	}

	// Fallback to current time if no metadata timestamp available
	if timestampNs == 0 {
		timestampNs = time.Now().UnixNano()
	}

	return &data.CapturedPacket{
		Data:           packetData,
		TimestampNs:    timestampNs,
		CaptureLength:  uint32(captureLen),  // #nosec G115
		OriginalLength: uint32(originalLen), // #nosec G115
		InterfaceIndex: 0,
		LinkType:       uint32(pktInfo.LinkType), // #nosec G115
		InterfaceName:  pktInfo.Interface,
	}
}

// Ensure LocalSource implements PacketSource.
var _ PacketSource = (*LocalSource)(nil)
