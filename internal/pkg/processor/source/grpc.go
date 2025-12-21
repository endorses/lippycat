// Package source - GRPCSource Implementation
//
// GRPCSource implements the PacketSource interface for receiving packets
// from remote hunters via gRPC streaming. It serves as the packet source
// for the distributed capture architecture.
//
// Architecture:
//
//	Hunters → gRPC StreamPackets → GRPCSource.Push() → Batches() channel → Processor
//
// The source is used with the existing Processor gRPC handlers:
//   - StreamPackets calls Push() when it receives a batch from a hunter
//   - processBatch() consumes from Batches() channel
//   - HunterManager provides hunter registration and monitoring
package source

import (
	"context"
	"sync"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/hunter"
)

// GRPCSource receives packets from hunters via gRPC streaming.
// It implements the PacketSource interface for the distributed capture mode.
type GRPCSource struct {
	processorID   string
	hunterManager *hunter.Manager

	// Packet batch channel for processing
	batches chan *PacketBatch

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

// GRPCSourceConfig contains configuration for GRPCSource.
type GRPCSourceConfig struct {
	ProcessorID   string
	HunterManager *hunter.Manager
	BatchBuffer   int // Channel buffer size (default: 1000)
}

// NewGRPCSource creates a new GRPCSource.
func NewGRPCSource(cfg GRPCSourceConfig) *GRPCSource {
	bufferSize := cfg.BatchBuffer
	if bufferSize == 0 {
		bufferSize = 1000 // Default buffer size
	}

	return &GRPCSource{
		processorID:   cfg.ProcessorID,
		hunterManager: cfg.HunterManager,
		batches:       make(chan *PacketBatch, bufferSize),
		stats:         NewAtomicStats(),
	}
}

// Start begins the packet source operation.
// For GRPCSource, this primarily sets up the context and waits for shutdown.
// The actual packet reception happens in Push() called by StreamPackets handler.
func (s *GRPCSource) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	logger.Info("GRPCSource started", "processor_id", s.processorID)

	// Wait for context cancellation
	<-s.ctx.Done()

	// Close batches channel to signal consumers
	close(s.batches)

	// Wait for any pending operations
	s.wg.Wait()

	logger.Info("GRPCSource stopped", "processor_id", s.processorID)
	return nil
}

// Batches returns the channel that receives packet batches from hunters.
func (s *GRPCSource) Batches() <-chan *PacketBatch {
	return s.batches
}

// Stats returns current packet source statistics.
func (s *GRPCSource) Stats() Stats {
	return s.stats.Snapshot()
}

// SourceID returns the unique identifier for this source.
func (s *GRPCSource) SourceID() string {
	return "grpc"
}

// Push sends a packet batch from a hunter to the processing pipeline.
// This method is called by the Processor's StreamPackets gRPC handler.
// It converts the protobuf batch to the internal format and sends it to the channel.
//
// Returns true if the batch was sent, false if the source is stopped or buffer is full.
func (s *GRPCSource) Push(batch *data.PacketBatch) bool {
	// Convert protobuf batch to internal format
	internalBatch := FromProtoBatch(batch)
	if internalBatch == nil {
		return false
	}

	// Update stats
	for _, pkt := range batch.Packets {
		s.stats.AddPacket(uint64(len(pkt.Data)))
	}
	s.stats.AddBatch()

	// Non-blocking send to prevent hunter stream from blocking
	select {
	case s.batches <- internalBatch:
		return true
	default:
		// Buffer full - log and drop
		s.stats.AddDropped(uint64(len(batch.Packets)))
		logger.Warn("GRPCSource batch buffer full, dropping batch",
			"hunter_id", batch.HunterId,
			"packets", len(batch.Packets),
			"sequence", batch.Sequence)
		return false
	}
}

// PushInternal sends an already-converted internal batch to the processing pipeline.
// This method is useful when batches are already in internal format.
func (s *GRPCSource) PushInternal(batch *PacketBatch) bool {
	if batch == nil {
		return false
	}

	// Update stats
	for _, pkt := range batch.Packets {
		s.stats.AddPacket(uint64(len(pkt.Data)))
	}
	s.stats.AddBatch()

	// Non-blocking send
	select {
	case s.batches <- batch:
		return true
	default:
		s.stats.AddDropped(uint64(len(batch.Packets)))
		logger.Warn("GRPCSource batch buffer full, dropping batch",
			"source_id", batch.SourceID,
			"packets", len(batch.Packets),
			"sequence", batch.Sequence)
		return false
	}
}

// HunterManager returns the hunter manager for distributed mode operations.
// This provides access to hunter registration, heartbeat, and status management.
func (s *GRPCSource) HunterManager() *hunter.Manager {
	return s.hunterManager
}

// Stop gracefully stops the source.
func (s *GRPCSource) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}
}

// IsStarted returns whether the source has been started.
func (s *GRPCSource) IsStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// Ensure GRPCSource implements PacketSource.
var _ PacketSource = (*GRPCSource)(nil)
