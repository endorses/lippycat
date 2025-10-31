package proxy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	pb "github.com/endorses/lippycat/api/gen/management"
)

const (
	// DefaultMaxBatchSize is the maximum number of updates to batch before flushing
	DefaultMaxBatchSize = 10

	// DefaultBatchDelay is the maximum time to wait before flushing a batch
	DefaultBatchDelay = 100 * time.Millisecond
)

// TopologyUpdateBatcher batches topology updates to reduce network overhead
type TopologyUpdateBatcher struct {
	mu sync.Mutex

	// Configuration
	maxBatchSize int
	batchDelay   time.Duration

	// State
	batch     []*pb.TopologyUpdate
	timer     *time.Timer
	flushFunc func([]*pb.TopologyUpdate)
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	started   bool
}

// NewTopologyUpdateBatcher creates a new topology update batcher
func NewTopologyUpdateBatcher(flushFunc func([]*pb.TopologyUpdate)) *TopologyUpdateBatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &TopologyUpdateBatcher{
		maxBatchSize: DefaultMaxBatchSize,
		batchDelay:   DefaultBatchDelay,
		batch:        make([]*pb.TopologyUpdate, 0, DefaultMaxBatchSize),
		flushFunc:    flushFunc,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start begins batching updates
func (b *TopologyUpdateBatcher) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.started {
		return
	}

	b.started = true
	slog.Info("Topology update batcher started",
		"max_batch_size", b.maxBatchSize,
		"batch_delay", b.batchDelay)
}

// Stop stops the batcher and flushes any pending updates
func (b *TopologyUpdateBatcher) Stop() {
	b.mu.Lock()
	if !b.started {
		b.mu.Unlock()
		return
	}

	// Stop timer if active
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	// Flush any pending updates
	if len(b.batch) > 0 {
		b.flushLocked()
	}

	b.started = false
	b.mu.Unlock()

	// Cancel context and wait for goroutines
	b.cancel()
	b.wg.Wait()

	slog.Info("Topology update batcher stopped")
}

// Add adds a topology update to the batch
func (b *TopologyUpdateBatcher) Add(update *pb.TopologyUpdate) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.started {
		slog.Warn("Attempted to add update to stopped batcher, dropping update")
		return
	}

	// Add to batch
	b.batch = append(b.batch, update)

	// If this is the first update in a new batch, start the timer
	if len(b.batch) == 1 {
		b.timer = time.AfterFunc(b.batchDelay, func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.batch) > 0 {
				b.flushLocked()
			}
		})
	}

	// Flush if batch is full
	if len(b.batch) >= b.maxBatchSize {
		// Stop the timer
		if b.timer != nil {
			b.timer.Stop()
			b.timer = nil
		}
		b.flushLocked()
	}
}

// flushLocked flushes the current batch (must be called with mu held)
func (b *TopologyUpdateBatcher) flushLocked() {
	if len(b.batch) == 0 {
		return
	}

	// Copy batch to avoid holding lock during flush
	updates := make([]*pb.TopologyUpdate, len(b.batch))
	copy(updates, b.batch)

	// Clear batch
	b.batch = b.batch[:0]

	// Reset timer
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	// Flush in background to avoid blocking
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		slog.Debug("Flushing topology update batch",
			"batch_size", len(updates))

		b.flushFunc(updates)
	}()
}

// Flush immediately flushes any pending updates
func (b *TopologyUpdateBatcher) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked()
}

// SetMaxBatchSize updates the maximum batch size
func (b *TopologyUpdateBatcher) SetMaxBatchSize(size int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxBatchSize = size
}

// SetBatchDelay updates the batch delay
func (b *TopologyUpdateBatcher) SetBatchDelay(delay time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.batchDelay = delay
}
