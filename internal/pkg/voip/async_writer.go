//go:build cli || all

package voip

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// PacketWriteRequest represents a packet write operation
type PacketWriteRequest struct {
	CallID     string
	Packet     gopacket.Packet
	PacketType PacketType
	Timestamp  time.Time
	ResultChan chan<- error // Optional channel to receive write result
}

// AsyncWriterPool manages multiple worker goroutines for async PCAP writing
type AsyncWriterPool struct {
	tracker *CallTracker
	// Configuration
	workerCount   int
	bufferSize    int
	workerTimeout time.Duration

	// Worker management
	ctx      context.Context
	cancel   context.CancelFunc
	workerWg sync.WaitGroup
	// writeQueues holds one queue per worker. Requests are sharded by Call-ID
	// so every packet of a call is written by the same worker, which is what
	// keeps packet order in the per-call PCAP. A single shared queue drained by
	// N workers reorders packets within a call.
	writeQueues []chan PacketWriteRequest
	started     atomic.Bool
	stopped     atomic.Bool
	// admissionMu makes accepting a request and closing the queues mutually
	// exclusive. An atomic stopped check alone is insufficient: Stop could close
	// a queue after a writer observed stopped=false but before it sent.
	admissionMu sync.RWMutex
	stopDone    chan struct{}

	// Statistics
	stats AsyncWriterStats

	// Callbacks
	onError func(callID string, err error)
}

// AsyncWriterStats tracks async writer performance metrics
type AsyncWriterStats struct {
	PacketsQueued    atomic.Int64
	PacketsWritten   atomic.Int64
	PacketsDropped   atomic.Int64
	WriteErrors      atomic.Int64
	QueueFullEvents  atomic.Int64
	AverageQueueTime atomic.Int64 // Nanoseconds
	WorkersActive    atomic.Int32
}

// NewAsyncWriterPool creates a new async writer pool
func NewAsyncWriterPool(workerCount, bufferSize int) *AsyncWriterPool {
	return NewAsyncWriterPoolWithTracker(NewCallTracker(), workerCount, bufferSize)
}

// NewAsyncWriterPoolWithTracker constructs a writer bound to one call tracker.
func NewAsyncWriterPoolWithTracker(tracker *CallTracker, workerCount, bufferSize int) *AsyncWriterPool {
	if workerCount <= 0 {
		workerCount = 4 // Default worker count
	}
	if bufferSize <= 0 {
		bufferSize = 1000 // Default buffer size
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Each queue gets the full configured depth rather than a 1/workerCount
	// slice of it: queues drop on overflow, and splitting would make a single
	// busy call hit the drop threshold workerCount times sooner. The extra
	// capacity costs only queue slots — the packet data behind them is
	// in-flight either way.
	writeQueues := make([]chan PacketWriteRequest, workerCount)
	for i := range writeQueues {
		writeQueues[i] = make(chan PacketWriteRequest, bufferSize)
	}

	return &AsyncWriterPool{
		tracker:       tracker,
		workerCount:   workerCount,
		bufferSize:    bufferSize,
		workerTimeout: 5 * time.Second,
		ctx:           ctx,
		cancel:        cancel,
		writeQueues:   writeQueues,
		stopDone:      make(chan struct{}),
		onError: func(callID string, err error) {
			logger.Error("Async write error",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
		},
	}
}

// Start begins the async writer workers
func (p *AsyncWriterPool) Start() error {
	if p.started.Load() {
		return nil // Already started
	}

	logger.Info("Starting async writer pool",
		"workers", p.workerCount,
		"buffer_size", p.bufferSize)

	for i := 0; i < p.workerCount; i++ {
		p.workerWg.Add(1)
		go p.worker(i)
	}

	p.started.Store(true)
	return nil
}

// Stop gracefully shuts down the async writer pool
func (p *AsyncWriterPool) Stop() error {
	// Close the write queues and let the workers drain what is still queued.
	// Cancelling the context here instead would race the workers and silently
	// discard packets that were accepted for writing, losing the tail of every
	// capture. The context is only cancelled once draining is done (or has
	// timed out), as an escape hatch for a wedged writer.
	p.admissionMu.Lock()
	if p.stopped.Load() {
		p.admissionMu.Unlock()
		<-p.stopDone
		return nil // Already stopped
	}

	logger.Info("Stopping async writer pool")
	p.stopped.Store(true)
	for _, q := range p.writeQueues {
		close(q)
	}
	p.admissionMu.Unlock()

	// Wait for all workers to finish with timeout
	done := make(chan struct{})
	go func() {
		p.workerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Async writer pool stopped gracefully")
	case <-time.After(10 * time.Second):
		logger.Warn("Async writer pool stop timeout, abandoning queued packets")
	}
	p.cancel()
	close(p.stopDone)

	return nil
}

// WritePacketAsync queues a packet for async writing
func (p *AsyncWriterPool) WritePacketAsync(callID string, packet gopacket.Packet, packetType PacketType) error {
	p.admissionMu.RLock()
	defer p.admissionMu.RUnlock()

	if p.stopped.Load() {
		return ErrWriterStopped
	}

	req := PacketWriteRequest{
		CallID:     callID,
		Packet:     packet,
		PacketType: packetType,
		Timestamp:  time.Now(),
	}

	// Try to queue the request
	select {
	case p.queueFor(callID) <- req:
		p.stats.PacketsQueued.Add(1)
		return nil
	default:
		// Queue is full, drop the packet
		p.stats.PacketsDropped.Add(1)
		p.stats.QueueFullEvents.Add(1)
		return ErrQueueFull
	}
}

// WritePacketSync queues a packet for async writing and waits for completion
func (p *AsyncWriterPool) WritePacketSync(callID string, packet gopacket.Packet, packetType PacketType) error {
	p.admissionMu.RLock()
	if p.stopped.Load() {
		p.admissionMu.RUnlock()
		return ErrWriterStopped
	}

	resultChan := make(chan error, 1)
	req := PacketWriteRequest{
		CallID:     callID,
		Packet:     packet,
		PacketType: packetType,
		Timestamp:  time.Now(),
		ResultChan: resultChan,
	}

	// Try to queue the request
	select {
	case p.queueFor(callID) <- req:
		p.stats.PacketsQueued.Add(1)
		p.admissionMu.RUnlock()
		// Wait for result
		select {
		case err := <-resultChan:
			return err
		case <-time.After(p.workerTimeout):
			return ErrWriteTimeout
		}
	default:
		p.admissionMu.RUnlock()
		// Queue is full
		p.stats.PacketsDropped.Add(1)
		p.stats.QueueFullEvents.Add(1)
		return ErrQueueFull
	}
}

// queueFor maps a Call-ID to a fixed worker queue (FNV-1a) so that all writes
// for one call are serialised through a single worker and land in the per-call
// PCAP in capture order.
func (p *AsyncWriterPool) queueFor(callID string) chan PacketWriteRequest {
	const (
		fnvOffset32 = 2166136261
		fnvPrime32  = 16777619
	)
	h := uint32(fnvOffset32)
	for i := 0; i < len(callID); i++ {
		h ^= uint32(callID[i])
		h *= fnvPrime32
	}
	return p.writeQueues[h%uint32(len(p.writeQueues))]
}

// worker processes write requests from its own queue
func (p *AsyncWriterPool) worker(workerID int) {
	defer p.workerWg.Done()
	p.stats.WorkersActive.Add(1)
	defer p.stats.WorkersActive.Add(-1)

	logger.Debug("Async writer worker started", "worker_id", workerID)

	queue := p.writeQueues[workerID]

	for {
		select {
		case <-p.ctx.Done():
			logger.Debug("Async writer worker stopping due to context cancellation", "worker_id", workerID)
			return

		case req, ok := <-queue:
			if !ok {
				logger.Debug("Async writer worker stopping due to closed queue", "worker_id", workerID)
				return
			}

			// Process the write request
			err := p.processWriteRequest(req)

			// Update statistics
			if err != nil {
				p.stats.WriteErrors.Add(1)
				if p.onError != nil {
					p.onError(req.CallID, err)
				}
			} else {
				p.stats.PacketsWritten.Add(1)
			}

			// Calculate and update queue time
			queueTime := time.Since(req.Timestamp).Nanoseconds()
			p.updateAverageQueueTime(queueTime)

			// Send result back if channel provided
			if req.ResultChan != nil {
				select {
				case req.ResultChan <- err:
				default:
					// Channel might be closed or not being read
				}
			}
		}
	}
}

// processWriteRequest handles the actual writing of a packet
func (p *AsyncWriterPool) processWriteRequest(req PacketWriteRequest) error {
	tracker := p.tracker

	// Track active write
	tracker.activeWrites.Add(1)
	defer tracker.activeWrites.Done()
	// Requests already admitted to the pool must drain during shutdown. The
	// stopped flag prevents new admissions while these accepted writes finish.

	tracker.mu.RLock()
	_, exists := tracker.callMap[req.CallID]
	tracker.mu.RUnlock()

	if !exists {
		return ErrCallNotFound
	}

	// Validate the Call-ID for security
	if err := ValidateCallIDForSecurity(req.CallID); err != nil {
		logger.Warn("Malicious Call-ID detected in async writer",
			"call_id", SanitizeCallIDForLogging(req.CallID),
			"error", err,
			"source", "async_writer")
		return err
	}

	// Determine which writer to use and lock appropriately
	var err error
	switch req.PacketType {
	case PacketTypeSIP:
		err = p.tracker.output.WritePacket(req.CallID, req.Packet, PacketTypeSIP)
	case PacketTypeRTP:
		err = p.tracker.output.WritePacket(req.CallID, req.Packet, PacketTypeRTP)
	default:
		return ErrInvalidPacketType
	}
	if err == nil {
		// Update call's last updated time (with minimal locking)
		tracker.mu.Lock()
		if call, exists := tracker.callMap[req.CallID]; exists {
			call.LastUpdated = time.Now()
		}
		tracker.mu.Unlock()
	}

	return err
}

// updateAverageQueueTime updates the running average of queue time
func (p *AsyncWriterPool) updateAverageQueueTime(newTime int64) {
	for {
		current := p.stats.AverageQueueTime.Load()
		// Simple exponential moving average (α = 0.1)
		newAvg := current*9/10 + newTime/10
		if p.stats.AverageQueueTime.CompareAndSwap(current, newAvg) {
			break
		}
	}
}

// GetStats returns a snapshot of the current statistics
func (p *AsyncWriterPool) GetStats() *AsyncWriterStats {
	stats := &AsyncWriterStats{}
	// Load current values atomically
	stats.PacketsQueued.Store(p.stats.PacketsQueued.Load())
	stats.PacketsWritten.Store(p.stats.PacketsWritten.Load())
	stats.PacketsDropped.Store(p.stats.PacketsDropped.Load())
	stats.WriteErrors.Store(p.stats.WriteErrors.Load())
	stats.QueueFullEvents.Store(p.stats.QueueFullEvents.Load())
	stats.AverageQueueTime.Store(p.stats.AverageQueueTime.Load())
	stats.WorkersActive.Store(p.stats.WorkersActive.Load())
	return stats
}

// SetErrorHandler sets a custom error handler
func (p *AsyncWriterPool) SetErrorHandler(handler func(callID string, err error)) {
	p.onError = handler
}

// GetAsyncWriter returns the writer pool owned by tracker.
func GetAsyncWriter(tracker *CallTracker) *AsyncWriterPool {
	if tracker == nil {
		return nil
	}
	tracker.asyncWriterMu.Lock()
	defer tracker.asyncWriterMu.Unlock()
	pool, _ := tracker.asyncWriter.(*AsyncWriterPool)
	if pool == nil || pool.stopped.Load() {
		config := tracker.config
		workerCount := config.TCPIOThreads
		if workerCount <= 0 {
			workerCount = 4
		}
		bufferSize := config.StreamQueueBuffer
		if bufferSize <= 0 {
			bufferSize = 1000
		}

		pool = NewAsyncWriterPoolWithTracker(tracker, workerCount, bufferSize)
		tracker.asyncWriter = pool

		// Start the async writer automatically
		if err := pool.Start(); err != nil {
			logger.Error("Failed to start async writer pool", "error", err)
		}
	}
	return pool
}

func (tracker *CallTracker) closeAsyncWriter() {
	tracker.asyncWriterMu.Lock()
	defer tracker.asyncWriterMu.Unlock()
	if tracker.asyncWriter != nil {
		if err := tracker.asyncWriter.Stop(); err != nil {
			logger.Error("Failed to stop async writer pool", "error", err)
		}
		tracker.asyncWriter = nil
	}
}
