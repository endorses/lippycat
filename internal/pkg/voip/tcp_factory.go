package voip

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// sipStreamFactory manages TCP stream creation and lifecycle
type sipStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	config           *Config
	configMutex      sync.RWMutex
	lastLogTime      int64
	streamQueue      chan *queuedStream
	allWorkers       sync.WaitGroup // tracks all background goroutines
	cleanupTicker    *time.Ticker
	closed           int32 // atomic flag to track if factory is closed
}

type queuedStream struct {
	reader    *tcpreader.ReaderStream
	detector  *CallIDDetector
	flow      gopacket.Flow
	createdAt time.Time
}

func NewSipStreamFactory(ctx context.Context) tcpassembly.StreamFactory {
	ctx, cancel := context.WithCancel(ctx)
	config := GetConfig()

	// Apply performance mode optimizations
	applyPerformanceModeOptimizations(config)

	factory := &sipStreamFactory{
		ctx:           ctx,
		cancel:        cancel,
		config:        config,
		streamQueue:   make(chan *queuedStream, config.StreamQueueBuffer),
		cleanupTicker: time.NewTicker(config.TCPCleanupInterval),
	}

	// Start queue worker goroutine to process queued streams
	factory.allWorkers.Add(1)
	go factory.processQueue()

	// Start cleanup goroutine for resource management
	factory.allWorkers.Add(1)
	go factory.cleanupRoutine()

	// Start performance monitoring if enabled
	if config.TCPPerformanceMode != "memory" {
		factory.allWorkers.Add(1)
		go factory.performanceMonitor()
	}

	// Register for global monitoring
	RegisterTCPFactory(factory)

	return factory
}

// Shutdown gracefully shuts down the stream factory and waits for all goroutines to complete
func (f *sipStreamFactory) Shutdown() {
	// Mark as closed
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return // Already closed
	}

	// Cancel context to signal goroutines to stop
	f.cancel()

	// Stop cleanup ticker
	if f.cleanupTicker != nil {
		f.cleanupTicker.Stop()
	}

	// Wait for all background goroutines to complete
	f.allWorkers.Wait()
}

// applyPerformanceModeOptimizations adjusts configuration based on performance mode
func applyPerformanceModeOptimizations(config *Config) {
	switch config.TCPPerformanceMode {
	case "throughput":
		// Optimize for high throughput
		if config.MaxGoroutines < 2000 {
			config.MaxGoroutines = 2000
		}
		if config.StreamQueueBuffer < 1000 {
			config.StreamQueueBuffer = 1000
		}
		config.TCPBatchSize = 64
		config.TCPBufferStrategy = "ring"

	case "latency":
		// Optimize for low latency
		config.TCPBatchSize = 1
		if config.MaxGoroutines < 500 {
			config.MaxGoroutines = 500
		}
		config.TCPBufferStrategy = "fixed"

	case "memory":
		// Optimize for memory usage
		if config.MaxGoroutines > 100 {
			config.MaxGoroutines = 100
		}
		if config.StreamQueueBuffer > 50 {
			config.StreamQueueBuffer = 50
		}
		config.TCPBufferStrategy = "adaptive"
		config.MemoryOptimization = true

	default: // "balanced"
		// Keep default balanced settings
		config.TCPBatchSize = 32
		config.TCPBufferStrategy = "adaptive"
	}
}

// processQueue handles queued stream processing with goroutine limits
func (f *sipStreamFactory) processQueue() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case queuedStream, ok := <-f.streamQueue:
			if !ok {
				// Channel closed, exit gracefully
				return
			}
			// Check if we can process immediately
			current := atomic.LoadInt64(&f.activeGoroutines)
			if current < int64(f.config.MaxGoroutines) {
				// Create and start stream immediately
				stream := createSIPStream(
					queuedStream.reader,
					queuedStream.detector,
					f.ctx,
					f,
					queuedStream.flow,
				)
				stream.createdAt = queuedStream.createdAt
				atomic.AddInt64(&f.activeGoroutines, 1)
				// Update metrics
				tcpStreamMetrics.mu.Lock()
				atomic.AddInt64(&tcpStreamMetrics.activeStreams, 1)
				tcpStreamMetrics.totalStreamsCreated++
				tcpStreamMetrics.queuedStreams--
				tcpStreamMetrics.mu.Unlock()
				go stream.run()
			} else {
				// Still at capacity, put it back in queue or drop it
				select {
				case f.streamQueue <- queuedStream:
					// Successfully re-queued
				default:
					// Queue is full, drop the stream
					tcpStreamMetrics.mu.Lock()
					tcpStreamMetrics.droppedStreams++
					tcpStreamMetrics.mu.Unlock()
					logger.Warn("Dropped TCP stream due to full queue and goroutine limit")
				}
			}
		}
	}
}

// cleanupRoutine performs periodic cleanup of resources
func (f *sipStreamFactory) cleanupRoutine() {
	defer f.allWorkers.Done()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.cleanupTicker.C:
			// Clean up old TCP buffers
			cleanupOldTCPBuffers(f.config.TCPBufferMaxAge)

			// Perform memory optimization if enabled
			if f.config.MemoryOptimization {
				f.performMemoryOptimization()
			}

			// Clean up stale queued streams
			f.cleanupStaleQueuedStreams()
		}
	}
}

// cleanupStaleQueuedStreams removes old queued streams
func (f *sipStreamFactory) cleanupStaleQueuedStreams() {
	maxAge := f.config.TCPStreamMaxQueueTime
	drainedCount := 0

	// Drain stale streams from queue
drainLoop:
	for {
		select {
		case queuedStream := <-f.streamQueue:
			if time.Since(queuedStream.createdAt) > maxAge {
				drainedCount++
				// Update metrics for dropped stream
				tcpStreamMetrics.mu.Lock()
				tcpStreamMetrics.droppedStreams++
				tcpStreamMetrics.queuedStreams--
				tcpStreamMetrics.mu.Unlock()
			} else {
				// Put non-stale stream back
				select {
				case f.streamQueue <- queuedStream:
				default:
					drainedCount++
				}
			}
		default:
			break drainLoop
		}
	}

	if drainedCount > 0 {
		logger.Debug("Cleaned up stale queued streams", "count", drainedCount)
	}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	detector := NewCallIDDetector()

	// Check current goroutine count
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.config.MaxGoroutines) {
		// Log goroutine limit reached
		f.logGoroutineLimit()

		// Try to queue the stream for later processing
		queuedStream := &queuedStream{
			reader:    &r,
			detector:  detector,
			flow:      net,
			createdAt: time.Now(),
		}

		select {
		case f.streamQueue <- queuedStream:
			// Successfully queued
			tcpStreamMetrics.mu.Lock()
			tcpStreamMetrics.queuedStreams++
			tcpStreamMetrics.mu.Unlock()
		default:
			// Queue is full, drop the stream
			tcpStreamMetrics.mu.Lock()
			tcpStreamMetrics.droppedStreams++
			tcpStreamMetrics.mu.Unlock()
			logger.Warn("Dropped TCP stream due to full queue",
				"active_goroutines", current,
				"max_goroutines", f.config.MaxGoroutines,
				"queue_length", len(f.streamQueue))
		}

		return &r
	}

	// Create stream immediately
	stream := createSIPStream(&r, detector, f.ctx, f, net)

	// Increment goroutine counter before starting
	atomic.AddInt64(&f.activeGoroutines, 1)
	// Update metrics
	tcpStreamMetrics.mu.Lock()
	atomic.AddInt64(&tcpStreamMetrics.activeStreams, 1)
	tcpStreamMetrics.totalStreamsCreated++
	tcpStreamMetrics.mu.Unlock()
	go stream.run()
	return &r
}

// GetActiveGoroutines returns the current number of active goroutines
func (f *sipStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum number of goroutines allowed
func (f *sipStreamFactory) GetMaxGoroutines() int {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return f.config.MaxGoroutines
}

func (f *sipStreamFactory) Close() {
	// Use atomic compare-and-swap to ensure Close is only executed once
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return // Already closed
	}

	// Cancel context to stop all goroutines
	f.cancel()

	// Stop cleanup ticker
	f.cleanupTicker.Stop()

	// Close stream queue to signal processQueue to exit
	close(f.streamQueue)

	// Wait for all background workers to finish
	f.allWorkers.Wait()

	// Log remaining metrics
	tcpStreamMetrics.mu.Lock()
	if tcpStreamMetrics.queuedStreams > 0 {
		tcpStreamMetrics.droppedStreams += tcpStreamMetrics.queuedStreams
		tcpStreamMetrics.queuedStreams = 0
	}
	tcpStreamMetrics.mu.Unlock()

	logger.Info("TCP stream factory closed")
}
