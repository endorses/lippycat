package voip

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// sipStreamFactory manages TCP stream creation and lifecycle
type sipStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	config           *Config
	configMutex      sync.RWMutex
	// autoTuneBatchSize is the configured/profile batch size restored when
	// auto-tuning pressure clears. backpressureEnabled makes transitions
	// idempotent so the monitor does not repeatedly halve or log the same state.
	autoTuneBatchSize   int
	backpressureEnabled bool
	lastLogTime         int64
	// lastStreamLimitLogTime rate-limits the MaxStreams rejection warning
	lastStreamLimitLogTime int64
	allWorkers             sync.WaitGroup // tracks all background goroutines
	cleanupTicker          *time.Ticker
	closed                 int32             // atomic flag to track if factory is closed
	handler                SIPMessageHandler // handler for processing complete SIP messages
	callActive             func(string) bool // injected registry query for call-aware timeouts
}

type SIPStreamFactory interface {
	reassembly.StreamFactory
	Shutdown() error
}

func NewSipStreamFactory(ctx context.Context, handler SIPMessageHandler) SIPStreamFactory {
	return NewSipStreamFactoryWithConfig(ctx, handler, *GetConfig(), nil)
}

// NewSipStreamFactoryWithConfig constructs a stream factory from immutable
// configuration and an optional instance-owned call registry query. Keeping the
// query at the composition boundary prevents TCP stream aging from reaching into
// package-global call state.
func NewSipStreamFactoryWithConfig(ctx context.Context, handler SIPMessageHandler, cfg Config, callActive func(string) bool) SIPStreamFactory {
	ctx, cancel := context.WithCancel(ctx)
	config := cfg

	// Apply performance mode optimizations
	applyPerformanceModeOptimizations(&config)

	factory := &sipStreamFactory{
		ctx:               ctx,
		cancel:            cancel,
		config:            &config,
		autoTuneBatchSize: config.TCPBatchSize,
		handler:           handler,
		callActive:        callActive,
		cleanupTicker:     time.NewTicker(config.TCPCleanupInterval),
	}

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
func (f *sipStreamFactory) Shutdown() error {
	// Mark as closed
	if !atomic.CompareAndSwapInt32(&f.closed, 0, 1) {
		return nil // Already closed
	}

	// Cancel context to signal goroutines to stop
	f.cancel()

	// Stop cleanup ticker
	if f.cleanupTicker != nil {
		f.cleanupTicker.Stop()
	}

	// Wait for all background goroutines to complete
	f.allWorkers.Wait()
	return nil
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
		config.TCPLatencyOptimization = true

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
		}
	}
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	// bufferedSIPStream uses a BUFFERED channel with non-blocking sends so
	// ReassembledSG() NEVER blocks the packet capture loop - data is dropped only
	// if the buffer is full. This guarantees the capture loop always continues.

	// voip.max_streams is a hard cap (0 = unlimited): beyond it, new connections
	// get a stream that discards data instead of spawning goroutines. Without it,
	// a flood of short-lived or bogus TCP flows grows memory without bound. New
	// may run concurrently across reassembly shards, so reserve the slot with a
	// CAS instead of separating the limit check from the increment.
	current, reserved := f.reserveStreamSlot()
	if !reserved {
		tcpStreamMetrics.mu.Lock()
		tcpStreamMetrics.droppedStreams++
		tcpStreamMetrics.mu.Unlock()
		f.logStreamLimit(current)
		return &discardStream{}
	}

	// Log if we're over the soft limit (for monitoring, not enforcement).
	if current > int64(f.config.MaxGoroutines) {
		f.logGoroutineLimit()
	}

	detector := NewCallIDDetector()

	// Update metrics
	tcpStreamMetrics.mu.Lock()
	atomic.AddInt64(&tcpStreamMetrics.activeStreams, 1)
	tcpStreamMetrics.totalStreamsCreated++
	tcpStreamMetrics.mu.Unlock()

	// Create buffered stream - starts processing goroutine immediately
	// but Reassembled() never blocks due to buffered channel
	// Pass both network flow (IPs) and transport flow (ports) to construct proper endpoints
	stream := newBufferedSIPStream(f.ctx, f, detector, net, transport)

	return stream
}

func (f *sipStreamFactory) reserveStreamSlot() (int64, bool) {
	limit := int64(f.config.MaxStreams)
	for {
		current := atomic.LoadInt64(&f.activeGoroutines)
		if limit > 0 && current >= limit {
			return current, false
		}
		if atomic.CompareAndSwapInt64(&f.activeGoroutines, current, current+1) {
			return current + 1, true
		}
	}
}

// GetActiveGoroutines returns the current number of active goroutines
func (f *sipStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum number of goroutines allowed
func (f *sipStreamFactory) GetMaxGoroutines() int64 {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return int64(f.config.MaxGoroutines)
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
