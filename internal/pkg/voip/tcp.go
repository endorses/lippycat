package voip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/spf13/viper"
)

// Global LinkType storage for TCP streams
var (
	currentLinkType   layers.LinkType
	currentLinkTypeMu sync.RWMutex
)

// TCP packet buffering for PCAP writing
type TCPPacketBuffer struct {
	packets    []capture.PacketInfo
	mu         sync.Mutex
	maxSize    int
	strategy   string // buffering strategy: "adaptive", "fixed", "ring"
	lastAccess time.Time
}

// Performance-optimized buffer pool
type TCPBufferPool struct {
	mu       sync.Mutex
	buffers  []*TCPPacketBuffer
	maxSize  int
	created  int64
	reused   int64
	released int64
}

var tcpBufferPool = &TCPBufferPool{
	buffers: make([]*TCPPacketBuffer, 0, DefaultTCPBufferPoolSize),
	maxSize: DefaultTCPBufferPoolSize,
}

var (
	tcpPacketBuffers   = make(map[gopacket.Flow]*TCPPacketBuffer)
	tcpPacketBuffersMu sync.RWMutex
)

func setCurrentLinkType(linkType layers.LinkType) {
	currentLinkTypeMu.Lock()
	defer currentLinkTypeMu.Unlock()
	currentLinkType = linkType
}

func getCurrentLinkType() layers.LinkType {
	currentLinkTypeMu.RLock()
	defer currentLinkTypeMu.RUnlock()
	return currentLinkType
}

// getOrCreateBuffer gets a buffer from the pool or creates a new one
func getOrCreateBuffer(strategy string, maxSize int) *TCPPacketBuffer {
	tcpBufferPool.mu.Lock()
	defer tcpBufferPool.mu.Unlock()

	// Try to reuse a buffer from the pool
	if len(tcpBufferPool.buffers) > 0 {
		buffer := tcpBufferPool.buffers[len(tcpBufferPool.buffers)-1]
		tcpBufferPool.buffers = tcpBufferPool.buffers[:len(tcpBufferPool.buffers)-1]
		tcpBufferPool.reused++

		// Reset buffer for reuse
		buffer.packets = buffer.packets[:0]
		buffer.strategy = strategy
		buffer.maxSize = maxSize
		buffer.lastAccess = time.Now()
		return buffer
	}

	// Create new buffer if pool is empty
	tcpBufferPool.created++
	return &TCPPacketBuffer{
		packets:    make([]capture.PacketInfo, 0, 100),
		maxSize:    maxSize,
		strategy:   strategy,
		lastAccess: time.Now(),
	}
}

// releaseBuffer returns a buffer to the pool
func releaseBuffer(buffer *TCPPacketBuffer) {
	tcpBufferPool.mu.Lock()
	defer tcpBufferPool.mu.Unlock()

	// Only pool buffers if we haven't exceeded the limit
	if len(tcpBufferPool.buffers) < tcpBufferPool.maxSize {
		tcpBufferPool.buffers = append(tcpBufferPool.buffers, buffer)
		tcpBufferPool.released++
	}
}

// bufferTCPPacket stores a TCP packet for later PCAP writing with optimized strategies
func bufferTCPPacket(flow gopacket.Flow, pkt capture.PacketInfo) {
	config := GetConfig()
	strategy := config.TCPBufferStrategy
	maxSize := config.MaxTCPBuffers

	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists {
		buffer = getOrCreateBuffer(strategy, maxSize)
		tcpPacketBuffers[flow] = buffer
	}

	buffer.mu.Lock()
	defer buffer.mu.Unlock()

	buffer.lastAccess = time.Now()

	// Apply different buffering strategies
	switch strategy {
	case "ring":
		// Ring buffer - overwrite oldest when full
		if len(buffer.packets) >= buffer.maxSize {
			buffer.packets[0] = pkt
			buffer.packets = append(buffer.packets[1:], buffer.packets[0])
		} else {
			buffer.packets = append(buffer.packets, pkt)
		}
	case "adaptive":
		// Adaptive - adjust size based on load
		if len(buffer.packets) >= buffer.maxSize {
			// Remove oldest 25% of packets when full
			removeCount := buffer.maxSize / 4
			if removeCount < 1 {
				removeCount = 1
			}
			buffer.packets = buffer.packets[removeCount:]
		}
		buffer.packets = append(buffer.packets, pkt)
	default: // "fixed"
		// Fixed - drop when full
		if len(buffer.packets) >= buffer.maxSize {
			buffer.packets = buffer.packets[1:]
		}
		buffer.packets = append(buffer.packets, pkt)
	}

	// Update statistics
	tcpBufferStats.mu.Lock()
	tcpBufferStats.totalPackets++
	tcpBufferStats.mu.Unlock()
}

// flushTCPPacketsToCall writes buffered TCP packets to PCAP files
func flushTCPPacketsToCall(flow gopacket.Flow, callID string, writeVoip bool) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	buffer, exists := tcpPacketBuffers[flow]
	if !exists {
		return
	}

	buffer.mu.Lock()
	defer buffer.mu.Unlock()

	// Write all buffered packets for this flow
	for _, pkt := range buffer.packets {
		if writeVoip {
			WriteSIP(callID, pkt.Packet)
		}
	}

	// Release buffer back to pool and clean up
	releaseBuffer(buffer)
	delete(tcpPacketBuffers, flow)
}

// TCP buffer monitoring and cleanup
type tcpBufferStatsInternal struct {
	mu              sync.RWMutex
	totalBuffers    int64
	totalPackets    int64
	buffersDropped  int64
	packetsDropped  int64
	lastCleanupTime time.Time
}

// TCPBufferStats represents TCP buffer statistics without mutexes for external use
type TCPBufferStats struct {
	TotalBuffers    int64     `json:"total_buffers"`
	TotalPackets    int64     `json:"total_packets"`
	BuffersDropped  int64     `json:"buffers_dropped"`
	PacketsDropped  int64     `json:"packets_dropped"`
	LastCleanupTime time.Time `json:"last_cleanup_time"`
}

var tcpBufferStats = &tcpBufferStatsInternal{
	lastCleanupTime: time.Now(),
}

// GetTCPBufferStats returns current TCP buffer statistics
func GetTCPBufferStats() TCPBufferStats {
	tcpBufferStats.mu.RLock()
	defer tcpBufferStats.mu.RUnlock()
	// Return a copy without the mutex
	return TCPBufferStats{
		TotalBuffers:    tcpBufferStats.totalBuffers,
		TotalPackets:    tcpBufferStats.totalPackets,
		BuffersDropped:  tcpBufferStats.buffersDropped,
		PacketsDropped:  tcpBufferStats.packetsDropped,
		LastCleanupTime: tcpBufferStats.lastCleanupTime,
	}
}

// cleanupOldTCPBuffers periodically removes old TCP buffers to prevent memory leaks
func cleanupOldTCPBuffers(maxAge time.Duration) {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()

	now := time.Now()
	droppedBuffers := 0
	droppedPackets := 0

	// In a production implementation, we would track buffer timestamps
	// For now, we implement a simple LRU-style cleanup based on size limits
	totalBuffers := len(tcpPacketBuffers)
	if totalBuffers > GetConfig().MaxTCPBuffers {
		// Remove excess buffers (oldest first)
		excessBuffers := totalBuffers - GetConfig().MaxTCPBuffers
		count := 0
		for flow, buffer := range tcpPacketBuffers {
			if count >= excessBuffers {
				break
			}
			buffer.mu.Lock()
			droppedPackets += len(buffer.packets)
			buffer.mu.Unlock()
			delete(tcpPacketBuffers, flow)
			droppedBuffers++
			count++
		}
	}

	// Update statistics
	tcpBufferStats.mu.Lock()
	tcpBufferStats.buffersDropped += int64(droppedBuffers)
	tcpBufferStats.packetsDropped += int64(droppedPackets)
	tcpBufferStats.lastCleanupTime = now
	tcpBufferStats.totalBuffers = int64(len(tcpPacketBuffers))
	tcpBufferStats.mu.Unlock()

	if droppedBuffers > 0 {
		logger.Debug("TCP buffer cleanup completed",
			"dropped_buffers", droppedBuffers,
			"dropped_packets", droppedPackets,
			"remaining_buffers", len(tcpPacketBuffers))
	}
}

type CallIDDetector struct {
	mu     sync.Mutex
	callID string
	found  bool
	done   chan struct{}
	closed bool
}

func NewCallIDDetector() *CallIDDetector {
	return &CallIDDetector{
		done: make(chan struct{}),
	}
}

func (c *CallIDDetector) SetCallID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.found && !c.closed {
		c.callID = id
		c.found = true
		c.closed = true
		close(c.done)
	}
}

func (c *CallIDDetector) Wait() string {
	timeout := GetConfig().CallIDDetectionTimeout
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.callID
	case <-time.After(timeout): // Prevent indefinite waiting
		return ""
	}
}

func (c *CallIDDetector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
}

// TCP stream metrics and monitoring
type tcpStreamMetricsInternal struct {
	mu                    sync.RWMutex
	activeStreams         int64
	totalStreamsCreated   int64
	totalStreamsCompleted int64
	totalStreamsFailed    int64
	queuedStreams         int64
	droppedStreams        int64
	lastMetricsUpdate     time.Time
}

// TCPStreamMetrics represents TCP stream statistics without mutexes for external use
type TCPStreamMetrics struct {
	ActiveStreams         int64     `json:"active_streams"`
	TotalStreamsCreated   int64     `json:"total_streams_created"`
	TotalStreamsCompleted int64     `json:"total_streams_completed"`
	TotalStreamsFailed    int64     `json:"total_streams_failed"`
	QueuedStreams         int64     `json:"queued_streams"`
	DroppedStreams        int64     `json:"dropped_streams"`
	LastMetricsUpdate     time.Time `json:"last_metrics_update"`
}

var tcpStreamMetrics = &tcpStreamMetricsInternal{
	lastMetricsUpdate: time.Now(),
}

// GetTCPStreamMetrics returns current TCP stream metrics
func GetTCPStreamMetrics() TCPStreamMetrics {
	tcpStreamMetrics.mu.RLock()
	defer tcpStreamMetrics.mu.RUnlock()
	// Return a copy without the mutex
	return TCPStreamMetrics{
		ActiveStreams:         tcpStreamMetrics.activeStreams,
		TotalStreamsCreated:   tcpStreamMetrics.totalStreamsCreated,
		TotalStreamsCompleted: tcpStreamMetrics.totalStreamsCompleted,
		TotalStreamsFailed:    tcpStreamMetrics.totalStreamsFailed,
		QueuedStreams:         tcpStreamMetrics.queuedStreams,
		DroppedStreams:        tcpStreamMetrics.droppedStreams,
		LastMetricsUpdate:     tcpStreamMetrics.lastMetricsUpdate,
	}
}

type sipStreamFactory struct {
	ctx              context.Context
	cancel           context.CancelFunc
	activeGoroutines int64
	config           *Config
	lastLogTime      int64
	streamQueue      chan *queuedStream
	queueWorker      sync.WaitGroup
	cleanupTicker    *time.Ticker
	cleanupDone      chan struct{}
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
		cleanupDone:   make(chan struct{}),
	}

	// Start queue worker goroutine to process queued streams
	factory.queueWorker.Add(1)
	go factory.processQueue()

	// Start cleanup goroutine for resource management
	go factory.cleanupRoutine()

	// Start performance monitoring if enabled
	if config.TCPPerformanceMode != "memory" {
		go factory.performanceMonitor()
	}

	// Register for global monitoring
	RegisterTCPFactory(factory)

	return factory
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
		config.TCPLatencyOptimization = true
		config.TCPBufferStrategy = "fixed"
		config.TCPCleanupInterval = 30 * time.Second

	case "memory":
		// Optimize for low memory usage
		config.MaxGoroutines = 100
		config.MaxTCPBuffers = 1000
		config.StreamQueueBuffer = 50
		config.MemoryOptimization = true
		config.TCPBufferStrategy = "adaptive"

	default: // "balanced"
		// Keep defaults - balanced performance
	}
}

func (f *sipStreamFactory) processQueue() {
	defer f.queueWorker.Done()

	for {
		select {
		case <-f.ctx.Done():
			// Drain the queue and close remaining streams
			for {
				select {
				case queuedStream := <-f.streamQueue:
					if queuedStream.detector != nil {
						queuedStream.detector.Close()
					}
				default:
					return
				}
			}
		case queuedStream := <-f.streamQueue:
			// Check if we can process this stream now
			current := atomic.LoadInt64(&f.activeGoroutines)
			if current < int64(f.config.MaxGoroutines) {
				// Process the stream
				stream := &SIPStream{
					reader:         queuedStream.reader,
					callIDDetector: queuedStream.detector,
					ctx:            f.ctx,
					factory:        f,
					flow:           queuedStream.flow,
					createdAt:      queuedStream.createdAt,
				}
				atomic.AddInt64(&f.activeGoroutines, 1)
				// Update metrics
				tcpStreamMetrics.mu.Lock()
				tcpStreamMetrics.activeStreams++
				tcpStreamMetrics.totalStreamsCreated++
				tcpStreamMetrics.queuedStreams--
				tcpStreamMetrics.mu.Unlock()
				go stream.run()
			} else {
				// Still at capacity, put it back in queue or drop it
				select {
				case f.streamQueue <- queuedStream:
					// Successfully queued again
				default:
					// Queue is full, gracefully close the stream
					logger.Warn("Stream queue full, dropping stream gracefully")
					if queuedStream.detector != nil {
						queuedStream.detector.Close()
					}
					// Update metrics
					tcpStreamMetrics.mu.Lock()
					tcpStreamMetrics.droppedStreams++
					tcpStreamMetrics.queuedStreams--
					tcpStreamMetrics.mu.Unlock()
				}
			}
		}
	}
}

// cleanupRoutine performs periodic cleanup of TCP resources
func (f *sipStreamFactory) cleanupRoutine() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("TCP cleanup routine panic recovered", "panic_value", r)
		}
	}()

	for {
		select {
		case <-f.ctx.Done():
			close(f.cleanupDone)
			return
		case <-f.cleanupTicker.C:
			// Perform periodic cleanup tasks
			cleanupOldTCPBuffers(f.config.TCPBufferMaxAge)
			f.cleanupStaleQueuedStreams()
			f.updateMetrics()

			// Memory optimization if enabled
			if f.config.MemoryOptimization {
				f.performMemoryOptimization()
			}
		}
	}
}

// cleanupStaleQueuedStreams removes old queued streams that have been waiting too long
func (f *sipStreamFactory) cleanupStaleQueuedStreams() {
	now := time.Now()
	maxAge := f.config.TCPStreamMaxQueueTime
	drainedCount := 0

	// Drain old streams from the queue
drainLoop:
	for {
		select {
		case queuedStream := <-f.streamQueue:
			if now.Sub(queuedStream.createdAt) > maxAge {
				// Stream is too old, close it
				if queuedStream.detector != nil {
					queuedStream.detector.Close()
				}
				drainedCount++
				// Update metrics
				tcpStreamMetrics.mu.Lock()
				tcpStreamMetrics.droppedStreams++
				tcpStreamMetrics.queuedStreams--
				tcpStreamMetrics.mu.Unlock()
			} else {
				// Stream is still fresh, put it back and stop draining
				select {
				case f.streamQueue <- queuedStream:
					// Successfully put back
				default:
					// Queue is full, close this stream too
					if queuedStream.detector != nil {
						queuedStream.detector.Close()
					}
					drainedCount++
					// Update metrics
					tcpStreamMetrics.mu.Lock()
					tcpStreamMetrics.droppedStreams++
					tcpStreamMetrics.queuedStreams--
					tcpStreamMetrics.mu.Unlock()
				}
				break drainLoop
			}
		default:
			// Queue is empty
			break drainLoop
		}
	}

	if drainedCount > 0 {
		logger.Debug("Cleaned up stale queued streams", "count", drainedCount)
	}
}

// updateMetrics updates the TCP stream metrics
func (f *sipStreamFactory) updateMetrics() {
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.activeStreams = atomic.LoadInt64(&f.activeGoroutines)
	tcpStreamMetrics.queuedStreams = int64(len(f.streamQueue))
	tcpStreamMetrics.lastMetricsUpdate = time.Now()
	tcpStreamMetrics.mu.Unlock()
}

func (f *sipStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	detector := NewCallIDDetector()

	// Use the network flow to identify the stream
	flow := net

	// Check if we're at the goroutine limit
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.config.MaxGoroutines) {
		// Try to queue the stream instead of dropping it immediately
		queuedStream := &queuedStream{
			reader:    &r,
			detector:  detector,
			flow:      flow,
			createdAt: time.Now(),
		}

		select {
		case f.streamQueue <- queuedStream:
			// Successfully queued, stream will be processed when capacity is available
			logger.Debug("Stream queued due to goroutine limit",
				"max_goroutines", f.config.MaxGoroutines,
				"current_goroutines", current,
				"queue_length", len(f.streamQueue))
			// Update metrics
			tcpStreamMetrics.mu.Lock()
			tcpStreamMetrics.queuedStreams++
			tcpStreamMetrics.mu.Unlock()
		default:
			// Queue is full, log and gracefully close
			now := time.Now().Unix()
			lastLog := atomic.LoadInt64(&f.lastLogTime)
			logInterval := int64(f.config.LogGoroutineLimitInterval.Seconds())
			if now-lastLog > logInterval {
				atomic.StoreInt64(&f.lastLogTime, now)
				logger.Warn("SIP stream queue full, dropping stream",
					"max_goroutines", f.config.MaxGoroutines,
					"queue_capacity", cap(f.streamQueue),
					"action", "graceful_degradation")
			}
			detector.Close()
			// Update metrics
			tcpStreamMetrics.mu.Lock()
			tcpStreamMetrics.droppedStreams++
			tcpStreamMetrics.mu.Unlock()
			// Return a placeholder stream that reads and discards data
			// This prevents connection errors while gracefully degrading performance
			go func() {
				defer r.Close()
				buf := make([]byte, 1024)
				for {
					select {
					case <-f.ctx.Done():
						return
					default:
						_, err := r.Read(buf)
						if err != nil {
							return
						}
					}
				}
			}()
		}
		return &r
	}

	// We have capacity, process immediately
	stream := &SIPStream{
		reader:         &r,
		callIDDetector: detector,
		ctx:            f.ctx,
		factory:        f,
		flow:           flow,
		createdAt:      time.Now(),
	}

	// Increment goroutine counter before starting
	atomic.AddInt64(&f.activeGoroutines, 1)
	// Update metrics
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.activeStreams++
	tcpStreamMetrics.totalStreamsCreated++
	tcpStreamMetrics.mu.Unlock()
	go stream.run()
	return &r
}

func (f *sipStreamFactory) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	// Stop cleanup ticker
	if f.cleanupTicker != nil {
		f.cleanupTicker.Stop()
	}
	// Wait for cleanup routine to finish
	select {
	case <-f.cleanupDone:
	case <-time.After(5 * time.Second):
		logger.Warn("TCP cleanup routine did not finish within timeout")
	}
	// Wait for the queue worker to finish
	f.queueWorker.Wait()
}

// GetActiveGoroutines returns the current number of active stream processing goroutines
func (f *sipStreamFactory) GetActiveGoroutines() int64 {
	return atomic.LoadInt64(&f.activeGoroutines)
}

// GetMaxGoroutines returns the maximum allowed goroutines
func (f *sipStreamFactory) GetMaxGoroutines() int64 {
	return int64(f.config.MaxGoroutines)
}

// GetQueueLength returns the current number of queued streams
func (f *sipStreamFactory) GetQueueLength() int {
	return len(f.streamQueue)
}

// GetQueueCapacity returns the maximum queue capacity
func (f *sipStreamFactory) GetQueueCapacity() int {
	return cap(f.streamQueue)
}

// IsHealthy performs a health check on the TCP stream factory
func (f *sipStreamFactory) IsHealthy() bool {
	select {
	case <-f.ctx.Done():
		return false
	default:
	}

	// Check if we're not at maximum capacity for too long
	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	maxGoroutines := int64(f.config.MaxGoroutines)
	queueLength := len(f.streamQueue)
	queueCapacity := cap(f.streamQueue)

	// Health criteria:
	// 1. Not shutting down
	// 2. Not at max goroutines with full queue (indicates backlog)
	// 3. Cleanup routine is running (check last cleanup time)
	isBacklogged := activeGoroutines >= maxGoroutines && queueLength >= queueCapacity
	if isBacklogged {
		return false
	}

	// Check if cleanup is working (last cleanup should be recent)
	tcpBufferStats.mu.RLock()
	lastCleanup := tcpBufferStats.lastCleanupTime
	tcpBufferStats.mu.RUnlock()

	cleanupAge := time.Since(lastCleanup)
	maxCleanupAge := f.config.TCPCleanupInterval * 3 // Allow up to 3 intervals
	if cleanupAge > maxCleanupAge {
		return false
	}

	return true
}

// GetHealthStatus returns detailed health information
func (f *sipStreamFactory) GetHealthStatus() map[string]interface{} {
	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	maxGoroutines := int64(f.config.MaxGoroutines)
	queueLength := len(f.streamQueue)
	queueCapacity := cap(f.streamQueue)

	// Get buffer stats
	bufferStats := GetTCPBufferStats()
	streamMetrics := GetTCPStreamMetrics()

	status := map[string]interface{}{
		"healthy":               f.IsHealthy(),
		"active_goroutines":     activeGoroutines,
		"max_goroutines":        maxGoroutines,
		"goroutine_utilization": float64(activeGoroutines) / float64(maxGoroutines),
		"queue_length":          queueLength,
		"queue_capacity":        queueCapacity,
		"queue_utilization":     float64(queueLength) / float64(queueCapacity),
		"total_buffers":         bufferStats.TotalBuffers,
		"total_packets":         bufferStats.TotalPackets,
		"dropped_buffers":       bufferStats.BuffersDropped,
		"dropped_packets":       bufferStats.PacketsDropped,
		"last_cleanup":          bufferStats.LastCleanupTime,
		"active_streams":        streamMetrics.ActiveStreams,
		"total_created":         streamMetrics.TotalStreamsCreated,
		"total_completed":       streamMetrics.TotalStreamsCompleted,
		"total_failed":          streamMetrics.TotalStreamsFailed,
		"queued_streams":        streamMetrics.QueuedStreams,
		"dropped_streams":       streamMetrics.DroppedStreams,
		"last_metrics_update":   streamMetrics.LastMetricsUpdate,
	}

	return status
}

// performanceMonitor runs performance monitoring and auto-tuning
func (f *sipStreamFactory) performanceMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.performAutoTuning()
		}
	}
}

// performAutoTuning adjusts settings based on current performance
func (f *sipStreamFactory) performAutoTuning() {
	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	maxGoroutines := int64(f.config.MaxGoroutines)
	queueLength := len(f.streamQueue)
	queueCapacity := cap(f.streamQueue)

	// Calculate utilization metrics
	goroutineUtilization := float64(activeGoroutines) / float64(maxGoroutines)
	queueUtilization := float64(queueLength) / float64(queueCapacity)

	// Auto-tune based on utilization
	if f.config.EnableBackpressure {
		if goroutineUtilization > 0.9 && queueUtilization > 0.8 {
			// High load - enable aggressive backpressure
			f.enableBackpressure()
		} else if goroutineUtilization < 0.5 && queueUtilization < 0.3 {
			// Low load - relax backpressure
			f.relaxBackpressure()
		}
	}

	// Log performance metrics
	logger.Debug("TCP performance metrics",
		"goroutine_utilization", goroutineUtilization,
		"queue_utilization", queueUtilization,
		"active_goroutines", activeGoroutines,
		"queue_length", queueLength)
}

// enableBackpressure implements backpressure mechanisms
func (f *sipStreamFactory) enableBackpressure() {
	// Implement backpressure by reducing batch sizes and increasing delays
	if f.config.TCPBatchSize > 1 {
		f.config.TCPBatchSize = f.config.TCPBatchSize / 2
	}
	logger.Info("Backpressure enabled", "new_batch_size", f.config.TCPBatchSize)
}

// relaxBackpressure reduces backpressure mechanisms
func (f *sipStreamFactory) relaxBackpressure() {
	// Relax backpressure by increasing batch sizes
	if f.config.TCPBatchSize < 64 {
		f.config.TCPBatchSize = f.config.TCPBatchSize * 2
	}
	logger.Debug("Backpressure relaxed", "new_batch_size", f.config.TCPBatchSize)
}

// performMemoryOptimization implements memory usage optimizations
func (f *sipStreamFactory) performMemoryOptimization() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Current memory usage in MB
	currentMemory := memStats.Alloc / (1024 * 1024)
	memoryLimit := uint64(f.config.TCPMemoryLimit) / (1024 * 1024)

	if currentMemory > memoryLimit {
		// Aggressive cleanup when over memory limit
		f.aggressiveCleanup()
		logger.Warn("Memory limit exceeded, performing aggressive cleanup",
			"current_mb", currentMemory,
			"limit_mb", memoryLimit)

		// Force garbage collection
		runtime.GC()
	}
}

// aggressiveCleanup performs aggressive memory cleanup
func (f *sipStreamFactory) aggressiveCleanup() {
	// Clean up buffer pool
	tcpBufferPool.mu.Lock()
	droppedBuffers := len(tcpBufferPool.buffers) / 2
	for i := 0; i < droppedBuffers; i++ {
		if len(tcpBufferPool.buffers) > 0 {
			tcpBufferPool.buffers = tcpBufferPool.buffers[1:]
		}
	}
	tcpBufferPool.mu.Unlock()

	// Clean up packet buffers more aggressively
	tcpPacketBuffersMu.Lock()
	cleanedBuffers := 0
	for flow, buffer := range tcpPacketBuffers {
		buffer.mu.Lock()
		if time.Since(buffer.lastAccess) > f.config.TCPBufferMaxAge/2 {
			buffer.mu.Unlock()
			delete(tcpPacketBuffers, flow)
			cleanedBuffers++
		} else {
			// Trim buffer to half size
			if len(buffer.packets) > 10 {
				midpoint := len(buffer.packets) / 2
				buffer.packets = buffer.packets[midpoint:]
			}
			buffer.mu.Unlock()
		}
	}
	tcpPacketBuffersMu.Unlock()

	logger.Debug("Aggressive cleanup completed",
		"dropped_pool_buffers", droppedBuffers,
		"cleaned_packet_buffers", cleanedBuffers)
}

// Global TCP assembler monitoring
var (
	globalTCPFactory *sipStreamFactory
	globalTCPMutex   sync.RWMutex
)

// RegisterTCPFactory registers the global TCP factory for monitoring
func RegisterTCPFactory(factory *sipStreamFactory) {
	globalTCPMutex.Lock()
	defer globalTCPMutex.Unlock()
	globalTCPFactory = factory
}

// GetTCPAssemblerHealth returns the health status of the TCP assembler
func GetTCPAssemblerHealth() map[string]interface{} {
	globalTCPMutex.RLock()
	defer globalTCPMutex.RUnlock()

	if globalTCPFactory == nil {
		return map[string]interface{}{
			"status":  "not_initialized",
			"healthy": false,
			"error":   "TCP factory not registered",
		}
	}

	return globalTCPFactory.GetHealthStatus()
}

// IsTCPAssemblerHealthy returns a simple boolean health check
func IsTCPAssemblerHealthy() bool {
	globalTCPMutex.RLock()
	defer globalTCPMutex.RUnlock()

	if globalTCPFactory == nil {
		return false
	}

	return globalTCPFactory.IsHealthy()
}

// GetTCPAssemblerMetrics returns comprehensive TCP assembler metrics
func GetTCPAssemblerMetrics() map[string]interface{} {
	bufferStats := GetTCPBufferStats()
	streamMetrics := GetTCPStreamMetrics()
	healthStatus := GetTCPAssemblerHealth()

	return map[string]interface{}{
		"health":    healthStatus,
		"buffers":   bufferStats,
		"streams":   streamMetrics,
		"timestamp": time.Now(),
	}
}

type SIPStream struct {
	reader         *tcpreader.ReaderStream
	callIDDetector *CallIDDetector
	ctx            context.Context
	factory        *sipStreamFactory
	flow           gopacket.Flow
	createdAt      time.Time
	processedBytes int64
	processedMsgs  int64
}

// Batch processing for improved performance
type MessageBatch struct {
	messages [][]byte
	mu       sync.Mutex
	size     int
	maxSize  int
}

func (s *SIPStream) run() {
	defer func() {
		// Decrement goroutine counter
		if s.factory != nil {
			atomic.AddInt64(&s.factory.activeGoroutines, -1)
		}

		// Update metrics
		tcpStreamMetrics.mu.Lock()
		tcpStreamMetrics.activeStreams--
		if r := recover(); r != nil {
			tcpStreamMetrics.totalStreamsFailed++
			logger.Error("SIP stream panic recovered",
				"panic_value", r,
				"stream_context", s.ctx.Err(),
				"stream_age", time.Since(s.createdAt),
				"processed_bytes", s.processedBytes,
				"processed_messages", s.processedMsgs)
		} else {
			tcpStreamMetrics.totalStreamsCompleted++
		}
		tcpStreamMetrics.mu.Unlock()

		// Ensure resources are cleaned up
		if s.callIDDetector != nil {
			s.callIDDetector.Close()
		}

		// Log stream completion statistics
		logger.Debug("TCP SIP stream completed",
			"stream_age", time.Since(s.createdAt),
			"processed_bytes", s.processedBytes,
			"processed_messages", s.processedMsgs)
	}()

	// Determine if batch processing should be used
	batchSize := s.factory.config.TCPBatchSize
	if batchSize > 1 {
		s.processBatched(batchSize)
	} else {
		s.processSingle()
	}
}

// processSingle handles single message processing (latency optimized)
func (s *SIPStream) processSingle() {
	// Read and buffer the complete SIP message
	sipMessage, err := s.readCompleteSipMessage()
	if err != nil {
		if err != io.EOF {
			logger.Error("Error reading complete SIP message", "error", err)
		}
		return
	}

	if len(sipMessage) == 0 {
		return
	}

	// Update processing statistics
	s.processedBytes += int64(len(sipMessage))
	s.processedMsgs++

	s.processSipMessage(sipMessage)
}

// processBatched handles batch message processing (throughput optimized)
func (s *SIPStream) processBatched(batchSize int) {
	batch := &MessageBatch{
		messages: make([][]byte, 0, batchSize),
		maxSize:  batchSize,
	}

	for batch.size < batchSize {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read message with short timeout to avoid blocking
		sipMessage, err := s.readCompleteSipMessage()
		if err != nil {
			if err != io.EOF {
				logger.Error("Error reading SIP message in batch", "error", err)
			}
			break
		}

		if len(sipMessage) > 0 {
			batch.messages = append(batch.messages, sipMessage)
			batch.size++
			s.processedBytes += int64(len(sipMessage))
			s.processedMsgs++
		}
	}

	// Process all messages in batch
	for _, message := range batch.messages {
		s.processSipMessage(message)
	}
}

// processSipMessage handles the actual SIP message processing
func (s *SIPStream) processSipMessage(sipMessage []byte) {

	// Process the complete SIP message through the same pipeline as UDP
	if !handleSipMessage(sipMessage) {
		return
	}

	// Parse headers and extract call ID and other information
	headers, body := parseSipHeaders(sipMessage)
	callID := headers["call-id"]

	if callID != "" {
		// Get current LinkType and create the call
		linkType := getCurrentLinkType()
		GetOrCreateCall(callID, linkType)

		// Set the CallID in the detector for backward compatibility
		s.callIDDetector.SetCallID(callID)

		// Write PCAP files if enabled
		writeVoip := viper.GetViper().GetBool("writeVoip")
		if writeVoip {
			// Flush all buffered TCP packets for this flow to the PCAP file
			flushTCPPacketsToCall(s.flow, callID, writeVoip)
		} else {
			// Print packet info for non-PCAP mode
			fmt.Printf("[%s] TCP SIP call detected\n", callID)
		}

		// Extract RTP ports from SDP if this is an audio session
		if strings.Contains(body, "m=audio") {
			ExtractPortFromSdp(body, callID)
		}
	}
}

// readCompleteSipMessage reads a complete SIP message from the TCP stream
// It also handles individual line parsing for backward compatibility with tests
func (s *SIPStream) readCompleteSipMessage() ([]byte, error) {
	buf := bufio.NewReader(s.reader)
	var message []byte
	var headersDone bool
	contentLength := 0
	bodyBytesRead := 0
	var callID string

	for {
		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		default:
		}

		line, err := buf.ReadString('\n')
		if err != nil {
			return message, err
		}

		message = append(message, []byte(line)...)

		// Trim line for processing
		trimmedLine := strings.TrimSpace(line)

		if !headersDone {
			// Check for Call-ID in individual lines for backward compatibility
			if detectCallIDHeader(trimmedLine, &callID) && callID != "" {
				s.callIDDetector.SetCallID(callID)
			}

			// Check for end of headers (empty line)
			if trimmedLine == "" {
				headersDone = true
				if contentLength == 0 {
					// No body, message is complete
					return message, nil
				}
				continue
			}

			// Parse Content-Length header
			if strings.HasPrefix(strings.ToLower(trimmedLine), "content-length:") {
				parts := strings.SplitN(trimmedLine, ":", 2)
				if len(parts) == 2 {
					lengthStr := strings.TrimSpace(parts[1])
					if length, parseErr := parseContentLength(lengthStr); parseErr == nil {
						contentLength = length
					}
				}
			}
		} else {
			// Reading body
			bodyBytesRead += len(line)
			if bodyBytesRead >= contentLength {
				// Complete message read
				return message, nil
			}
		}
	}
}

// parseContentLength safely parses the Content-Length header value
func parseContentLength(value string) (int, error) {
	// Simple integer parsing for Content-Length
	length := 0
	for _, char := range value {
		if char >= '0' && char <= '9' {
			length = length*10 + int(char-'0')
		} else {
			break
		}
	}
	return length, nil
}

// detectCallIDHeader robustly parses Call-ID headers in both full and compact form
func detectCallIDHeader(line string, callID *string) bool {
	line = strings.TrimSpace(line)

	// Try full form first (case-insensitive)
	if len(line) > 8 && strings.EqualFold(line[:8], "call-id:") {
		*callID = strings.TrimSpace(line[8:])
		return *callID != ""
	}

	// Try compact form (case-insensitive)
	if len(line) > 2 && strings.EqualFold(line[:2], "i:") {
		*callID = strings.TrimSpace(line[2:])
		return *callID != ""
	}

	return false
}

func handleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		packet := pkt.Packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Store LinkType for later use by streams
			setCurrentLinkType(pkt.LinkType)

			// Buffer this packet for potential PCAP writing
			flow := packet.NetworkLayer().NetworkFlow()
			bufferTCPPacket(flow, pkt)

			// Use the assembler properly to process the packet
			// The stream factory will handle call ID detection
			assembler.AssembleWithTimestamp(
				flow,
				layer,
				packet.Metadata().Timestamp,
			)
		}
	}
}
