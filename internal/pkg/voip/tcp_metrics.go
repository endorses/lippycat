package voip

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

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

	// Diagnostic counters for SIP detection failures
	streamsRejectedNonSIP int64 // Streams that returned errNotSIP (first line not SIP)
	streamsTimedOut       int64 // Streams that timed out waiting for data
	sipMessagesDetected   int64 // SIP messages successfully detected and processed

	// Reassembled() call tracking
	reassembledCalls             int64 // Total Reassembled() calls from assembler
	reassembledWithData          int64 // Reassembled() calls that received actual data
	reassembledEmptyData         int64 // Reassembled() calls with no payload (SYN/ACK)
	reassembledDataDropped       int64 // Data dropped due to full buffer
	postReassemblyDroppedBytes   int64
	streamDiscontinuities        int64
	missingSequenceBytes         int64
	parserFramingDiscontinuities int64
	recoverySuccesses            int64
	recoveryFailures             int64
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

	// Diagnostic counters for SIP detection failures
	StreamsRejectedNonSIP int64 `json:"streams_rejected_non_sip"`
	StreamsTimedOut       int64 `json:"streams_timed_out"`
	SIPMessagesDetected   int64 `json:"sip_messages_detected"`

	// Reassembled() call tracking
	ReassembledCalls             int64 `json:"reassembled_calls"`
	ReassembledWithData          int64 `json:"reassembled_with_data"`
	ReassembledEmptyData         int64 `json:"reassembled_empty_data"`
	ReassembledDataDropped       int64 `json:"reassembled_data_dropped"`
	PostReassemblyDroppedChunks  int64 `json:"post_reassembly_dropped_chunks"`
	PostReassemblyDroppedBytes   int64 `json:"post_reassembly_dropped_bytes"`
	StreamDiscontinuities        int64 `json:"stream_discontinuities"`
	MissingSequenceBytes         int64 `json:"missing_sequence_bytes"`
	ParserFramingDiscontinuities int64 `json:"parser_framing_discontinuities"`
	RecoverySuccesses            int64 `json:"recovery_successes"`
	RecoveryFailures             int64 `json:"recovery_failures"`
}

var tcpStreamMetrics = &tcpStreamMetricsInternal{
	lastMetricsUpdate: time.Now(),
}

// ResetTCPStreamMetrics starts a new capture-session accounting interval.
// It must only be called after the prior capture pipeline has stopped.
func ResetTCPStreamMetrics() {
	tcpStreamMetrics.mu.Lock()
	defer tcpStreamMetrics.mu.Unlock()
	tcpStreamMetrics.activeStreams = 0
	tcpStreamMetrics.totalStreamsCreated = 0
	tcpStreamMetrics.totalStreamsCompleted = 0
	tcpStreamMetrics.totalStreamsFailed = 0
	tcpStreamMetrics.queuedStreams = 0
	tcpStreamMetrics.droppedStreams = 0
	tcpStreamMetrics.streamsRejectedNonSIP = 0
	tcpStreamMetrics.streamsTimedOut = 0
	tcpStreamMetrics.sipMessagesDetected = 0
	tcpStreamMetrics.reassembledCalls = 0
	tcpStreamMetrics.reassembledWithData = 0
	tcpStreamMetrics.reassembledEmptyData = 0
	tcpStreamMetrics.reassembledDataDropped = 0
	tcpStreamMetrics.postReassemblyDroppedBytes = 0
	tcpStreamMetrics.streamDiscontinuities = 0
	tcpStreamMetrics.missingSequenceBytes = 0
	tcpStreamMetrics.parserFramingDiscontinuities = 0
	tcpStreamMetrics.recoverySuccesses = 0
	tcpStreamMetrics.recoveryFailures = 0
	tcpStreamMetrics.lastMetricsUpdate = time.Now()
}

// GetTCPStreamMetrics returns current TCP stream metrics
func GetTCPStreamMetrics() TCPStreamMetrics {
	tcpStreamMetrics.mu.RLock()
	defer tcpStreamMetrics.mu.RUnlock()
	// Return a copy without the mutex, using atomic load for activeStreams
	return TCPStreamMetrics{
		ActiveStreams:         atomic.LoadInt64(&tcpStreamMetrics.activeStreams),
		TotalStreamsCreated:   tcpStreamMetrics.totalStreamsCreated,
		TotalStreamsCompleted: tcpStreamMetrics.totalStreamsCompleted,
		TotalStreamsFailed:    tcpStreamMetrics.totalStreamsFailed,
		QueuedStreams:         tcpStreamMetrics.queuedStreams,
		DroppedStreams:        tcpStreamMetrics.droppedStreams,
		LastMetricsUpdate:     tcpStreamMetrics.lastMetricsUpdate,
		StreamsRejectedNonSIP: tcpStreamMetrics.streamsRejectedNonSIP,
		StreamsTimedOut:       tcpStreamMetrics.streamsTimedOut,
		SIPMessagesDetected:   tcpStreamMetrics.sipMessagesDetected,

		ReassembledCalls:             atomic.LoadInt64(&tcpStreamMetrics.reassembledCalls),
		ReassembledWithData:          atomic.LoadInt64(&tcpStreamMetrics.reassembledWithData),
		ReassembledEmptyData:         atomic.LoadInt64(&tcpStreamMetrics.reassembledEmptyData),
		ReassembledDataDropped:       atomic.LoadInt64(&tcpStreamMetrics.reassembledDataDropped),
		PostReassemblyDroppedChunks:  atomic.LoadInt64(&tcpStreamMetrics.reassembledDataDropped),
		PostReassemblyDroppedBytes:   atomic.LoadInt64(&tcpStreamMetrics.postReassemblyDroppedBytes),
		StreamDiscontinuities:        atomic.LoadInt64(&tcpStreamMetrics.streamDiscontinuities),
		MissingSequenceBytes:         atomic.LoadInt64(&tcpStreamMetrics.missingSequenceBytes),
		ParserFramingDiscontinuities: atomic.LoadInt64(&tcpStreamMetrics.parserFramingDiscontinuities),
		RecoverySuccesses:            atomic.LoadInt64(&tcpStreamMetrics.recoverySuccesses),
		RecoveryFailures:             atomic.LoadInt64(&tcpStreamMetrics.recoveryFailures),
	}
}

// IncrementNonSIPRejection increments the counter for streams rejected as non-SIP
func IncrementNonSIPRejection() {
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.streamsRejectedNonSIP++
	tcpStreamMetrics.mu.Unlock()
}

// IncrementStreamTimeout increments the counter for streams that timed out
func IncrementStreamTimeout() {
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.streamsTimedOut++
	tcpStreamMetrics.mu.Unlock()
}

// IncrementSIPMessagesDetected increments the counter for SIP messages detected
func IncrementSIPMessagesDetected() {
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.sipMessagesDetected++
	tcpStreamMetrics.mu.Unlock()
}

// IncrementReassembledCalls increments counter for ALL Reassembled() calls from assembler
func IncrementReassembledCalls() {
	atomic.AddInt64(&tcpStreamMetrics.reassembledCalls, 1)
}

// IncrementReassembledWithData increments counter for Reassembled() calls with data
func IncrementReassembledWithData() {
	atomic.AddInt64(&tcpStreamMetrics.reassembledWithData, 1)
}

// IncrementReassembledEmptyData increments counter for Reassembled() calls without data
func IncrementReassembledEmptyData() {
	atomic.AddInt64(&tcpStreamMetrics.reassembledEmptyData, 1)
}

// IncrementReassembledDataDropped increments counter for dropped data due to full buffer
func IncrementReassembledDataDropped() {
	atomic.AddInt64(&tcpStreamMetrics.reassembledDataDropped, 1)
}

// RecordPostReassemblyDrop records one whole chunk rejected by the bounded
// stream queue. Counters are cumulative for the current capture session.
func RecordPostReassemblyDrop(bytes int) {
	atomic.AddInt64(&tcpStreamMetrics.reassembledDataDropped, 1)
	atomic.AddInt64(&tcpStreamMetrics.postReassemblyDroppedBytes, int64(bytes))
	atomic.AddInt64(&tcpStreamMetrics.streamDiscontinuities, 1)
}

// RecordReassemblyDiscontinuity records absent TCP sequence space reported by
// gopacket. Missing bytes never include locally dropped payload bytes.
func RecordReassemblyDiscontinuity(bytes int) {
	if bytes <= 0 {
		return
	}
	atomic.AddInt64(&tcpStreamMetrics.streamDiscontinuities, 1)
	atomic.AddInt64(&tcpStreamMetrics.missingSequenceBytes, int64(bytes))
}

func IncrementStreamRecoverySuccess() { atomic.AddInt64(&tcpStreamMetrics.recoverySuccesses, 1) }
func IncrementStreamRecoveryFailure() { atomic.AddInt64(&tcpStreamMetrics.recoveryFailures, 1) }
func IncrementParserFramingDiscontinuity() {
	atomic.AddInt64(&tcpStreamMetrics.parserFramingDiscontinuities, 1)
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

// Health check and metrics methods for sipStreamFactory
func (f *sipStreamFactory) GetHealthStatus() map[string]interface{} {
	if f == nil {
		return map[string]interface{}{
			"status":  "factory_nil",
			"healthy": false,
		}
	}

	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	maxGoroutines := int64(f.config.MaxGoroutines)

	healthy := activeGoroutines < maxGoroutines*9/10

	status := map[string]interface{}{
		"healthy":           healthy,
		"active_goroutines": activeGoroutines,
		"max_goroutines":    maxGoroutines,
		"performance_mode":  f.config.TCPPerformanceMode,
		"last_updated":      time.Now(),
	}

	if healthy {
		status["status"] = "healthy"
	} else {
		status["status"] = "degraded"
		if activeGoroutines >= maxGoroutines {
			status["warning"] = "goroutine limit reached"
		}
	}

	return status
}

func (f *sipStreamFactory) IsHealthy() bool {
	if f == nil {
		return false
	}

	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	maxGoroutines := int64(f.config.MaxGoroutines)

	// Consider healthy if under 90% of the goroutine limit
	return activeGoroutines < maxGoroutines*9/10
}

func (f *sipStreamFactory) getGoroutineLimit() int64 {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return int64(f.config.MaxGoroutines)
}

// updateMetrics updates the TCP stream metrics
func (f *sipStreamFactory) updateMetrics() {
	tcpStreamMetrics.mu.Lock()
	tcpStreamMetrics.lastMetricsUpdate = time.Now()
	tcpStreamMetrics.mu.Unlock()
}

// logGoroutineLimit logs when goroutine limits are reached
func (f *sipStreamFactory) logGoroutineLimit() {
	current := atomic.LoadInt64(&f.activeGoroutines)
	if current >= int64(f.config.MaxGoroutines) {
		now := time.Now().Unix()
		lastLog := atomic.LoadInt64(&f.lastLogTime)

		f.configMutex.RLock()
		logInterval := int64(f.config.LogGoroutineLimitInterval.Seconds())
		f.configMutex.RUnlock()

		if now-lastLog >= logInterval {
			if atomic.CompareAndSwapInt64(&f.lastLogTime, lastLog, now) {
				logger.Warn("TCP stream goroutine limit reached",
					"active_goroutines", current,
					"max_goroutines", f.config.MaxGoroutines)
			}
		}
	}
}

// logStreamLimit logs when the hard stream cap rejects a connection, rate-limited
// to the same interval as the goroutine limit warning.
func (f *sipStreamFactory) logStreamLimit(current int64) {
	now := time.Now().Unix()
	lastLog := atomic.LoadInt64(&f.lastStreamLimitLogTime)

	f.configMutex.RLock()
	logInterval := int64(f.config.LogGoroutineLimitInterval.Seconds())
	f.configMutex.RUnlock()

	if now-lastLog >= logInterval {
		if atomic.CompareAndSwapInt64(&f.lastStreamLimitLogTime, lastLog, now) {
			tcpStreamMetrics.mu.RLock()
			dropped := tcpStreamMetrics.droppedStreams
			tcpStreamMetrics.mu.RUnlock()
			logger.Warn("TCP stream limit reached, rejecting new streams",
				"active_streams", current,
				"max_streams", f.config.MaxStreams,
				"dropped_streams", dropped)
		}
	}
}

// Performance monitoring and auto-tuning
func (f *sipStreamFactory) performanceMonitor() {
	defer f.allWorkers.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			if f.config.EnableAutoTuning {
				f.performAutoTuning()
			}
			f.updateMetrics()
		}
	}
}

func (f *sipStreamFactory) performAutoTuning() {
	activeGoroutines := atomic.LoadInt64(&f.activeGoroutines)
	f.configMutex.RLock()
	maxStreams := int64(f.config.MaxStreams)
	backpressureAllowed := f.config.EnableBackpressure
	f.configMutex.RUnlock()

	// MaxGoroutines is a soft observability threshold and is not a capacity
	// control. Base pressure on MaxStreams, the actual enforced stream limit.
	// An unlimited stream configuration has no capacity-derived pressure signal.
	if backpressureAllowed && maxStreams > 0 && activeGoroutines > maxStreams*8/10 {
		f.enableBackpressure()
	} else if !backpressureAllowed || maxStreams == 0 || activeGoroutines < maxStreams*3/10 {
		f.relaxBackpressure()
	}

	// Memory optimization if enabled
	if f.config.MemoryOptimization {
		f.performMemoryOptimization()
	}

	logger.Debug("Performance auto-tuning completed",
		"active_streams", activeGoroutines,
		"max_streams", maxStreams)
}

// getCurrentBatchSize safely gets the current batch size
func (f *sipStreamFactory) getCurrentBatchSize() int {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return f.config.TCPBatchSize
}

// enableBackpressure implements backpressure mechanisms
func (f *sipStreamFactory) enableBackpressure() {
	f.configMutex.Lock()
	defer f.configMutex.Unlock()

	if f.backpressureEnabled {
		return
	}

	f.backpressureEnabled = true
	f.config.TCPBatchSize = max(1, f.autoTuneBatchSize/2)
	logger.Info("Backpressure enabled", "new_batch_size", f.config.TCPBatchSize)
}

// relaxBackpressure reduces backpressure mechanisms
func (f *sipStreamFactory) relaxBackpressure() {
	f.configMutex.Lock()
	defer f.configMutex.Unlock()

	if !f.backpressureEnabled {
		return
	}

	f.backpressureEnabled = false
	f.config.TCPBatchSize = f.autoTuneBatchSize
	logger.Debug("Backpressure relaxed", "new_batch_size", f.config.TCPBatchSize)
}

// performMemoryOptimization implements memory usage optimizations
func (f *sipStreamFactory) performMemoryOptimization() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Convert bytes to MB for comparison (safe: memory limit is positive config value)
	currentMemoryMB := memStats.Alloc / (1024 * 1024)
	memoryLimit := uint64(f.config.TCPMemoryLimit) / (1024 * 1024) // #nosec G115

	if currentMemoryMB > memoryLimit {
		// Trigger aggressive cleanup
		cleanupOldTCPBuffers(f.config.TCPBufferMaxAge / 2)
		runtime.GC()

		logger.Info("Memory optimization triggered",
			"current_memory_mb", currentMemoryMB,
			"memory_limit_mb", memoryLimit)
	}
}
