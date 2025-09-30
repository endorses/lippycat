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
	// Return a copy without the mutex, using atomic load for activeStreams
	return TCPStreamMetrics{
		ActiveStreams:         atomic.LoadInt64(&tcpStreamMetrics.activeStreams),
		TotalStreamsCreated:   tcpStreamMetrics.totalStreamsCreated,
		TotalStreamsCompleted: tcpStreamMetrics.totalStreamsCompleted,
		TotalStreamsFailed:    tcpStreamMetrics.totalStreamsFailed,
		QueuedStreams:         tcpStreamMetrics.queuedStreams,
		DroppedStreams:        tcpStreamMetrics.droppedStreams,
		LastMetricsUpdate:     tcpStreamMetrics.lastMetricsUpdate,
	}
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

	f.configMutex.RLock()
	queueLength := len(f.streamQueue)
	f.configMutex.RUnlock()

	healthy := activeGoroutines < maxGoroutines*9/10 && queueLength < cap(f.streamQueue)*9/10

	status := map[string]interface{}{
		"healthy":           healthy,
		"active_goroutines": activeGoroutines,
		"max_goroutines":    maxGoroutines,
		"queue_length":      queueLength,
		"queue_capacity":    cap(f.streamQueue),
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
		if queueLength >= cap(f.streamQueue) {
			status["warning"] = "queue capacity exceeded"
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

	f.configMutex.RLock()
	queueLength := len(f.streamQueue)
	queueCapacity := cap(f.streamQueue)
	f.configMutex.RUnlock()

	// Consider healthy if under 90% of limits
	return activeGoroutines < maxGoroutines*9/10 && queueLength < queueCapacity*9/10
}

func (f *sipStreamFactory) getGoroutineLimit() int64 {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return int64(f.config.MaxGoroutines)
}

// updateMetrics updates the TCP stream metrics
func (f *sipStreamFactory) updateMetrics() {
	tcpStreamMetrics.mu.Lock()
	// Keep activeStreams and activeGoroutines in sync via atomic operations
	tcpStreamMetrics.queuedStreams = int64(len(f.streamQueue))
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
					"max_goroutines", f.config.MaxGoroutines,
					"queue_length", len(f.streamQueue))
			}
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
	maxGoroutines := int64(f.config.MaxGoroutines)
	queueLength := int64(len(f.streamQueue))

	// Auto-tune based on load
	if activeGoroutines > maxGoroutines*8/10 || queueLength > int64(cap(f.streamQueue))*7/10 {
		f.enableBackpressure()
	} else if activeGoroutines < maxGoroutines*3/10 && queueLength < int64(cap(f.streamQueue))*2/10 {
		f.relaxBackpressure()
	}

	// Memory optimization if enabled
	if f.config.MemoryOptimization {
		f.performMemoryOptimization()
	}

	logger.Debug("Performance auto-tuning completed",
		"active_goroutines", activeGoroutines,
		"queue_length", queueLength)
}

// getCurrentBatchSize safely gets the current batch size
func (f *sipStreamFactory) getCurrentBatchSize() int {
	f.configMutex.RLock()
	defer f.configMutex.RUnlock()
	return f.config.TCPBatchSize
}

// enableBackpressure implements backpressure mechanisms
func (f *sipStreamFactory) enableBackpressure() {
	// Implement backpressure by reducing batch sizes and increasing delays
	f.configMutex.Lock()
	defer f.configMutex.Unlock()

	if f.config.TCPBatchSize > 1 {
		f.config.TCPBatchSize = f.config.TCPBatchSize / 2
	}
	logger.Info("Backpressure enabled", "new_batch_size", f.config.TCPBatchSize)
}

// relaxBackpressure reduces backpressure mechanisms
func (f *sipStreamFactory) relaxBackpressure() {
	// Relax backpressure by increasing batch sizes
	f.configMutex.Lock()
	defer f.configMutex.Unlock()

	if f.config.TCPBatchSize < 64 {
		f.config.TCPBatchSize = f.config.TCPBatchSize * 2
	}
	logger.Debug("Backpressure relaxed", "new_batch_size", f.config.TCPBatchSize)
}

// performMemoryOptimization implements memory usage optimizations
func (f *sipStreamFactory) performMemoryOptimization() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Convert bytes to MB for comparison
	currentMemoryMB := memStats.Alloc / (1024 * 1024)
	memoryLimit := uint64(f.config.TCPMemoryLimit) / (1024 * 1024)

	if currentMemoryMB > memoryLimit {
		// Trigger aggressive cleanup
		cleanupOldTCPBuffers(f.config.TCPBufferMaxAge / 2)
		runtime.GC()

		logger.Info("Memory optimization triggered",
			"current_memory_mb", currentMemoryMB,
			"memory_limit_mb", memoryLimit)
	}
}
