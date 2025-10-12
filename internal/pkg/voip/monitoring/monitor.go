package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Monitor coordinates all monitoring subsystems
type Monitor struct {
	enabled          atomic.Bool
	metricsCollector *MetricsCollector
	tracingExporter  *TracingExporter
	updateInterval   time.Duration
	stopChan         chan struct{}
	wg               sync.WaitGroup
	mu               sync.RWMutex
}

// MonitorConfig contains configuration for the monitoring system
type MonitorConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	MetricsEnabled       bool          `mapstructure:"metrics_enabled"`
	TracingEnabled       bool          `mapstructure:"tracing_enabled"`
	UpdateInterval       time.Duration `mapstructure:"update_interval"`
	EnableRuntimeMetrics bool          `mapstructure:"enable_runtime_metrics"`
	EnableSystemMetrics  bool          `mapstructure:"enable_system_metrics"`
	EnablePluginMetrics  bool          `mapstructure:"enable_plugin_metrics"`
}

// NewMonitor creates a new monitoring coordinator
func NewMonitor(config MonitorConfig) *Monitor {
	monitor := &Monitor{
		metricsCollector: NewMetricsCollector(),
		tracingExporter:  NewTracingExporter("lippycat"),
		updateInterval:   config.UpdateInterval,
		stopChan:         make(chan struct{}),
	}

	if config.UpdateInterval == 0 {
		monitor.updateInterval = 30 * time.Second
	}

	return monitor
}

// Enable starts all configured monitoring subsystems
func (m *Monitor) Enable(config MonitorConfig) error {
	if m.enabled.Load() {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("Starting monitoring system", "config", config)

	// Start metrics collection if enabled
	if config.MetricsEnabled {
		m.metricsCollector.Enable()
		logger.Info("Internal metrics collection enabled")
	}

	// Start tracing if enabled
	if config.TracingEnabled {
		m.tracingExporter.Enable()
		logger.Info("Distributed tracing enabled")
	}

	// Start monitoring loop
	m.wg.Add(1)
	go m.monitoringLoop(config)

	m.enabled.Store(true)
	logger.Info("Monitoring system started successfully")
	return nil
}

// Disable stops all monitoring subsystems
func (m *Monitor) Disable() error {
	if !m.enabled.Load() {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("Stopping monitoring system")

	// Stop monitoring loop
	close(m.stopChan)
	m.wg.Wait()

	// Disable subsystems
	m.metricsCollector.Disable()
	m.tracingExporter.Disable()

	m.enabled.Store(false)
	logger.Info("Monitoring system stopped")
	return nil
}

// IsEnabled returns whether monitoring is enabled
func (m *Monitor) IsEnabled() bool {
	return m.enabled.Load()
}

// monitoringLoop runs the main monitoring update loop
func (m *Monitor) monitoringLoop(config MonitorConfig) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			logger.Debug("Monitoring loop stopping")
			return
		case <-ticker.C:
			m.updateMetrics(config)
		}
	}
}

// updateMetrics updates all monitoring metrics
func (m *Monitor) updateMetrics(config MonitorConfig) {
	if !m.enabled.Load() {
		return
	}

	// Collect runtime metrics if enabled
	if config.EnableRuntimeMetrics {
		m.collectRuntimeMetrics()
	}

	// Collect system metrics if enabled
	if config.EnableSystemMetrics {
		m.collectSystemMetrics()
	}

	logger.Debug("Updated monitoring metrics")
}

// collectRuntimeMetrics collects Go runtime metrics
func (m *Monitor) collectRuntimeMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Memory metrics (uint64 -> int64 conversions are safe: memory won't exceed 9 exabytes)
	m.metricsCollector.SetGauge("runtime_alloc_bytes", int64(memStats.Alloc))            // #nosec G115
	m.metricsCollector.SetGauge("runtime_total_alloc_bytes", int64(memStats.TotalAlloc)) // #nosec G115
	m.metricsCollector.SetGauge("runtime_sys_bytes", int64(memStats.Sys))                // #nosec G115
	m.metricsCollector.SetGauge("runtime_heap_alloc_bytes", int64(memStats.HeapAlloc))   // #nosec G115
	m.metricsCollector.SetGauge("runtime_heap_inuse_bytes", int64(memStats.HeapInuse))   // #nosec G115
	m.metricsCollector.SetGauge("runtime_heap_idle_bytes", int64(memStats.HeapIdle))     // #nosec G115

	// GC metrics (uint64/uint32 -> int64 conversions are safe: won't overflow in practice)
	m.metricsCollector.SetGauge("runtime_gc_cycles", int64(memStats.NumGC))          // #nosec G115
	m.metricsCollector.SetGauge("runtime_gc_pause_ns", int64(memStats.PauseTotalNs)) // #nosec G115

	// Goroutine metrics
	m.metricsCollector.SetGauge("runtime_goroutines", int64(runtime.NumGoroutine()))

	// CPU metrics
	m.metricsCollector.SetGauge("runtime_num_cpu", int64(runtime.NumCPU()))
}

// collectSystemMetrics collects system-level metrics
func (m *Monitor) collectSystemMetrics() {
	// These would typically come from system monitoring libraries
	// For now, we'll collect basic application metrics

	// Update timestamp
	m.metricsCollector.SetGauge("system_uptime_seconds", time.Now().Unix())

	// In a real implementation, you might collect:
	// - CPU usage
	// - Memory usage
	// - Disk I/O
	// - Network I/O
	// - File descriptor count
	// etc.
}

// GetMetricsCollector returns the metrics collector
func (m *Monitor) GetMetricsCollector() *MetricsCollector {
	return m.metricsCollector
}

// GetTracingExporter returns the tracing exporter
func (m *Monitor) GetTracingExporter() *TracingExporter {
	return m.tracingExporter
}

// GetStats returns comprehensive monitoring statistics
func (m *Monitor) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled": m.enabled.Load(),
		"components": map[string]interface{}{
			"metrics": m.metricsCollector.GetAllMetrics(),
			"tracing": m.tracingExporter.GetStats(),
		},
	}

	return stats
}

// RecordVoIPEvent records a VoIP-specific event with comprehensive metrics and tracing
func (m *Monitor) RecordVoIPEvent(ctx context.Context, eventType string, metadata map[string]interface{}) {
	if !m.enabled.Load() {
		return
	}

	// Record metrics
	m.metricsCollector.IncrementCounter(fmt.Sprintf("voip_events_%s", eventType))

	// Add trace info if span exists
	if span := SpanFromContext(ctx); span != nil {
		span.AddTag("event_type", eventType)
		for key, value := range metadata {
			span.AddTag(key, value)
		}
		span.LogInfo(fmt.Sprintf("VoIP event: %s", eventType), metadata)
	}
}

// RecordPacketProcessing records packet processing metrics
func (m *Monitor) RecordPacketProcessing(ctx context.Context, protocol, direction string, duration time.Duration) {
	if !m.enabled.Load() {
		return
	}

	// Record metrics
	m.metricsCollector.IncrementCounter("packets_processed")
	m.metricsCollector.RecordDuration("packet_processing_time", duration)

	// Tracing
	if span := SpanFromContext(ctx); span != nil {
		span.AddTag("processing_duration_ms", float64(duration.Nanoseconds())/1e6)
	}
}

// RecordPluginExecution records plugin execution metrics
func (m *Monitor) RecordPluginExecution(ctx context.Context, pluginName, protocol string, duration time.Duration, success bool) {
	if !m.enabled.Load() {
		return
	}

	// Record metrics
	m.metricsCollector.IncrementCounter(fmt.Sprintf("plugin_%s_executions", pluginName))
	m.metricsCollector.RecordDuration(fmt.Sprintf("plugin_%s_duration", pluginName), duration)

	if !success {
		m.metricsCollector.IncrementCounter(fmt.Sprintf("plugin_%s_errors", pluginName))
	}

	// Tracing
	if span := SpanFromContext(ctx); span != nil {
		span.AddTag("plugin_duration_ms", float64(duration.Nanoseconds())/1e6)
		span.AddTag("success", success)
		if !success {
			span.SetStatus(StatusError, "Plugin execution failed")
		}
	}
}

// RecordCallTrackingEvent records call tracking events
func (m *Monitor) RecordCallTrackingEvent(ctx context.Context, callID, event string, metadata map[string]interface{}) {
	if !m.enabled.Load() {
		return
	}

	// Record metrics
	m.metricsCollector.IncrementCounter(fmt.Sprintf("call_events_%s", event))

	// Tracing
	if span := SpanFromContext(ctx); span != nil {
		span.AddTag("call_event", event)
		span.AddTag("call_id", callID)
		for key, value := range metadata {
			span.AddTag(key, value)
		}
	}
}

// UpdateActiveCallCount updates the active call count
func (m *Monitor) UpdateActiveCallCount(count int, protocol string) {
	if !m.enabled.Load() {
		return
	}

	m.metricsCollector.SetGauge("active_calls", int64(count))
}

// Global monitoring instance
var (
	globalMonitor *Monitor
	monitorOnce   sync.Once
)

// GetGlobalMonitor returns the global monitoring instance
func GetGlobalMonitor() *Monitor {
	monitorOnce.Do(func() {
		config := MonitorConfig{
			UpdateInterval: 30 * time.Second,
		}
		globalMonitor = NewMonitor(config)
	})
	return globalMonitor
}

// Initialize monitoring with configuration
func InitializeMonitoring(config MonitorConfig) error {
	monitor := GetGlobalMonitor()
	if config.Enabled {
		return monitor.Enable(config)
	}
	return nil
}

// Shutdown monitoring system
func ShutdownMonitoring() error {
	return GetGlobalMonitor().Disable()
}

// Convenience functions for global monitoring

// RecordPacket records a packet processing event
func RecordPacket(ctx context.Context, protocol, direction string, duration time.Duration) {
	GetGlobalMonitor().RecordPacketProcessing(ctx, protocol, direction, duration)
}

// RecordPlugin records a plugin execution event
func RecordPlugin(ctx context.Context, pluginName, protocol string, duration time.Duration, success bool) {
	GetGlobalMonitor().RecordPluginExecution(ctx, pluginName, protocol, duration, success)
}

// RecordCallEvent records a call tracking event
func RecordCallEvent(ctx context.Context, callID, event string, metadata map[string]interface{}) {
	GetGlobalMonitor().RecordCallTrackingEvent(ctx, callID, event, metadata)
}

// UpdateActiveCalls updates the active call count
func UpdateActiveCalls(count int, protocol string) {
	GetGlobalMonitor().UpdateActiveCallCount(count, protocol)
}

// RecordVoIPEvent records a general VoIP event
func RecordVoIPEvent(ctx context.Context, eventType string, metadata map[string]interface{}) {
	GetGlobalMonitor().RecordVoIPEvent(ctx, eventType, metadata)
}
