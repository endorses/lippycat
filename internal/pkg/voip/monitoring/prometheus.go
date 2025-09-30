package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusExporter exports metrics to Prometheus
type PrometheusExporter struct {
	enabled    atomic.Bool
	registry   *prometheus.Registry
	server     *http.Server
	port       int
	mu         sync.RWMutex
	metrics    map[string]prometheus.Collector
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(port int) *PrometheusExporter {
	registry := prometheus.NewRegistry()

	// Add Go runtime metrics
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return &PrometheusExporter{
		registry:   registry,
		port:       port,
		metrics:    make(map[string]prometheus.Collector),
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
	}
}

// Enable starts the Prometheus metrics server
func (p *PrometheusExporter) Enable() error {
	if p.enabled.Load() {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Register VoIP-specific metrics
	if err := p.registerVoIPMetrics(); err != nil {
		return fmt.Errorf("failed to register VoIP metrics: %w", err)
	}

	// Start HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	mux.HandleFunc("/health", p.healthHandler)

	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("Starting Prometheus metrics server", "port", p.port)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Prometheus server error", "error", err)
		}
	}()

	p.enabled.Store(true)
	logger.Info("Prometheus metrics enabled", "endpoint", fmt.Sprintf("http://localhost:%d/metrics", p.port))
	return nil
}

// Disable stops the Prometheus metrics server
func (p *PrometheusExporter) Disable() error {
	if !p.enabled.Load() {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			logger.Error("Error shutting down Prometheus server", "error", err)
		}
		p.server = nil
	}

	p.enabled.Store(false)
	logger.Info("Prometheus metrics disabled")
	return nil
}

// IsEnabled returns whether Prometheus export is enabled
func (p *PrometheusExporter) IsEnabled() bool {
	return p.enabled.Load()
}

// registerVoIPMetrics registers VoIP-specific Prometheus metrics
func (p *PrometheusExporter) registerVoIPMetrics() error {
	// Packet processing metrics
	packetsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "lippycat_packets_processed_total",
			Help: "Total number of packets processed",
		},
		[]string{"protocol", "direction", "interface"},
	)
	p.counters["packets_total"] = packetsTotal
	p.registry.MustRegister(packetsTotal)

	// Call tracking metrics
	callsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "lippycat_calls_total",
			Help: "Total number of calls tracked",
		},
		[]string{"state", "protocol"},
	)
	p.counters["calls_total"] = callsTotal
	p.registry.MustRegister(callsTotal)

	activeCalls := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "lippycat_active_calls",
			Help: "Number of currently active calls",
		},
		[]string{"protocol"},
	)
	p.gauges["active_calls"] = activeCalls
	p.registry.MustRegister(activeCalls)

	// Processing latency metrics
	processingDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "lippycat_processing_duration_seconds",
			Help:    "Time spent processing packets",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		[]string{"component", "protocol"},
	)
	p.histograms["processing_duration"] = processingDuration
	p.registry.MustRegister(processingDuration)

	// Memory usage metrics
	memoryUsage := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "lippycat_memory_usage_bytes",
			Help: "Memory usage by component",
		},
		[]string{"component"},
	)
	p.gauges["memory_usage"] = memoryUsage
	p.registry.MustRegister(memoryUsage)

	// Error metrics
	errorsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "lippycat_errors_total",
			Help: "Total number of errors",
		},
		[]string{"component", "error_type"},
	)
	p.counters["errors_total"] = errorsTotal
	p.registry.MustRegister(errorsTotal)

	// Plugin system metrics
	pluginProcessingDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "lippycat_plugin_processing_duration_seconds",
			Help:    "Time spent in plugin processing",
			Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01},
		},
		[]string{"plugin", "protocol"},
	)
	p.histograms["plugin_processing_duration"] = pluginProcessingDuration
	p.registry.MustRegister(pluginProcessingDuration)

	pluginHealth := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "lippycat_plugin_health",
			Help: "Plugin health status (0=unhealthy, 1=degraded, 2=healthy)",
		},
		[]string{"plugin"},
	)
	p.gauges["plugin_health"] = pluginHealth
	p.registry.MustRegister(pluginHealth)

	// TCP stream metrics
	tcpStreams := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "lippycat_tcp_streams_active",
			Help: "Number of active TCP streams",
		},
		[]string{"state"},
	)
	p.gauges["tcp_streams"] = tcpStreams
	p.registry.MustRegister(tcpStreams)

	// Buffer metrics
	bufferUsage := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "lippycat_buffer_usage_ratio",
			Help: "Buffer usage ratio (0-1)",
		},
		[]string{"buffer_type"},
	)
	p.gauges["buffer_usage"] = bufferUsage
	p.registry.MustRegister(bufferUsage)

	logger.Info("Registered VoIP Prometheus metrics")
	return nil
}

// UpdateMetrics updates Prometheus metrics from the global metrics collector
func (p *PrometheusExporter) UpdateMetrics() {
	if !p.enabled.Load() {
		return
	}

	collector := GetGlobalMetricsCollector()
	if !collector.IsEnabled() {
		return
	}

	allMetrics := collector.GetAllMetrics()

	// Update counters
	if counters, ok := allMetrics["counters"].(map[string]int64); ok {
		for name, value := range counters {
			p.updatePrometheusCounter(name, value)
		}
	}

	// Update gauges
	if gauges, ok := allMetrics["gauges"].(map[string]int64); ok {
		for name, value := range gauges {
			p.updatePrometheusGauge(name, float64(value))
		}
	}

	// Update histograms
	if histograms, ok := allMetrics["histograms"].(map[string]*HistogramStats); ok {
		for name, stats := range histograms {
			p.updatePrometheusHistogram(name, stats)
		}
	}
}

// updatePrometheusCounter updates a Prometheus counter
func (p *PrometheusExporter) updatePrometheusCounter(name string, value int64) {
	switch name {
	case "packets_processed":
		if counter, ok := p.counters["packets_total"]; ok {
			counter.WithLabelValues("unknown", "inbound", "default").Add(float64(value))
		}
	case "calls_created":
		if counter, ok := p.counters["calls_total"]; ok {
			counter.WithLabelValues("created", "sip").Add(float64(value))
		}
	case "plugin_errors":
		if counter, ok := p.counters["errors_total"]; ok {
			counter.WithLabelValues("plugin", "processing").Add(float64(value))
		}
	}
}

// updatePrometheusGauge updates a Prometheus gauge
func (p *PrometheusExporter) updatePrometheusGauge(name string, value float64) {
	switch name {
	case "active_calls":
		if gauge, ok := p.gauges["active_calls"]; ok {
			gauge.WithLabelValues("sip").Set(value)
		}
	case "tcp_streams_active":
		if gauge, ok := p.gauges["tcp_streams"]; ok {
			gauge.WithLabelValues("active").Set(value)
		}
	case "memory_usage_mb":
		if gauge, ok := p.gauges["memory_usage"]; ok {
			gauge.WithLabelValues("total").Set(value * 1024 * 1024) // Convert MB to bytes
		}
	}
}

// updatePrometheusHistogram updates a Prometheus histogram
func (p *PrometheusExporter) updatePrometheusHistogram(name string, stats *HistogramStats) {
	switch name {
	case "packet_processing_time":
		if histogram, ok := p.histograms["processing_duration"]; ok {
			// Convert milliseconds to seconds
			histogram.WithLabelValues("packet_processing", "all").Observe(stats.Average / 1000.0)
		}
	case "plugin_processing_time":
		if histogram, ok := p.histograms["plugin_processing_duration"]; ok {
			histogram.WithLabelValues("all", "all").Observe(stats.Average / 1000.0)
		}
	}
}

// healthHandler provides a health check endpoint
func (p *PrometheusExporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p.enabled.Load() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","prometheus":"enabled"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"disabled","prometheus":"disabled"}`))
	}
}

// RecordPacketProcessed records a packet processing event
func (p *PrometheusExporter) RecordPacketProcessed(protocol, direction, iface string) {
	if !p.enabled.Load() {
		return
	}

	if counter, ok := p.counters["packets_total"]; ok {
		counter.WithLabelValues(protocol, direction, iface).Inc()
	}
}

// RecordCallEvent records a call lifecycle event
func (p *PrometheusExporter) RecordCallEvent(state, protocol string) {
	if !p.enabled.Load() {
		return
	}

	if counter, ok := p.counters["calls_total"]; ok {
		counter.WithLabelValues(state, protocol).Inc()
	}
}

// SetActiveCalls sets the number of active calls
func (p *PrometheusExporter) SetActiveCalls(count int, protocol string) {
	if !p.enabled.Load() {
		return
	}

	if gauge, ok := p.gauges["active_calls"]; ok {
		gauge.WithLabelValues(protocol).Set(float64(count))
	}
}

// RecordProcessingDuration records processing duration
func (p *PrometheusExporter) RecordProcessingDuration(component, protocol string, duration time.Duration) {
	if !p.enabled.Load() {
		return
	}

	if histogram, ok := p.histograms["processing_duration"]; ok {
		histogram.WithLabelValues(component, protocol).Observe(duration.Seconds())
	}
}

// RecordPluginProcessingDuration records plugin processing duration
func (p *PrometheusExporter) RecordPluginProcessingDuration(plugin, protocol string, duration time.Duration) {
	if !p.enabled.Load() {
		return
	}

	if histogram, ok := p.histograms["plugin_processing_duration"]; ok {
		histogram.WithLabelValues(plugin, protocol).Observe(duration.Seconds())
	}
}

// SetPluginHealth sets plugin health status
func (p *PrometheusExporter) SetPluginHealth(plugin string, health int) {
	if !p.enabled.Load() {
		return
	}

	if gauge, ok := p.gauges["plugin_health"]; ok {
		gauge.WithLabelValues(plugin).Set(float64(health))
	}
}

// RecordError records an error event
func (p *PrometheusExporter) RecordError(component, errorType string) {
	if !p.enabled.Load() {
		return
	}

	if counter, ok := p.counters["errors_total"]; ok {
		counter.WithLabelValues(component, errorType).Inc()
	}
}

// SetMemoryUsage sets memory usage for a component
func (p *PrometheusExporter) SetMemoryUsage(component string, bytes int64) {
	if !p.enabled.Load() {
		return
	}

	if gauge, ok := p.gauges["memory_usage"]; ok {
		gauge.WithLabelValues(component).Set(float64(bytes))
	}
}

// SetTCPStreams sets the number of TCP streams
func (p *PrometheusExporter) SetTCPStreams(state string, count int) {
	if !p.enabled.Load() {
		return
	}

	if gauge, ok := p.gauges["tcp_streams"]; ok {
		gauge.WithLabelValues(state).Set(float64(count))
	}
}

// SetBufferUsage sets buffer usage ratio
func (p *PrometheusExporter) SetBufferUsage(bufferType string, ratio float64) {
	if !p.enabled.Load() {
		return
	}

	if gauge, ok := p.gauges["buffer_usage"]; ok {
		gauge.WithLabelValues(bufferType).Set(ratio)
	}
}

// Global Prometheus exporter instance
var (
	globalPrometheusExporter *PrometheusExporter
	prometheusOnce          sync.Once
)

// GetGlobalPrometheusExporter returns the global Prometheus exporter
func GetGlobalPrometheusExporter() *PrometheusExporter {
	prometheusOnce.Do(func() {
		globalPrometheusExporter = NewPrometheusExporter(9090) // Default Prometheus port
	})
	return globalPrometheusExporter
}

// Convenience functions for Prometheus metrics

// RecordCall records a call event
func RecordCall(state, protocol string) {
	GetGlobalPrometheusExporter().RecordCallEvent(state, protocol)
}

// RecordProcessingTime records processing duration
func RecordProcessingTime(component, protocol string, duration time.Duration) {
	GetGlobalPrometheusExporter().RecordProcessingDuration(component, protocol, duration)
}

// RecordPluginTime records plugin processing duration
func RecordPluginTime(plugin, protocol string, duration time.Duration) {
	GetGlobalPrometheusExporter().RecordPluginProcessingDuration(plugin, protocol, duration)
}

// UpdatePluginHealth updates plugin health status
func UpdatePluginHealth(plugin string, health int) {
	GetGlobalPrometheusExporter().SetPluginHealth(plugin, health)
}

// RecordMonitoringError records an error
func RecordMonitoringError(component, errorType string) {
	GetGlobalPrometheusExporter().RecordError(component, errorType)
}

// UpdateMemoryUsage updates memory usage
func UpdateMemoryUsage(component string, bytes int64) {
	GetGlobalPrometheusExporter().SetMemoryUsage(component, bytes)
}

// UpdateTCPStreams updates TCP stream count
func UpdateTCPStreams(state string, count int) {
	GetGlobalPrometheusExporter().SetTCPStreams(state, count)
}

// UpdateBufferUsage updates buffer usage
func UpdateBufferUsage(bufferType string, ratio float64) {
	GetGlobalPrometheusExporter().SetBufferUsage(bufferType, ratio)
}