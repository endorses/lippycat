package monitoring

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// MetricsCollector provides a centralized metrics collection system
type MetricsCollector struct {
	enabled        atomic.Bool
	counters       sync.Map // map[string]*atomic.Int64
	gauges         sync.Map // map[string]*atomic.Int64
	histograms     sync.Map // map[string]*Histogram
	lastUpdate     atomic.Int64
	updateInterval time.Duration
	mu             sync.RWMutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		updateInterval: 30 * time.Second,
	}
}

// Enable enables metrics collection
func (m *MetricsCollector) Enable() {
	m.enabled.Store(true)
	m.lastUpdate.Store(time.Now().UnixNano())
	logger.Info("Metrics collection enabled")
}

// Disable disables metrics collection
func (m *MetricsCollector) Disable() {
	m.enabled.Store(false)
	logger.Info("Metrics collection disabled")
}

// IsEnabled returns whether metrics collection is enabled
func (m *MetricsCollector) IsEnabled() bool {
	return m.enabled.Load()
}

// IncrementCounter increments a named counter
func (m *MetricsCollector) IncrementCounter(name string) {
	if !m.enabled.Load() {
		return
	}

	value, _ := m.counters.LoadOrStore(name, &atomic.Int64{})
	counter := value.(*atomic.Int64)
	counter.Add(1)
}

// AddToCounter adds a value to a named counter
func (m *MetricsCollector) AddToCounter(name string, value int64) {
	if !m.enabled.Load() {
		return
	}

	counterValue, _ := m.counters.LoadOrStore(name, &atomic.Int64{})
	counter := counterValue.(*atomic.Int64)
	counter.Add(value)
}

// SetGauge sets a gauge value
func (m *MetricsCollector) SetGauge(name string, value int64) {
	if !m.enabled.Load() {
		return
	}

	gaugeValue, _ := m.gauges.LoadOrStore(name, &atomic.Int64{})
	gauge := gaugeValue.(*atomic.Int64)
	gauge.Store(value)
}

// RecordHistogram records a value in a histogram
func (m *MetricsCollector) RecordHistogram(name string, value float64) {
	if !m.enabled.Load() {
		return
	}

	histValue, _ := m.histograms.LoadOrStore(name, NewHistogram())
	histogram := histValue.(*Histogram)
	histogram.Record(value)
}

// RecordDuration records a duration in a histogram (converted to milliseconds)
func (m *MetricsCollector) RecordDuration(name string, duration time.Duration) {
	m.RecordHistogram(name, float64(duration.Nanoseconds())/1e6)
}

// GetCounter returns the current value of a counter
func (m *MetricsCollector) GetCounter(name string) int64 {
	if value, ok := m.counters.Load(name); ok {
		return value.(*atomic.Int64).Load()
	}
	return 0
}

// GetGauge returns the current value of a gauge
func (m *MetricsCollector) GetGauge(name string) int64 {
	if value, ok := m.gauges.Load(name); ok {
		return value.(*atomic.Int64).Load()
	}
	return 0
}

// GetHistogram returns a copy of histogram statistics
func (m *MetricsCollector) GetHistogram(name string) *HistogramStats {
	if value, ok := m.histograms.Load(name); ok {
		return value.(*Histogram).Stats()
	}
	return nil
}

// GetAllMetrics returns all current metrics
func (m *MetricsCollector) GetAllMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Add counters
	counters := make(map[string]int64)
	m.counters.Range(func(key, value interface{}) bool {
		counters[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	metrics["counters"] = counters

	// Add gauges
	gauges := make(map[string]int64)
	m.gauges.Range(func(key, value interface{}) bool {
		gauges[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	metrics["gauges"] = gauges

	// Add histograms
	histograms := make(map[string]*HistogramStats)
	m.histograms.Range(func(key, value interface{}) bool {
		histograms[key.(string)] = value.(*Histogram).Stats()
		return true
	})
	metrics["histograms"] = histograms

	metrics["last_update"] = time.Unix(0, m.lastUpdate.Load())
	metrics["enabled"] = m.enabled.Load()

	return metrics
}

// Reset clears all metrics
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.counters = sync.Map{}
	m.gauges = sync.Map{}
	m.histograms = sync.Map{}
	m.lastUpdate.Store(time.Now().UnixNano())

	logger.Info("Metrics reset")
}

// Histogram provides histogram functionality for tracking distributions
type Histogram struct {
	mu      sync.RWMutex
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Value // float64
	count   atomic.Int64
	min     atomic.Value // float64
	max     atomic.Value // float64
}

// NewHistogram creates a new histogram with default buckets
func NewHistogram() *Histogram {
	// Default buckets for latency measurements (milliseconds)
	buckets := []float64{0.1, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

	h := &Histogram{
		buckets: buckets,
		counts:  make([]atomic.Int64, len(buckets)+1), // +1 for overflow bucket
	}

	h.sum.Store(float64(0))
	h.min.Store(float64(0))
	h.max.Store(float64(0))

	return h
}

// Record records a value in the histogram
func (h *Histogram) Record(value float64) {
	h.count.Add(1)

	// Update sum
	for {
		current := h.sum.Load().(float64)
		if h.sum.CompareAndSwap(current, current+value) {
			break
		}
	}

	// Update min/max
	for {
		current := h.min.Load().(float64)
		if current == 0 || value < current {
			if h.min.CompareAndSwap(current, value) {
				break
			}
		} else {
			break
		}
	}

	for {
		current := h.max.Load().(float64)
		if value > current {
			if h.max.CompareAndSwap(current, value) {
				break
			}
		} else {
			break
		}
	}

	// Find appropriate bucket
	h.mu.RLock()
	defer h.mu.RUnlock()

	bucketIndex := len(h.buckets) // overflow bucket by default
	for i, bucket := range h.buckets {
		if value <= bucket {
			bucketIndex = i
			break
		}
	}

	h.counts[bucketIndex].Add(1)
}

// HistogramStats contains histogram statistics
type HistogramStats struct {
	Count      int64                `json:"count"`
	Sum        float64              `json:"sum"`
	Average    float64              `json:"average"`
	Min        float64              `json:"min"`
	Max        float64              `json:"max"`
	Buckets    []float64            `json:"buckets"`
	BucketCounts []int64            `json:"bucket_counts"`
	Percentiles map[string]float64  `json:"percentiles"`
}

// Stats returns current histogram statistics
func (h *Histogram) Stats() *HistogramStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	count := h.count.Load()
	sum := h.sum.Load().(float64)
	min := h.min.Load().(float64)
	max := h.max.Load().(float64)

	var average float64
	if count > 0 {
		average = sum / float64(count)
	}

	// Get bucket counts
	bucketCounts := make([]int64, len(h.counts))
	for i := range h.counts {
		bucketCounts[i] = h.counts[i].Load()
	}

	// Calculate percentiles (simplified approximation)
	percentiles := h.calculatePercentiles(bucketCounts, count)

	return &HistogramStats{
		Count:        count,
		Sum:          sum,
		Average:      average,
		Min:          min,
		Max:          max,
		Buckets:      append([]float64(nil), h.buckets...), // copy
		BucketCounts: bucketCounts,
		Percentiles:  percentiles,
	}
}

// calculatePercentiles calculates approximate percentiles from bucket data
func (h *Histogram) calculatePercentiles(bucketCounts []int64, totalCount int64) map[string]float64 {
	if totalCount == 0 {
		return map[string]float64{
			"p50": 0, "p90": 0, "p95": 0, "p99": 0,
		}
	}

	percentiles := map[string]float64{}
	targets := map[string]float64{
		"p50": 0.50,
		"p90": 0.90,
		"p95": 0.95,
		"p99": 0.99,
	}

	var cumulativeCount int64
	for percentile, target := range targets {
		targetCount := int64(float64(totalCount) * target)

		cumulativeCount = 0
		for i, count := range bucketCounts {
			cumulativeCount += count
			if cumulativeCount >= targetCount {
				if i < len(h.buckets) {
					percentiles[percentile] = h.buckets[i]
				} else {
					// Overflow bucket - use max value
					percentiles[percentile] = h.max.Load().(float64)
				}
				break
			}
		}
	}

	return percentiles
}

// Global metrics collector instance
var (
	globalMetricsCollector *MetricsCollector
	metricsOnce           sync.Once
)

// GetGlobalMetricsCollector returns the global metrics collector
func GetGlobalMetricsCollector() *MetricsCollector {
	metricsOnce.Do(func() {
		globalMetricsCollector = NewMetricsCollector()
	})
	return globalMetricsCollector
}

// Convenience functions for global metrics

// IncrementCounter increments a global counter
func IncrementCounter(name string) {
	GetGlobalMetricsCollector().IncrementCounter(name)
}

// AddToCounter adds to a global counter
func AddToCounter(name string, value int64) {
	GetGlobalMetricsCollector().AddToCounter(name, value)
}

// SetGauge sets a global gauge
func SetGauge(name string, value int64) {
	GetGlobalMetricsCollector().SetGauge(name, value)
}

// RecordHistogram records to a global histogram
func RecordHistogram(name string, value float64) {
	GetGlobalMetricsCollector().RecordHistogram(name, value)
}

// RecordDuration records a duration to a global histogram
func RecordDuration(name string, duration time.Duration) {
	GetGlobalMetricsCollector().RecordDuration(name, duration)
}

// Timer provides a simple way to time operations
type Timer struct {
	start time.Time
	name  string
}

// StartTimer starts a new timer
func StartTimer(name string) *Timer {
	return &Timer{
		start: time.Now(),
		name:  name,
	}
}

// Stop stops the timer and records the duration
func (t *Timer) Stop() {
	duration := time.Since(t.start)
	RecordDuration(t.name, duration)
}

// Measure provides a convenient way to measure function execution time
func Measure(name string, fn func()) {
	timer := StartTimer(name)
	defer timer.Stop()
	fn()
}

// MeasureAsync provides a way to measure async operations
func MeasureAsync(name string, fn func() error) error {
	timer := StartTimer(name)
	defer timer.Stop()
	return fn()
}