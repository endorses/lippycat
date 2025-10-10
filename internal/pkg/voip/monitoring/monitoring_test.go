package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsCollector(t *testing.T) {
	collector := NewMetricsCollector()
	require.NotNil(t, collector)

	// Test enable/disable
	assert.False(t, collector.IsEnabled())
	collector.Enable()
	assert.True(t, collector.IsEnabled())

	// Test counters
	collector.IncrementCounter("test_counter")
	collector.IncrementCounter("test_counter")
	collector.AddToCounter("test_counter", 5)
	assert.Equal(t, int64(7), collector.GetCounter("test_counter"))

	// Test gauges
	collector.SetGauge("test_gauge", 42)
	assert.Equal(t, int64(42), collector.GetGauge("test_gauge"))

	// Test histograms
	collector.RecordHistogram("test_histogram", 10.5)
	collector.RecordHistogram("test_histogram", 20.0)
	stats := collector.GetHistogram("test_histogram")
	require.NotNil(t, stats)
	assert.Equal(t, int64(2), stats.Count)
	assert.Equal(t, 30.5, stats.Sum)
	assert.Equal(t, 15.25, stats.Average)

	// Test duration recording
	collector.RecordDuration("test_duration", 100*time.Millisecond)
	durationStats := collector.GetHistogram("test_duration")
	require.NotNil(t, durationStats)
	assert.Equal(t, int64(1), durationStats.Count)

	// Test get all metrics
	allMetrics := collector.GetAllMetrics()
	assert.Contains(t, allMetrics, "counters")
	assert.Contains(t, allMetrics, "gauges")
	assert.Contains(t, allMetrics, "histograms")

	// Test reset
	collector.Reset()
	assert.Equal(t, int64(0), collector.GetCounter("test_counter"))

	collector.Disable()
	assert.False(t, collector.IsEnabled())
}

func TestHistogram(t *testing.T) {
	histogram := NewHistogram()
	require.NotNil(t, histogram)

	// Record some values
	values := []float64{1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0}
	for _, value := range values {
		histogram.Record(value)
	}

	stats := histogram.Stats()
	require.NotNil(t, stats)

	assert.Equal(t, int64(7), stats.Count)
	assert.Equal(t, 193.5, stats.Sum)
	assert.InDelta(t, 27.64, stats.Average, 0.01)
	assert.Equal(t, 1.0, stats.Min)
	assert.Equal(t, 100.0, stats.Max)

	// Check percentiles
	assert.Contains(t, stats.Percentiles, "p50")
	assert.Contains(t, stats.Percentiles, "p90")
	assert.Contains(t, stats.Percentiles, "p95")
	assert.Contains(t, stats.Percentiles, "p99")
}

func TestTracingExporter(t *testing.T) {
	tracer := NewTracingExporter("test-service")
	require.NotNil(t, tracer)

	// Test enable/disable
	assert.False(t, tracer.IsEnabled())
	tracer.Enable()
	assert.True(t, tracer.IsEnabled())

	// Test span creation
	ctx := context.Background()
	span, newCtx := tracer.StartSpan(ctx, "test_operation", "test_component")
	require.NotNil(t, span)
	require.NotNil(t, newCtx)

	// Test span from context
	retrievedSpan := SpanFromContext(newCtx)
	require.NotNil(t, retrievedSpan)
	assert.Equal(t, span.SpanID, retrievedSpan.SpanID)

	// Test span operations
	span.AddTag("test_key", "test_value")
	span.LogInfo("test info", map[string]interface{}{"key": "value"})
	span.LogWarn("test warning", nil)
	span.LogError("test error", assert.AnError, map[string]interface{}{"error_type": "test"})

	// Test child span
	childSpan, _ := tracer.StartSpan(newCtx, "child_operation", "child_component")
	require.NotNil(t, childSpan)
	assert.Equal(t, span.TraceID, childSpan.TraceID)
	assert.Equal(t, span.SpanID, childSpan.ParentID)

	// Finish spans
	tracer.FinishSpan(childSpan)
	tracer.FinishSpan(span)

	// Test stats
	stats := tracer.GetStats()
	assert.Contains(t, stats, "enabled")
	assert.Contains(t, stats, "completed_spans")
	assert.Contains(t, stats, "service_name")

	tracer.Disable()
	assert.False(t, tracer.IsEnabled())
}

func TestSpanOperations(t *testing.T) {
	tracer := NewTracingExporter("test")
	tracer.Enable()

	ctx := context.Background()
	span, _ := tracer.StartSpan(ctx, "test", "test")
	require.NotNil(t, span)

	// Test tag operations
	span.AddTag("string_tag", "value")
	span.AddTag("int_tag", 42)
	span.AddTag("bool_tag", true)

	assert.Equal(t, "value", span.Tags["string_tag"])
	assert.Equal(t, 42, span.Tags["int_tag"])
	assert.Equal(t, true, span.Tags["bool_tag"])

	// Test log operations
	span.LogInfo("info message", map[string]interface{}{"level": "info"})
	span.LogWarn("warning message", map[string]interface{}{"level": "warn"})
	span.LogError("error message", assert.AnError, map[string]interface{}{"level": "error"})

	assert.Len(t, span.Logs, 3)
	assert.Equal(t, "info", span.Logs[0].Level)
	assert.Equal(t, "warn", span.Logs[1].Level)
	assert.Equal(t, "error", span.Logs[2].Level)

	// Test status operations
	span.SetStatus(StatusError, "test error")
	assert.Equal(t, StatusError, span.Status.Code)
	assert.Equal(t, "test error", span.Status.Message)

	tracer.FinishSpan(span)
	assert.True(t, span.finished.Load())

	tracer.Disable()
}

func TestMonitor(t *testing.T) {
	config := MonitorConfig{
		Enabled:        true,
		MetricsEnabled: true,
		TracingEnabled: true,
		UpdateInterval: 1 * time.Second,
	}

	monitor := NewMonitor(config)
	require.NotNil(t, monitor)

	// Test enable/disable
	assert.False(t, monitor.IsEnabled())

	err := monitor.Enable(config)
	require.NoError(t, err)
	assert.True(t, monitor.IsEnabled())

	// Test monitoring operations
	ctx := context.Background()
	monitor.RecordPacketProcessing(ctx, "sip", "inbound", 10*time.Millisecond)
	monitor.RecordPluginExecution(ctx, "sip_plugin", "sip", 5*time.Millisecond, true)
	monitor.RecordCallTrackingEvent(ctx, "call123", "created", map[string]interface{}{
		"protocol": "sip",
		"source":   "192.168.1.1",
	})
	monitor.UpdateActiveCallCount(5, "sip")

	// Test VoIP event recording
	monitor.RecordVoIPEvent(ctx, "invite", map[string]interface{}{
		"protocol": "sip",
		"call_id":  "test123",
	})

	// Test stats
	stats := monitor.GetStats()
	assert.Contains(t, stats, "enabled")
	assert.Contains(t, stats, "components")

	// Give monitor time to update
	time.Sleep(100 * time.Millisecond)

	err = monitor.Disable()
	require.NoError(t, err)
	assert.False(t, monitor.IsEnabled())
}

func TestConvenienceFunctions(t *testing.T) {
	// Test timer
	timer := StartTimer("test_operation")
	require.NotNil(t, timer)
	time.Sleep(10 * time.Millisecond)
	timer.Stop()

	// Test measure function
	executed := false
	Measure("test_measure", func() {
		executed = true
		time.Sleep(5 * time.Millisecond)
	})
	assert.True(t, executed)

	// Test measure async
	err := MeasureAsync("test_async", func() error {
		time.Sleep(5 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)

	// Test tracing convenience functions
	ctx := context.Background()

	span, _, finish := TraceFunction(ctx, "test_func", "test_component")
	if span != nil {
		span.AddTag("test", true)
		finish()
	}

	span, _, finish = TracePacketProcessing(ctx, "sip")
	if span != nil {
		finish()
	}

	span, _, finish = TraceCallProcessing(ctx, "call123", "create")
	if span != nil {
		finish()
	}

	span, _, finish = TracePluginExecution(ctx, "sip_plugin", "sip")
	if span != nil {
		finish()
	}

	span, _, finish = TraceTCPStreamProcessing(ctx, "stream123")
	if span != nil {
		finish()
	}

	span, newCtx, finish := TraceFileWrite(ctx, "test.pcap", "pcap")
	if span != nil {
		finish()
	}

	// Test trace logging
	TraceInfo(newCtx, "test info", map[string]interface{}{"key": "value"})
	TraceWarn(newCtx, "test warning", nil)
	TraceError(newCtx, assert.AnError, "test error")
}

func TestGlobalInstances(t *testing.T) {
	// Test global metrics collector
	collector := GetGlobalMetricsCollector()
	require.NotNil(t, collector)

	// Test global tracing exporter
	tracing := GetGlobalTracingExporter()
	require.NotNil(t, tracing)

	// Test global monitor
	monitor := GetGlobalMonitor()
	require.NotNil(t, monitor)

	// Test global convenience functions
	IncrementCounter("test_global_counter")
	AddToCounter("test_global_counter", 5)
	SetGauge("test_global_gauge", 42)
	RecordHistogram("test_global_histogram", 10.5)
	RecordDuration("test_global_duration", 100*time.Millisecond)

	// Test global monitoring functions
	ctx := context.Background()
	RecordPacket(ctx, "sip", "inbound", 10*time.Millisecond)
	RecordPlugin(ctx, "sip_plugin", "sip", 5*time.Millisecond, true)
	RecordCallEvent(ctx, "call123", "created", map[string]interface{}{"protocol": "sip"})
	UpdateActiveCalls(15, "sip")
	RecordVoIPEvent(ctx, "invite", map[string]interface{}{"protocol": "sip"})
}

// Benchmark tests
func BenchmarkMetricsCounter(b *testing.B) {
	collector := NewMetricsCollector()
	collector.Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.IncrementCounter("benchmark_counter")
	}
}

func BenchmarkMetricsGauge(b *testing.B) {
	collector := NewMetricsCollector()
	collector.Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.SetGauge("benchmark_gauge", int64(i))
	}
}

func BenchmarkMetricsHistogram(b *testing.B) {
	collector := NewMetricsCollector()
	collector.Enable()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordHistogram("benchmark_histogram", float64(i))
	}
}

func BenchmarkSpanCreation(b *testing.B) {
	tracer := NewTracingExporter("benchmark")
	tracer.Enable()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span, _ := tracer.StartSpan(ctx, "benchmark_operation", "benchmark")
		tracer.FinishSpan(span)
	}
}

func BenchmarkSpanLogging(b *testing.B) {
	tracer := NewTracingExporter("benchmark")
	tracer.Enable()
	span, _ := tracer.StartSpan(context.Background(), "benchmark", "benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span.LogInfo("benchmark log", map[string]interface{}{"iteration": i})
	}

	tracer.FinishSpan(span)
}

func BenchmarkMonitorRecordPacket(b *testing.B) {
	config := MonitorConfig{
		Enabled:        true,
		MetricsEnabled: true,
		TracingEnabled: true,
	}
	monitor := NewMonitor(config)
	_ = monitor.Enable(config)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.RecordPacketProcessing(ctx, "sip", "inbound", 10*time.Millisecond)
	}

	_ = monitor.Disable()
}
