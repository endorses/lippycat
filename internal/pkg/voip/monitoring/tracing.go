package monitoring

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// TracingExporter provides distributed tracing capabilities
type TracingExporter struct {
	enabled        atomic.Bool
	serviceName    string
	spans          sync.Map // map[string]*Span
	activeSpans    atomic.Int64
	completedSpans atomic.Int64
	exportInterval time.Duration
	maxSpans       int
	mu             sync.RWMutex
}

// Span represents a distributed tracing span
type Span struct {
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	ParentID   string                 `json:"parent_id,omitempty"`
	Operation  string                 `json:"operation"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Duration   time.Duration          `json:"duration"`
	Tags       map[string]interface{} `json:"tags"`
	Logs       []SpanLog              `json:"logs"`
	Status     SpanStatus             `json:"status"`
	Component  string                 `json:"component"`
	finished   atomic.Bool
}

// SpanLog represents a log entry within a span
type SpanLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// SpanStatus represents the status of a span
type SpanStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Span status codes
const (
	StatusOK    = 0
	StatusError = 1
	StatusAbort = 2
)

// NewTracingExporter creates a new tracing exporter
func NewTracingExporter(serviceName string) *TracingExporter {
	return &TracingExporter{
		serviceName:    serviceName,
		exportInterval: 10 * time.Second,
		maxSpans:       10000,
	}
}

// Enable enables distributed tracing
func (t *TracingExporter) Enable() {
	if t.enabled.Load() {
		return
	}

	t.enabled.Store(true)
	go t.exportLoop()
	logger.Info("Distributed tracing enabled", "service", t.serviceName)
}

// Disable disables distributed tracing
func (t *TracingExporter) Disable() {
	if !t.enabled.Load() {
		return
	}

	t.enabled.Store(false)
	logger.Info("Distributed tracing disabled")
}

// IsEnabled returns whether tracing is enabled
func (t *TracingExporter) IsEnabled() bool {
	return t.enabled.Load()
}

// StartSpan creates and starts a new span
func (t *TracingExporter) StartSpan(ctx context.Context, operation string, component string) (*Span, context.Context) {
	if !t.enabled.Load() {
		return nil, ctx
	}

	// Check if we've exceeded max spans to prevent memory issues
	if t.activeSpans.Load() >= int64(t.maxSpans) {
		logger.Warn("Maximum active spans reached, dropping new span",
			"operation", operation,
			"max_spans", t.maxSpans)
		return nil, ctx
	}

	span := &Span{
		TraceID:   t.generateTraceID(ctx),
		SpanID:    t.generateSpanID(),
		Operation: operation,
		StartTime: time.Now(),
		Tags:      make(map[string]interface{}),
		Logs:      make([]SpanLog, 0),
		Status:    SpanStatus{Code: StatusOK},
		Component: component,
	}

	// Check for parent span in context
	if parentSpan := SpanFromContext(ctx); parentSpan != nil {
		span.TraceID = parentSpan.TraceID
		span.ParentID = parentSpan.SpanID
	}

	// Store span
	t.spans.Store(span.SpanID, span)
	t.activeSpans.Add(1)

	// Add span to context
	ctx = ContextWithSpan(ctx, span)

	logger.Debug("Started tracing span",
		"trace_id", span.TraceID,
		"span_id", span.SpanID,
		"operation", operation,
		"component", component)

	return span, ctx
}

// FinishSpan finishes a span
func (t *TracingExporter) FinishSpan(span *Span) {
	if span == nil || !t.enabled.Load() {
		return
	}

	if !span.finished.CompareAndSwap(false, true) {
		return // Already finished
	}

	span.EndTime = time.Now()
	span.Duration = span.EndTime.Sub(span.StartTime)

	t.activeSpans.Add(-1)
	t.completedSpans.Add(1)

	logger.Debug("Finished tracing span",
		"trace_id", span.TraceID,
		"span_id", span.SpanID,
		"operation", span.Operation,
		"duration", span.Duration)
}

// AddTag adds a tag to a span
func (s *Span) AddTag(key string, value interface{}) {
	if s == nil {
		return
	}
	s.Tags[key] = value
}

// LogInfo adds an info log to a span
func (s *Span) LogInfo(message string, fields map[string]interface{}) {
	s.addLog("info", message, fields)
}

// LogError adds an error log to a span and sets error status
func (s *Span) LogError(message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	if err != nil {
		fields["error"] = err.Error()
	}

	s.addLog("error", message, fields)
	s.Status = SpanStatus{Code: StatusError, Message: message}
}

// LogWarn adds a warning log to a span
func (s *Span) LogWarn(message string, fields map[string]interface{}) {
	s.addLog("warn", message, fields)
}

// addLog adds a log entry to the span
func (s *Span) addLog(level, message string, fields map[string]interface{}) {
	if s == nil {
		return
	}

	log := SpanLog{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Fields:    fields,
	}

	s.Logs = append(s.Logs, log)
}

// SetStatus sets the span status
func (s *Span) SetStatus(code int, message string) {
	if s == nil {
		return
	}
	s.Status = SpanStatus{Code: code, Message: message}
}

// generateTraceID generates a new trace ID or gets it from context
func (t *TracingExporter) generateTraceID(ctx context.Context) string {
	if span := SpanFromContext(ctx); span != nil {
		return span.TraceID
	}
	return fmt.Sprintf("trace_%d_%d", time.Now().UnixNano(), traceIDCounter.Add(1))
}

// generateSpanID generates a new span ID
func (t *TracingExporter) generateSpanID() string {
	return fmt.Sprintf("span_%d_%d", time.Now().UnixNano(), spanIDCounter.Add(1))
}

// exportLoop periodically exports completed spans
func (t *TracingExporter) exportLoop() {
	ticker := time.NewTicker(t.exportInterval)
	defer ticker.Stop()

	for t.enabled.Load() {
		select {
		case <-ticker.C:
			t.exportSpans()
		}
	}
}

// exportSpans exports completed spans (in a real implementation, this would send to Jaeger/Zipkin)
func (t *TracingExporter) exportSpans() {
	var spansToExport []*Span
	var spansToDelete []string

	// Collect finished spans
	t.spans.Range(func(key, value interface{}) bool {
		span := value.(*Span)
		if span.finished.Load() {
			spansToExport = append(spansToExport, span)
			spansToDelete = append(spansToDelete, key.(string))
		}
		return true
	})

	// Remove exported spans
	for _, spanID := range spansToDelete {
		t.spans.Delete(spanID)
	}

	if len(spansToExport) > 0 {
		// In a real implementation, you would export to Jaeger, Zipkin, etc.
		logger.Debug("Exported tracing spans",
			"count", len(spansToExport),
			"service", t.serviceName)

		// For demonstration, log some span statistics
		for _, span := range spansToExport {
			if span.Status.Code != StatusOK {
				logger.Info("Traced operation with issues",
					"trace_id", span.TraceID,
					"operation", span.Operation,
					"duration", span.Duration,
					"status", span.Status.Message,
					"component", span.Component)
			}
		}
	}
}

// GetStats returns tracing statistics
func (t *TracingExporter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":         t.enabled.Load(),
		"active_spans":    t.activeSpans.Load(),
		"completed_spans": t.completedSpans.Load(),
		"service_name":    t.serviceName,
		"max_spans":       t.maxSpans,
	}
}

// Context key for spans
type spanContextKey struct{}

// ContextWithSpan returns a new context with the span attached
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, spanContextKey{}, span)
}

// SpanFromContext retrieves a span from the context
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanContextKey{}).(*Span); ok {
		return span
	}
	return nil
}

// Global counters for ID generation
var (
	traceIDCounter atomic.Int64
	spanIDCounter  atomic.Int64
)

// Global tracing exporter instance
var (
	globalTracingExporter *TracingExporter
	tracingOnce           sync.Once
)

// GetGlobalTracingExporter returns the global tracing exporter
func GetGlobalTracingExporter() *TracingExporter {
	tracingOnce.Do(func() {
		globalTracingExporter = NewTracingExporter("lippycat")
	})
	return globalTracingExporter
}

// Convenience functions for tracing

// StartSpan starts a new span in the global tracer
func StartSpan(ctx context.Context, operation, component string) (*Span, context.Context) {
	return GetGlobalTracingExporter().StartSpan(ctx, operation, component)
}

// FinishSpan finishes a span in the global tracer
func FinishSpan(span *Span) {
	GetGlobalTracingExporter().FinishSpan(span)
}

// TraceFunction provides a convenient way to trace function execution
func TraceFunction(ctx context.Context, operation, component string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, operation, component)

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TracePacketProcessing traces packet processing operations
func TracePacketProcessing(ctx context.Context, protocol string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, fmt.Sprintf("process_%s_packet", protocol), "packet_processor")
	if span != nil {
		span.AddTag("protocol", protocol)
		span.AddTag("packet.type", "voip")
	}

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TraceCallProcessing traces call processing operations
func TraceCallProcessing(ctx context.Context, callID, operation string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, fmt.Sprintf("call_%s", operation), "call_tracker")
	if span != nil {
		span.AddTag("call_id", callID)
		span.AddTag("operation", operation)
	}

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TracePluginExecution traces plugin execution
func TracePluginExecution(ctx context.Context, pluginName, protocol string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, fmt.Sprintf("plugin_%s", pluginName), "plugin_system")
	if span != nil {
		span.AddTag("plugin", pluginName)
		span.AddTag("protocol", protocol)
	}

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TraceTCPStreamProcessing traces TCP stream processing
func TraceTCPStreamProcessing(ctx context.Context, streamID string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, "tcp_stream_processing", "tcp_processor")
	if span != nil {
		span.AddTag("stream_id", streamID)
		span.AddTag("protocol", "tcp")
	}

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TraceFileWrite traces file write operations
func TraceFileWrite(ctx context.Context, filename, fileType string) (*Span, context.Context, func()) {
	span, newCtx := StartSpan(ctx, "file_write", "file_writer")
	if span != nil {
		span.AddTag("filename", filename)
		span.AddTag("file_type", fileType)
	}

	return span, newCtx, func() {
		FinishSpan(span)
	}
}

// TraceError adds error information to the current span
func TraceError(ctx context.Context, err error, message string) {
	if span := SpanFromContext(ctx); span != nil {
		span.LogError(message, err, map[string]interface{}{
			"error.type": fmt.Sprintf("%T", err),
		})
	}
}

// TraceInfo adds info to the current span
func TraceInfo(ctx context.Context, message string, fields map[string]interface{}) {
	if span := SpanFromContext(ctx); span != nil {
		span.LogInfo(message, fields)
	}
}

// TraceWarn adds warning to the current span
func TraceWarn(ctx context.Context, message string, fields map[string]interface{}) {
	if span := SpanFromContext(ctx); span != nil {
		span.LogWarn(message, fields)
	}
}