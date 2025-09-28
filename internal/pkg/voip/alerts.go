package voip

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// AlertLevel represents the severity of an alert
type AlertLevel int

const (
	AlertInfo AlertLevel = iota
	AlertWarning
	AlertCritical
)

func (a AlertLevel) String() string {
	switch a {
	case AlertInfo:
		return "INFO"
	case AlertWarning:
		return "WARNING"
	case AlertCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Alert represents a TCP resource alert
type Alert struct {
	ID          string    `json:"id"`
	Level       AlertLevel `json:"level"`
	Component   string    `json:"component"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
	Resolved    bool      `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// AlertHandler defines the interface for handling alerts
type AlertHandler interface {
	HandleAlert(alert Alert) error
}

// LogAlertHandler logs alerts using the logger
type LogAlertHandler struct{}

func (h *LogAlertHandler) HandleAlert(alert Alert) error {
	level := logger.Info
	switch alert.Level {
	case AlertWarning:
		level = logger.Warn
	case AlertCritical:
		level = logger.Error
	}

	level("TCP Resource Alert",
		"alert_id", alert.ID,
		"level", alert.Level.String(),
		"component", alert.Component,
		"message", alert.Message,
		"metrics", alert.Metrics)
	return nil
}

// ConsoleAlertHandler prints alerts to console
type ConsoleAlertHandler struct{}

func (h *ConsoleAlertHandler) HandleAlert(alert Alert) error {
	fmt.Printf("[%s] %s - %s: %s\n",
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Level.String(),
		alert.Component,
		alert.Message)
	return nil
}

// AlertManager manages TCP resource alerts
type AlertManager struct {
	mu           sync.RWMutex
	handlers     []AlertHandler
	activeAlerts map[string]*Alert
	thresholds   *AlertThresholds
	enabled      bool
	ctx          context.Context
	cancel       context.CancelFunc
	ticker       *time.Ticker
}

// AlertThresholds defines when to trigger alerts
type AlertThresholds struct {
	// Memory thresholds
	MemoryWarningMB  int64
	MemoryCriticalMB int64

	// Goroutine thresholds
	GoroutineWarningPercent  float64
	GoroutineCriticalPercent float64

	// Queue thresholds
	QueueWarningPercent  float64
	QueueCriticalPercent float64

	// Buffer thresholds
	BufferWarningCount  int64
	BufferCriticalCount int64

	// Stream failure thresholds
	FailureRateWarningPercent  float64
	FailureRateCriticalPercent float64

	// Health check thresholds
	UnhealthyDurationWarning  time.Duration
	UnhealthyDurationCritical time.Duration
}

// DefaultAlertThresholds returns sensible default thresholds
func DefaultAlertThresholds() *AlertThresholds {
	return &AlertThresholds{
		MemoryWarningMB:           200, // 200MB
		MemoryCriticalMB:          500, // 500MB
		GoroutineWarningPercent:   80,  // 80% of max_goroutines
		GoroutineCriticalPercent:  95,  // 95% of max_goroutines
		QueueWarningPercent:       70,  // 70% of queue capacity
		QueueCriticalPercent:      90,  // 90% of queue capacity
		BufferWarningCount:        8000, // 8000 buffers
		BufferCriticalCount:       9500, // 9500 buffers
		FailureRateWarningPercent: 5,   // 5% failure rate
		FailureRateCriticalPercent: 15, // 15% failure rate
		UnhealthyDurationWarning:  2 * time.Minute,
		UnhealthyDurationCritical: 5 * time.Minute,
	}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(thresholds *AlertThresholds) *AlertManager {
	if thresholds == nil {
		thresholds = DefaultAlertThresholds()
	}

	ctx, cancel := context.WithCancel(context.Background())

	am := &AlertManager{
		handlers:     []AlertHandler{&LogAlertHandler{}},
		activeAlerts: make(map[string]*Alert),
		thresholds:   thresholds,
		enabled:      true,
		ctx:          ctx,
		cancel:       cancel,
		ticker:       time.NewTicker(30 * time.Second), // Check every 30 seconds
	}

	// Start monitoring goroutine
	go am.monitor()

	return am
}

// AddHandler adds an alert handler
func (am *AlertManager) AddHandler(handler AlertHandler) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.handlers = append(am.handlers, handler)
}

// SetEnabled enables or disables alerting
func (am *AlertManager) SetEnabled(enabled bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.enabled = enabled
}

// Close stops the alert manager
func (am *AlertManager) Close() {
	if am.cancel != nil {
		am.cancel()
	}
	if am.ticker != nil {
		am.ticker.Stop()
	}
}

// monitor runs the monitoring loop
func (am *AlertManager) monitor() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Alert manager monitor panic recovered", "panic_value", r)
		}
	}()

	var lastUnhealthyTime *time.Time

	for {
		select {
		case <-am.ctx.Done():
			return
		case <-am.ticker.C:
			am.mu.RLock()
			enabled := am.enabled
			am.mu.RUnlock()

			if !enabled {
				continue
			}

			// Check TCP assembler health
			health := GetTCPAssemblerHealth()
			if healthy, ok := health["healthy"].(bool); ok && !healthy {
				if lastUnhealthyTime == nil {
					now := time.Now()
					lastUnhealthyTime = &now
				} else {
					unhealthyDuration := time.Since(*lastUnhealthyTime)

					if unhealthyDuration > am.thresholds.UnhealthyDurationCritical {
						am.triggerAlert("tcp-unhealthy-critical", AlertCritical, "TCP Assembler",
							fmt.Sprintf("TCP assembler has been unhealthy for %v", unhealthyDuration),
							health)
					} else if unhealthyDuration > am.thresholds.UnhealthyDurationWarning {
						am.triggerAlert("tcp-unhealthy-warning", AlertWarning, "TCP Assembler",
							fmt.Sprintf("TCP assembler has been unhealthy for %v", unhealthyDuration),
							health)
					}
				}
			} else {
				if lastUnhealthyTime != nil {
					// Resolve unhealthy alerts
					am.resolveAlert("tcp-unhealthy-warning")
					am.resolveAlert("tcp-unhealthy-critical")
					lastUnhealthyTime = nil
				}
			}

			// Check specific metrics
			am.checkGoroutineUsage(health)
			am.checkQueueUsage(health)
			am.checkBufferUsage()
			am.checkFailureRates()
		}
	}
}

// checkGoroutineUsage monitors goroutine utilization
func (am *AlertManager) checkGoroutineUsage(health map[string]interface{}) {
	if utilization, ok := health["goroutine_utilization"].(float64); ok {
		utilizationPercent := utilization * 100

		if utilizationPercent >= am.thresholds.GoroutineCriticalPercent {
			am.triggerAlert("goroutine-critical", AlertCritical, "Goroutine Pool",
				fmt.Sprintf("Goroutine utilization at %.1f%% (critical threshold: %.1f%%)",
					utilizationPercent, am.thresholds.GoroutineCriticalPercent),
				map[string]interface{}{
					"utilization_percent": utilizationPercent,
					"active_goroutines": health["active_goroutines"],
					"max_goroutines": health["max_goroutines"],
				})
		} else if utilizationPercent >= am.thresholds.GoroutineWarningPercent {
			am.triggerAlert("goroutine-warning", AlertWarning, "Goroutine Pool",
				fmt.Sprintf("Goroutine utilization at %.1f%% (warning threshold: %.1f%%)",
					utilizationPercent, am.thresholds.GoroutineWarningPercent),
				map[string]interface{}{
					"utilization_percent": utilizationPercent,
					"active_goroutines": health["active_goroutines"],
					"max_goroutines": health["max_goroutines"],
				})
		} else {
			// Resolve if below warning threshold
			am.resolveAlert("goroutine-warning")
			am.resolveAlert("goroutine-critical")
		}
	}
}

// checkQueueUsage monitors queue utilization
func (am *AlertManager) checkQueueUsage(health map[string]interface{}) {
	if utilization, ok := health["queue_utilization"].(float64); ok {
		utilizationPercent := utilization * 100

		if utilizationPercent >= am.thresholds.QueueCriticalPercent {
			am.triggerAlert("queue-critical", AlertCritical, "Stream Queue",
				fmt.Sprintf("Queue utilization at %.1f%% (critical threshold: %.1f%%)",
					utilizationPercent, am.thresholds.QueueCriticalPercent),
				map[string]interface{}{
					"utilization_percent": utilizationPercent,
					"queue_length": health["queue_length"],
					"queue_capacity": health["queue_capacity"],
				})
		} else if utilizationPercent >= am.thresholds.QueueWarningPercent {
			am.triggerAlert("queue-warning", AlertWarning, "Stream Queue",
				fmt.Sprintf("Queue utilization at %.1f%% (warning threshold: %.1f%%)",
					utilizationPercent, am.thresholds.QueueWarningPercent),
				map[string]interface{}{
					"utilization_percent": utilizationPercent,
					"queue_length": health["queue_length"],
					"queue_capacity": health["queue_capacity"],
				})
		} else {
			// Resolve if below warning threshold
			am.resolveAlert("queue-warning")
			am.resolveAlert("queue-critical")
		}
	}
}

// checkBufferUsage monitors buffer counts
func (am *AlertManager) checkBufferUsage() {
	bufferStats := GetTCPBufferStats()

	if bufferStats.TotalBuffers >= am.thresholds.BufferCriticalCount {
		am.triggerAlert("buffer-critical", AlertCritical, "TCP Buffers",
			fmt.Sprintf("Buffer count at %d (critical threshold: %d)",
				bufferStats.TotalBuffers, am.thresholds.BufferCriticalCount),
			map[string]interface{}{
				"total_buffers": bufferStats.TotalBuffers,
				"total_packets": bufferStats.TotalPackets,
				"buffers_dropped": bufferStats.BuffersDropped,
			})
	} else if bufferStats.TotalBuffers >= am.thresholds.BufferWarningCount {
		am.triggerAlert("buffer-warning", AlertWarning, "TCP Buffers",
			fmt.Sprintf("Buffer count at %d (warning threshold: %d)",
				bufferStats.TotalBuffers, am.thresholds.BufferWarningCount),
			map[string]interface{}{
				"total_buffers": bufferStats.TotalBuffers,
				"total_packets": bufferStats.TotalPackets,
				"buffers_dropped": bufferStats.BuffersDropped,
			})
	} else {
		// Resolve if below warning threshold
		am.resolveAlert("buffer-warning")
		am.resolveAlert("buffer-critical")
	}
}

// checkFailureRates monitors stream failure rates
func (am *AlertManager) checkFailureRates() {
	metrics := GetTCPStreamMetrics()

	if metrics.TotalStreamsCreated > 0 {
		failureRate := float64(metrics.TotalStreamsFailed) / float64(metrics.TotalStreamsCreated) * 100

		if failureRate >= am.thresholds.FailureRateCriticalPercent {
			am.triggerAlert("failure-rate-critical", AlertCritical, "Stream Processing",
				fmt.Sprintf("Stream failure rate at %.1f%% (critical threshold: %.1f%%)",
					failureRate, am.thresholds.FailureRateCriticalPercent),
				map[string]interface{}{
					"failure_rate_percent": failureRate,
					"total_created": metrics.TotalStreamsCreated,
					"total_failed": metrics.TotalStreamsFailed,
					"total_completed": metrics.TotalStreamsCompleted,
				})
		} else if failureRate >= am.thresholds.FailureRateWarningPercent {
			am.triggerAlert("failure-rate-warning", AlertWarning, "Stream Processing",
				fmt.Sprintf("Stream failure rate at %.1f%% (warning threshold: %.1f%%)",
					failureRate, am.thresholds.FailureRateWarningPercent),
				map[string]interface{}{
					"failure_rate_percent": failureRate,
					"total_created": metrics.TotalStreamsCreated,
					"total_failed": metrics.TotalStreamsFailed,
					"total_completed": metrics.TotalStreamsCompleted,
				})
		} else {
			// Resolve if below warning threshold
			am.resolveAlert("failure-rate-warning")
			am.resolveAlert("failure-rate-critical")
		}
	}
}

// triggerAlert creates and sends an alert
func (am *AlertManager) triggerAlert(id string, level AlertLevel, component, message string, metrics map[string]interface{}) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if alert already exists and is not resolved
	if existing, exists := am.activeAlerts[id]; exists && !existing.Resolved {
		// Update existing alert timestamp and metrics
		existing.Timestamp = time.Now()
		existing.Metrics = metrics
		return
	}

	// Create new alert
	alert := Alert{
		ID:        id,
		Level:     level,
		Component: component,
		Message:   message,
		Timestamp: time.Now(),
		Metrics:   metrics,
		Resolved:  false,
	}

	am.activeAlerts[id] = &alert

	// Send to all handlers
	for _, handler := range am.handlers {
		if err := handler.HandleAlert(alert); err != nil {
			logger.Error("Failed to handle alert", "alert_id", id, "error", err)
		}
	}
}

// resolveAlert marks an alert as resolved
func (am *AlertManager) resolveAlert(id string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if alert, exists := am.activeAlerts[id]; exists && !alert.Resolved {
		alert.Resolved = true
		now := time.Now()
		alert.ResolvedAt = &now

		// Create resolution alert
		resolutionAlert := Alert{
			ID:        id + "-resolved",
			Level:     AlertInfo,
			Component: alert.Component,
			Message:   fmt.Sprintf("RESOLVED: %s", alert.Message),
			Timestamp: now,
			Resolved:  true,
			ResolvedAt: &now,
		}

		// Send resolution to all handlers
		for _, handler := range am.handlers {
			if err := handler.HandleAlert(resolutionAlert); err != nil {
				logger.Error("Failed to handle resolution alert", "alert_id", id, "error", err)
			}
		}
	}
}

// GetActiveAlerts returns all active (unresolved) alerts
func (am *AlertManager) GetActiveAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var alerts []Alert
	for _, alert := range am.activeAlerts {
		if !alert.Resolved {
			alerts = append(alerts, *alert)
		}
	}
	return alerts
}

// GetAllAlerts returns all alerts (active and resolved)
func (am *AlertManager) GetAllAlerts() []Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var alerts []Alert
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, *alert)
	}
	return alerts
}

// Global alert manager instance
var (
	globalAlertManager *AlertManager
	alertManagerOnce   sync.Once
)

// GetAlertManager returns the global alert manager instance
func GetAlertManager() *AlertManager {
	alertManagerOnce.Do(func() {
		config := GetConfig()
		thresholds := DefaultAlertThresholds()

		// Override thresholds based on configuration
		if config.TCPMemoryLimit > 0 {
			thresholds.MemoryWarningMB = config.TCPMemoryLimit / (1024 * 1024) * 80 / 100 // 80% of limit
			thresholds.MemoryCriticalMB = config.TCPMemoryLimit / (1024 * 1024) * 95 / 100 // 95% of limit
		}

		if config.MaxTCPBuffers > 0 {
			thresholds.BufferWarningCount = int64(config.MaxTCPBuffers) * 80 / 100  // 80% of limit
			thresholds.BufferCriticalCount = int64(config.MaxTCPBuffers) * 95 / 100 // 95% of limit
		}

		globalAlertManager = NewAlertManager(thresholds)
	})
	return globalAlertManager
}

// CloseAlertManager closes the global alert manager
func CloseAlertManager() {
	if globalAlertManager != nil {
		globalAlertManager.Close()
	}
}