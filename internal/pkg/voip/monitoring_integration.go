package voip

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip/monitoring"
)

// InitializeMonitoringFromConfig initializes monitoring based on VoIP configuration
func InitializeMonitoringFromConfig() error {
	config := GetConfig()

	if !config.MonitoringEnabled {
		logger.Debug("Monitoring disabled in configuration")
		return nil
	}

	monitorConfig := monitoring.MonitorConfig{
		Enabled:                config.MonitoringEnabled,
		MetricsEnabled:         config.MetricsEnabled,
		PrometheusEnabled:      config.PrometheusEnabled,
		PrometheusPort:         config.PrometheusPort,
		TracingEnabled:         config.TracingEnabled,
		UpdateInterval:         config.MonitoringUpdateInterval,
		EnableRuntimeMetrics:   config.EnableRuntimeMetrics,
		EnableSystemMetrics:    config.EnableSystemMetrics,
		EnablePluginMetrics:    config.EnablePluginMetrics,
	}

	if err := monitoring.InitializeMonitoring(monitorConfig); err != nil {
		return err
	}

	logger.Info("VoIP monitoring initialized",
		"metrics_enabled", config.MetricsEnabled,
		"prometheus_enabled", config.PrometheusEnabled,
		"prometheus_port", config.PrometheusPort,
		"tracing_enabled", config.TracingEnabled)

	return nil
}

// ShutdownMonitoringSystem gracefully shuts down the monitoring system
func ShutdownMonitoringSystem() error {
	return monitoring.ShutdownMonitoring()
}

// StartMonitoringIfEnabled starts monitoring if enabled in configuration
func StartMonitoringIfEnabled() {
	if err := InitializeMonitoringFromConfig(); err != nil {
		logger.Error("Failed to initialize monitoring", "error", err)
	}
}

// GetMonitoringStats returns comprehensive monitoring statistics
func GetMonitoringStats() map[string]interface{} {
	monitor := monitoring.GetGlobalMonitor()
	return monitor.GetStats()
}

// RecordVoIPPacketProcessing records VoIP packet processing with monitoring
func RecordVoIPPacketProcessing(ctx context.Context, protocol string, callID string, processingTime int64) {
	monitoring.RecordVoIPEvent(ctx, "packet_processed", map[string]interface{}{
		"protocol":        protocol,
		"call_id":         callID,
		"processing_time": processingTime,
	})
}

// RecordCallStateChange records call state changes with monitoring
func RecordCallStateChange(ctx context.Context, callID, oldState, newState string) {
	monitoring.RecordCallEvent(ctx, callID, "state_change", map[string]interface{}{
		"old_state": oldState,
		"new_state": newState,
		"protocol":  "sip",
	})
}

// UpdateSystemMetrics updates system-level metrics
func UpdateSystemMetrics() {
	// Update active call counts
	if IsLockFreeModeEnabled() {
		tracker := GetLockFreeTracker()
		stats := tracker.GetStats()
		monitoring.UpdateActiveCalls(int(stats.ActiveCalls), "sip")
	} else {
		// Traditional tracker would need similar functionality
		monitoring.UpdateActiveCalls(0, "sip")
	}

	// Update plugin metrics if enabled
	if processor := GetGlobalPluginProcessor(); processor.IsEnabled() {
		registry := processor.GetRegistry()
		registryStats := registry.GetStats()

		monitoring.SetGauge("plugin_packets_processed", registryStats.PacketsProcessed.Load())
		monitoring.SetGauge("plugin_processing_time", registryStats.ProcessingTime.Load())
		monitoring.SetGauge("plugin_error_count", registryStats.ErrorCount.Load())
	}
}