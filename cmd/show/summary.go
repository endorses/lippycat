//go:build cli || all
// +build cli all

package show

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show overall system status summary",
	Long:  `Display a comprehensive summary of the TCP SIP processing system including health, metrics, alerts, and configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		showSummary()
	},
}

func showSummary() {
	fmt.Println("=== lippycat TCP SIP Processing Summary ===")
	fmt.Println()

	// Health status
	healthy := voip.IsTCPAssemblerHealthy()
	if healthy {
		fmt.Println("Overall Status: HEALTHY")
	} else {
		fmt.Println("Overall Status: UNHEALTHY")
	}

	// Quick metrics
	health := voip.GetTCPAssemblerHealth()
	if status, ok := health["status"].(string); ok && status == "not_initialized" {
		fmt.Println("TCP processing not active - start VoIP capture to see metrics")
		return
	}

	fmt.Println()

	// Resource utilization
	if activeGoroutines, ok := health["active_goroutines"].(int64); ok {
		if maxGoroutines, ok := health["max_goroutines"].(int64); ok {
			utilization := float64(activeGoroutines) / float64(maxGoroutines) * 100
			fmt.Printf("Goroutine Utilization: %.1f%% (%d/%d)\n", utilization, activeGoroutines, maxGoroutines)
		}
	}

	if queueLength, ok := health["queue_length"].(int); ok {
		if queueCapacity, ok := health["queue_capacity"].(int); ok {
			utilization := float64(queueLength) / float64(queueCapacity) * 100
			fmt.Printf("Queue Utilization: %.1f%% (%d/%d)\n", utilization, queueLength, queueCapacity)
		}
	}

	// Active alerts
	alertManager := voip.GetAlertManager()
	activeAlerts := alertManager.GetActiveAlerts()
	if len(activeAlerts) > 0 {
		fmt.Printf("Active Alerts: %d\n", len(activeAlerts))

		criticalCount := 0
		warningCount := 0
		for _, alert := range activeAlerts {
			switch alert.Level {
			case voip.AlertCritical:
				criticalCount++
			case voip.AlertWarning:
				warningCount++
			}
		}

		if criticalCount > 0 {
			fmt.Printf("   Critical: %d\n", criticalCount)
		}
		if warningCount > 0 {
			fmt.Printf("   Warning: %d\n", warningCount)
		}
	} else {
		fmt.Println("Active Alerts: None")
	}

	// Buffer stats
	bufferStats := voip.GetTCPBufferStats()
	fmt.Printf("TCP Buffers: %d (packets: %d)\n", bufferStats.TotalBuffers, bufferStats.TotalPackets)

	// Stream metrics
	streamMetrics := voip.GetTCPStreamMetrics()
	fmt.Printf("Active Streams: %d\n", streamMetrics.ActiveStreams)

	if streamMetrics.TotalStreamsCreated > 0 {
		successRate := float64(streamMetrics.TotalStreamsCompleted) / float64(streamMetrics.TotalStreamsCreated) * 100
		fmt.Printf("Stream Success Rate: %.1f%%\n", successRate)
	}

	// Configuration
	config := voip.GetConfig()
	fmt.Printf("Performance Mode: %s\n", config.TCPPerformanceMode)

	fmt.Println()
	fmt.Println("Use 'lc show <subcommand>' for detailed information:")
	fmt.Println("   health   - Detailed health status")
	fmt.Println("   metrics  - Comprehensive metrics")
	fmt.Println("   alerts   - Alert management")
	fmt.Println("   config   - Configuration details")
	fmt.Println()
}
