package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

// debugCmd represents the debug command
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug and inspect TCP SIP processing components",
	Long: `Debug command provides tools for inspecting and troubleshooting TCP SIP capture.
Use subcommands to inspect different aspects of the system:

  lippycat debug health     - Show TCP assembler health status
  lippycat debug metrics    - Display comprehensive TCP metrics
  lippycat debug alerts     - Show active alerts and alert history
  lippycat debug buffers    - Inspect TCP buffer statistics
  lippycat debug streams    - Show TCP stream processing metrics
  lippycat debug config     - Display current configuration
  lippycat debug summary    - Show overall system status summary`,
}

var debugHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show TCP assembler health status",
	Long:  `Display the current health status of the TCP assembler including goroutine usage, queue status, and overall health indicators.`,
	Run: func(cmd *cobra.Command, args []string) {
		showTCPHealth()
	},
}

var debugMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Display comprehensive TCP metrics",
	Long:  `Show detailed TCP processing metrics including stream statistics, buffer usage, and performance indicators.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showTCPMetrics(jsonOutput)
	},
}

var debugAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Show active alerts and alert history",
	Long:  `Display current active alerts and recent alert history for TCP resource monitoring.`,
	Run: func(cmd *cobra.Command, args []string) {
		showActiveOnly, _ := cmd.Flags().GetBool("active-only")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showAlerts(showActiveOnly, jsonOutput)
	},
}

var debugBuffersCmd = &cobra.Command{
	Use:   "buffers",
	Short: "Inspect TCP buffer statistics",
	Long:  `Show detailed TCP packet buffer statistics including total buffers, packets, and cleanup metrics.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showBufferStats(jsonOutput)
	},
}

var debugStreamsCmd = &cobra.Command{
	Use:   "streams",
	Short: "Show TCP stream processing metrics",
	Long:  `Display TCP stream processing statistics including active streams, completion rates, and failure metrics.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showStreamMetrics(jsonOutput)
	},
}

var debugConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Display current configuration",
	Long:  `Show the current TCP SIP configuration including performance mode, thresholds, and optimization settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showConfig(jsonOutput)
	},
}

var debugSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show overall system status summary",
	Long:  `Display a comprehensive summary of the TCP SIP processing system including health, metrics, alerts, and configuration.`,
	Run: func(cmd *cobra.Command, args []string) {
		showSummary()
	},
}

func init() {
	rootCmd.AddCommand(debugCmd)

	// Add subcommands
	debugCmd.AddCommand(debugHealthCmd)
	debugCmd.AddCommand(debugMetricsCmd)
	debugCmd.AddCommand(debugAlertsCmd)
	debugCmd.AddCommand(debugBuffersCmd)
	debugCmd.AddCommand(debugStreamsCmd)
	debugCmd.AddCommand(debugConfigCmd)
	debugCmd.AddCommand(debugSummaryCmd)

	// Add flags
	debugMetricsCmd.Flags().Bool("json", false, "Output in JSON format")
	debugAlertsCmd.Flags().Bool("active-only", false, "Show only active alerts")
	debugAlertsCmd.Flags().Bool("json", false, "Output in JSON format")
	debugBuffersCmd.Flags().Bool("json", false, "Output in JSON format")
	debugStreamsCmd.Flags().Bool("json", false, "Output in JSON format")
	debugConfigCmd.Flags().Bool("json", false, "Output in JSON format")
}

func showTCPHealth() {
	fmt.Println("=== TCP Assembler Health Status ===")

	if !voip.IsTCPAssemblerHealthy() {
		fmt.Println("❌ Status: UNHEALTHY")
	} else {
		fmt.Println("✅ Status: HEALTHY")
	}

	health := voip.GetTCPAssemblerHealth()

	if status, ok := health["status"].(string); ok && status == "not_initialized" {
		fmt.Println("⚠️  TCP factory not initialized - no active VoIP capture running")
		return
	}

	fmt.Println()

	// Goroutine usage
	if activeGoroutines, ok := health["active_goroutines"].(int64); ok {
		if maxGoroutines, ok := health["max_goroutines"].(int64); ok {
			utilization := float64(activeGoroutines) / float64(maxGoroutines) * 100
			fmt.Printf("🔄 Goroutines: %d/%d (%.1f%%)\n", activeGoroutines, maxGoroutines, utilization)

			if utilization > 90 {
				fmt.Println("   ⚠️  HIGH: Consider increasing max_goroutines or enabling backpressure")
			} else if utilization > 70 {
				fmt.Println("   ⚠️  MODERATE: Monitor for potential capacity issues")
			}
		}
	}

	// Queue usage
	if queueLength, ok := health["queue_length"].(int); ok {
		if queueCapacity, ok := health["queue_capacity"].(int); ok {
			utilization := float64(queueLength) / float64(queueCapacity) * 100
			fmt.Printf("📋 Queue: %d/%d (%.1f%%)\n", queueLength, queueCapacity, utilization)

			if utilization > 80 {
				fmt.Println("   ⚠️  HIGH: Consider increasing stream_queue_buffer")
			}
		}
	}

	// Active streams
	if activeStreams, ok := health["active_streams"].(int64); ok {
		fmt.Printf("🔗 Active Streams: %d\n", activeStreams)
	}

	// Last metrics update
	if lastUpdate, ok := health["last_metrics_update"].(time.Time); ok {
		age := time.Since(lastUpdate)
		fmt.Printf("📊 Last Update: %v ago\n", age.Round(time.Second))

		if age > 2*time.Minute {
			fmt.Println("   ⚠️  WARNING: Metrics may be stale")
		}
	}

	fmt.Println()
}

func showTCPMetrics(jsonOutput bool) {
	metrics := voip.GetTCPAssemblerMetrics()

	if jsonOutput {
		data, err := json.MarshalIndent(metrics, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling metrics: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== TCP Comprehensive Metrics ===")

	// Health section
	if health, ok := metrics["health"].(map[string]interface{}); ok {
		fmt.Println("\n🏥 Health Status:")
		if healthy, ok := health["healthy"].(bool); ok {
			if healthy {
				fmt.Println("   Status: ✅ HEALTHY")
			} else {
				fmt.Println("   Status: ❌ UNHEALTHY")
			}
		}
	}

	// Streams section
	if streams, ok := metrics["streams"].(voip.TCPStreamMetrics); ok {
		fmt.Println("\n🔗 Stream Metrics:")
		fmt.Printf("   Active Streams: %d\n", streams.ActiveStreams)
		fmt.Printf("   Total Created: %d\n", streams.TotalStreamsCreated)
		fmt.Printf("   Total Completed: %d\n", streams.TotalStreamsCompleted)
		fmt.Printf("   Total Failed: %d\n", streams.TotalStreamsFailed)
		fmt.Printf("   Queued Streams: %d\n", streams.QueuedStreams)
		fmt.Printf("   Dropped Streams: %d\n", streams.DroppedStreams)

		if streams.TotalStreamsCreated > 0 {
			successRate := float64(streams.TotalStreamsCompleted) / float64(streams.TotalStreamsCreated) * 100
			failureRate := float64(streams.TotalStreamsFailed) / float64(streams.TotalStreamsCreated) * 100
			fmt.Printf("   Success Rate: %.1f%%\n", successRate)
			fmt.Printf("   Failure Rate: %.1f%%\n", failureRate)

			if failureRate > 10 {
				fmt.Println("   ⚠️  HIGH failure rate - check logs for errors")
			}
		}
	}

	// Buffers section
	if buffers, ok := metrics["buffers"].(voip.TCPBufferStats); ok {
		fmt.Println("\n📦 Buffer Statistics:")
		fmt.Printf("   Total Buffers: %d\n", buffers.TotalBuffers)
		fmt.Printf("   Total Packets: %d\n", buffers.TotalPackets)
		fmt.Printf("   Buffers Dropped: %d\n", buffers.BuffersDropped)
		fmt.Printf("   Total Packets Buffered: %d\n", buffers.TotalPacketsBuffered)
		fmt.Printf("   Last Stats Update: %v ago\n", time.Since(buffers.LastStatsUpdate).Round(time.Second))

		if buffers.TotalBuffers > 8000 {
			fmt.Println("   ⚠️  HIGH buffer count - consider memory optimization")
		}
	}

	// Timestamp
	if timestamp, ok := metrics["timestamp"].(time.Time); ok {
		fmt.Printf("\n📅 Report Generated: %s\n", timestamp.Format("2006-01-02 15:04:05"))
	}

	fmt.Println()
}

func showAlerts(activeOnly, jsonOutput bool) {
	alertManager := voip.GetAlertManager()

	var alerts []voip.Alert
	if activeOnly {
		alerts = alertManager.GetActiveAlerts()
	} else {
		alerts = alertManager.GetAllAlerts()
	}

	if jsonOutput {
		data, err := json.MarshalIndent(alerts, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling alerts: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	if activeOnly {
		fmt.Println("=== Active Alerts ===")
	} else {
		fmt.Println("=== All Alerts ===")
	}

	if len(alerts) == 0 {
		if activeOnly {
			fmt.Println("✅ No active alerts")
		} else {
			fmt.Println("📭 No alerts in history")
		}
		return
	}

	// Sort alerts by timestamp (newest first)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LEVEL\tCOMPONENT\tSTATUS\tTIME\tMESSAGE")
	fmt.Fprintln(w, "-----\t---------\t------\t----\t-------")

	for _, alert := range alerts {
		level := alert.Level.String()
		status := "ACTIVE"
		if alert.Resolved {
			status = "RESOLVED"
		}

		// Add emoji indicators
		levelIcon := ""
		switch alert.Level {
		case voip.AlertCritical:
			levelIcon = "🔴"
		case voip.AlertWarning:
			levelIcon = "🟡"
		case voip.AlertInfo:
			levelIcon = "🔵"
		}

		timeStr := alert.Timestamp.Format("15:04:05")
		message := alert.Message
		if len(message) > 50 {
			message = message[:47] + "..."
		}

		fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\t%s\n",
			levelIcon, level, alert.Component, status, timeStr, message)
	}

	w.Flush()
	fmt.Println()
}

func showBufferStats(jsonOutput bool) {
	stats := voip.GetTCPBufferStats()

	if jsonOutput {
		data, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling buffer stats: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== TCP Buffer Statistics ===")
	fmt.Printf("Total Buffers: %d\n", stats.TotalBuffers)
	fmt.Printf("Total Packets: %d\n", stats.TotalPackets)
	fmt.Printf("Buffers Dropped: %d\n", stats.BuffersDropped)
	fmt.Printf("Total Packets Buffered: %d\n", stats.TotalPacketsBuffered)
	fmt.Printf("Last Stats Update: %v ago\n", time.Since(stats.LastStatsUpdate).Round(time.Second))

	if stats.TotalBuffers > 0 {
		avgPacketsPerBuffer := float64(stats.TotalPackets) / float64(stats.TotalBuffers)
		fmt.Printf("Avg Packets/Buffer: %.1f\n", avgPacketsPerBuffer)
	}

	if stats.BuffersDropped > 0 {
		dropRate := float64(stats.BuffersDropped) / float64(stats.TotalBuffers) * 100
		fmt.Printf("Buffer Drop Rate: %.1f%%\n", dropRate)

		if dropRate > 5 {
			fmt.Println("⚠️  HIGH drop rate - consider increasing max_tcp_buffers")
		}
	}

	fmt.Println()
}

func showStreamMetrics(jsonOutput bool) {
	metrics := voip.GetTCPStreamMetrics()

	if jsonOutput {
		data, err := json.MarshalIndent(metrics, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling stream metrics: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== TCP Stream Metrics ===")
	fmt.Printf("Active Streams: %d\n", metrics.ActiveStreams)
	fmt.Printf("Total Created: %d\n", metrics.TotalStreamsCreated)
	fmt.Printf("Total Completed: %d\n", metrics.TotalStreamsCompleted)
	fmt.Printf("Total Failed: %d\n", metrics.TotalStreamsFailed)
	fmt.Printf("Queued Streams: %d\n", metrics.QueuedStreams)
	fmt.Printf("Dropped Streams: %d\n", metrics.DroppedStreams)
	fmt.Printf("Last Update: %v ago\n", time.Since(metrics.LastMetricsUpdate).Round(time.Second))

	if metrics.TotalStreamsCreated > 0 {
		successRate := float64(metrics.TotalStreamsCompleted) / float64(metrics.TotalStreamsCreated) * 100
		failureRate := float64(metrics.TotalStreamsFailed) / float64(metrics.TotalStreamsCreated) * 100
		dropRate := float64(metrics.DroppedStreams) / float64(metrics.TotalStreamsCreated) * 100

		fmt.Printf("\nPerformance Metrics:\n")
		fmt.Printf("Success Rate: %.1f%%\n", successRate)
		fmt.Printf("Failure Rate: %.1f%%\n", failureRate)
		fmt.Printf("Drop Rate: %.1f%%\n", dropRate)

		if failureRate > 10 {
			fmt.Println("⚠️  HIGH failure rate - check error logs")
		}
		if dropRate > 5 {
			fmt.Println("⚠️  HIGH drop rate - consider increasing capacity")
		}
	}

	fmt.Println()
}

func showConfig(jsonOutput bool) {
	config := voip.GetConfig()

	if jsonOutput {
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config: %v\n", err)
			return
		}
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== TCP SIP Configuration ===")
	fmt.Printf("Performance Mode: %s\n", config.TCPPerformanceMode)
	fmt.Printf("Buffer Strategy: %s\n", config.TCPBufferStrategy)
	fmt.Printf("Max Goroutines: %d\n", config.MaxGoroutines)
	fmt.Printf("Max TCP Buffers: %d\n", config.MaxTCPBuffers)
	fmt.Printf("Cleanup Interval: %v\n", config.TCPCleanupInterval)
	fmt.Printf("Buffer Max Age: %v\n", config.TCPBufferMaxAge)
	fmt.Printf("Stream Timeout: %v\n", config.TCPStreamTimeout)
	fmt.Printf("Batch Size: %d\n", config.TCPBatchSize)
	fmt.Printf("Memory Limit: %d MB\n", config.TCPMemoryLimit/(1024*1024))
	fmt.Printf("Backpressure Enabled: %t\n", config.EnableBackpressure)
	fmt.Printf("Memory Optimization: %t\n", config.MemoryOptimization)
	fmt.Printf("Latency Optimization: %t\n", config.TCPLatencyOptimization)

	fmt.Println("\nRecommendations:")
	switch config.TCPPerformanceMode {
	case "throughput":
		fmt.Println("📈 Optimized for high-volume processing")
	case "latency":
		fmt.Println("⚡ Optimized for low-latency real-time processing")
	case "memory":
		fmt.Println("💾 Optimized for minimal memory usage")
	default:
		fmt.Println("⚖️  Balanced configuration for general use")
	}

	fmt.Println()
}

func showSummary() {
	fmt.Println("=== lippycat TCP SIP Processing Summary ===")
	fmt.Println()

	// Health status
	healthy := voip.IsTCPAssemblerHealthy()
	if healthy {
		fmt.Println("🟢 Overall Status: HEALTHY")
	} else {
		fmt.Println("🔴 Overall Status: UNHEALTHY")
	}

	// Quick metrics
	health := voip.GetTCPAssemblerHealth()
	if status, ok := health["status"].(string); ok && status == "not_initialized" {
		fmt.Println("⚠️  TCP processing not active - start VoIP capture to see metrics")
		return
	}

	fmt.Println()

	// Resource utilization
	if activeGoroutines, ok := health["active_goroutines"].(int64); ok {
		if maxGoroutines, ok := health["max_goroutines"].(int64); ok {
			utilization := float64(activeGoroutines) / float64(maxGoroutines) * 100
			fmt.Printf("🔄 Goroutine Utilization: %.1f%% (%d/%d)\n", utilization, activeGoroutines, maxGoroutines)
		}
	}

	if queueLength, ok := health["queue_length"].(int); ok {
		if queueCapacity, ok := health["queue_capacity"].(int); ok {
			utilization := float64(queueLength) / float64(queueCapacity) * 100
			fmt.Printf("📋 Queue Utilization: %.1f%% (%d/%d)\n", utilization, queueLength, queueCapacity)
		}
	}

	// Active alerts
	alertManager := voip.GetAlertManager()
	activeAlerts := alertManager.GetActiveAlerts()
	if len(activeAlerts) > 0 {
		fmt.Printf("🚨 Active Alerts: %d\n", len(activeAlerts))

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
			fmt.Printf("   🔴 Critical: %d\n", criticalCount)
		}
		if warningCount > 0 {
			fmt.Printf("   🟡 Warning: %d\n", warningCount)
		}
	} else {
		fmt.Println("✅ Active Alerts: None")
	}

	// Buffer stats
	bufferStats := voip.GetTCPBufferStats()
	fmt.Printf("📦 TCP Buffers: %d (packets: %d)\n", bufferStats.TotalBuffers, bufferStats.TotalPackets)

	// Stream metrics
	streamMetrics := voip.GetTCPStreamMetrics()
	fmt.Printf("🔗 Active Streams: %d\n", streamMetrics.ActiveStreams)

	if streamMetrics.TotalStreamsCreated > 0 {
		successRate := float64(streamMetrics.TotalStreamsCompleted) / float64(streamMetrics.TotalStreamsCreated) * 100
		fmt.Printf("📊 Stream Success Rate: %.1f%%\n", successRate)
	}

	// Configuration
	config := voip.GetConfig()
	fmt.Printf("⚙️  Performance Mode: %s\n", config.TCPPerformanceMode)

	fmt.Println()
	fmt.Println("💡 Use 'lippycat debug <subcommand>' for detailed information:")
	fmt.Println("   health   - Detailed health status")
	fmt.Println("   metrics  - Comprehensive metrics")
	fmt.Println("   alerts   - Alert management")
	fmt.Println("   config   - Configuration details")
	fmt.Println()
}
