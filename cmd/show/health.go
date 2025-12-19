//go:build cli || all
// +build cli all

package show

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show TCP assembler health status",
	Long:  `Display the current health status of the TCP assembler including goroutine usage, queue status, and overall health indicators.`,
	Run: func(cmd *cobra.Command, args []string) {
		showTCPHealth()
	},
}

func showTCPHealth() {
	fmt.Println("=== TCP Assembler Health Status ===")

	if !voip.IsTCPAssemblerHealthy() {
		fmt.Println("Status: UNHEALTHY")
	} else {
		fmt.Println("Status: HEALTHY")
	}

	health := voip.GetTCPAssemblerHealth()

	if status, ok := health["status"].(string); ok && status == "not_initialized" {
		fmt.Println("TCP factory not initialized - no active VoIP capture running")
		return
	}

	fmt.Println()

	// Goroutine usage
	if activeGoroutines, ok := health["active_goroutines"].(int64); ok {
		if maxGoroutines, ok := health["max_goroutines"].(int64); ok {
			utilization := float64(activeGoroutines) / float64(maxGoroutines) * 100
			fmt.Printf("Goroutines: %d/%d (%.1f%%)\n", activeGoroutines, maxGoroutines, utilization)

			if utilization > 90 {
				fmt.Println("   HIGH: Consider increasing max_goroutines or enabling backpressure")
			} else if utilization > 70 {
				fmt.Println("   MODERATE: Monitor for potential capacity issues")
			}
		}
	}

	// Queue usage
	if queueLength, ok := health["queue_length"].(int); ok {
		if queueCapacity, ok := health["queue_capacity"].(int); ok {
			utilization := float64(queueLength) / float64(queueCapacity) * 100
			fmt.Printf("Queue: %d/%d (%.1f%%)\n", queueLength, queueCapacity, utilization)

			if utilization > 80 {
				fmt.Println("   HIGH: Consider increasing stream_queue_buffer")
			}
		}
	}

	// Active streams
	if activeStreams, ok := health["active_streams"].(int64); ok {
		fmt.Printf("Active Streams: %d\n", activeStreams)
	}

	// Last metrics update
	if lastUpdate, ok := health["last_metrics_update"].(time.Time); ok {
		age := time.Since(lastUpdate)
		fmt.Printf("Last Update: %v ago\n", age.Round(time.Second))

		if age > 2*time.Minute {
			fmt.Println("   WARNING: Metrics may be stale")
		}
	}

	fmt.Println()
}
