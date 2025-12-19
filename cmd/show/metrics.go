//go:build cli || all
// +build cli all

package show

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Display comprehensive TCP metrics",
	Long:  `Show detailed TCP processing metrics including stream statistics, buffer usage, and performance indicators.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showTCPMetrics(jsonOutput)
	},
}

func init() {
	metricsCmd.Flags().Bool("json", false, "Output in JSON format")
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
		fmt.Println("\nHealth Status:")
		if healthy, ok := health["healthy"].(bool); ok {
			if healthy {
				fmt.Println("   Status: HEALTHY")
			} else {
				fmt.Println("   Status: UNHEALTHY")
			}
		}
	}

	// Streams section
	if streams, ok := metrics["streams"].(voip.TCPStreamMetrics); ok {
		fmt.Println("\nStream Metrics:")
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
				fmt.Println("   HIGH failure rate - check logs for errors")
			}
		}
	}

	// Buffers section
	if buffers, ok := metrics["buffers"].(voip.TCPBufferStats); ok {
		fmt.Println("\nBuffer Statistics:")
		fmt.Printf("   Total Buffers: %d\n", buffers.TotalBuffers)
		fmt.Printf("   Total Packets: %d\n", buffers.TotalPackets)
		fmt.Printf("   Buffers Dropped: %d\n", buffers.BuffersDropped)
		fmt.Printf("   Total Packets Buffered: %d\n", buffers.TotalPacketsBuffered)
		fmt.Printf("   Last Stats Update: %v ago\n", time.Since(buffers.LastStatsUpdate).Round(time.Second))

		if buffers.TotalBuffers > 8000 {
			fmt.Println("   HIGH buffer count - consider memory optimization")
		}
	}

	// Timestamp
	if timestamp, ok := metrics["timestamp"].(time.Time); ok {
		fmt.Printf("\nReport Generated: %s\n", timestamp.Format("2006-01-02 15:04:05"))
	}

	fmt.Println()
}
