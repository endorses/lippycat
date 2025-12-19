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

var streamsCmd = &cobra.Command{
	Use:   "streams",
	Short: "Show TCP stream processing metrics",
	Long:  `Display TCP stream processing statistics including active streams, completion rates, and failure metrics.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showStreamMetrics(jsonOutput)
	},
}

func init() {
	streamsCmd.Flags().Bool("json", false, "Output in JSON format")
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
			fmt.Println("HIGH failure rate - check error logs")
		}
		if dropRate > 5 {
			fmt.Println("HIGH drop rate - consider increasing capacity")
		}
	}

	fmt.Println()
}
