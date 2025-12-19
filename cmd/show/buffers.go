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

var buffersCmd = &cobra.Command{
	Use:   "buffers",
	Short: "Inspect TCP buffer statistics",
	Long:  `Show detailed TCP packet buffer statistics including total buffers, packets, and cleanup metrics.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showBufferStats(jsonOutput)
	},
}

func init() {
	buffersCmd.Flags().Bool("json", false, "Output in JSON format")
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
			fmt.Println("HIGH drop rate - consider increasing max_tcp_buffers")
		}
	}

	fmt.Println()
}
