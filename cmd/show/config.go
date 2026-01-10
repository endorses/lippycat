//go:build cli || all
// +build cli all

package show

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/output"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Display current configuration",
	Long:  `Show the current TCP SIP configuration including performance mode, thresholds, and optimization settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showConfig(jsonOutput)
	},
}

func init() {
	configCmd.Flags().Bool("json", false, "Output in JSON format")
}

func showConfig(jsonOutput bool) {
	config := voip.GetConfig()

	if jsonOutput {
		data, err := output.MarshalJSON(config)
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
		fmt.Println("Optimized for high-volume processing")
	case "latency":
		fmt.Println("Optimized for low-latency real-time processing")
	case "memory":
		fmt.Println("Optimized for minimal memory usage")
	default:
		fmt.Println("Balanced configuration for general use")
	}

	fmt.Println()
}
