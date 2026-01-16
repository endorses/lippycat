//go:build cuda

package sniff

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	gpuBackend   string
	gpuBatchSize int
	gpuMaxMemory int64
	gpuEnable    bool
)

// RegisterGPUFlags adds GPU-related flags to the command.
func RegisterGPUFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&gpuEnable, "gpu-enable", true, "Enable GPU acceleration for pattern matching (default: true)")
	cmd.Flags().StringVarP(&gpuBackend, "gpu-backend", "g", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd', 'disabled' (default: auto)")
	cmd.Flags().IntVar(&gpuBatchSize, "gpu-batch-size", 1024, "Batch size for GPU processing (default: 1024)")
	cmd.Flags().Int64Var(&gpuMaxMemory, "gpu-max-memory", 0, "Maximum GPU memory in bytes (0 = auto)")
}

// BindGPUViperFlags binds GPU flags to viper for config file support.
func BindGPUViperFlags(cmd *cobra.Command) {
	_ = viper.BindPFlag("voip.gpu_enable", cmd.Flags().Lookup("gpu-enable"))
	_ = viper.BindPFlag("voip.gpu_backend", cmd.Flags().Lookup("gpu-backend"))
	_ = viper.BindPFlag("voip.gpu_batch_size", cmd.Flags().Lookup("gpu-batch-size"))
	_ = viper.BindPFlag("voip.gpu_max_memory", cmd.Flags().Lookup("gpu-max-memory"))
}

// ApplyGPUConfig sets GPU configuration in viper if flags were changed.
func ApplyGPUConfig(cmd *cobra.Command) {
	if cmd.Flags().Changed("gpu-enable") {
		viper.Set("voip.gpu_enable", gpuEnable)
	}
	if cmd.Flags().Changed("gpu-backend") {
		viper.Set("voip.gpu_backend", gpuBackend)
	}
	if cmd.Flags().Changed("gpu-batch-size") {
		viper.Set("voip.gpu_batch_size", gpuBatchSize)
	}
	if cmd.Flags().Changed("gpu-max-memory") {
		viper.Set("voip.gpu_max_memory", gpuMaxMemory)
	}
}
