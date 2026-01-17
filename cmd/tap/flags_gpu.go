//go:build cuda

package tap

import (
	"github.com/endorses/lippycat/internal/pkg/cmdutil"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	enableVoIPFilter bool
	gpuBackend       string
	gpuBatchSize     int
)

// RegisterGPUFlags adds GPU-related flags to the command.
func RegisterGPUFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&enableVoIPFilter, "enable-voip-filter", false, "Enable GPU-accelerated VoIP filtering")
	cmd.PersistentFlags().StringVarP(&gpuBackend, "gpu-backend", "g", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd'")
	cmd.PersistentFlags().IntVar(&gpuBatchSize, "gpu-batch-size", 100, "Batch size for GPU processing")
}

// BindGPUViperFlags binds GPU flags to viper for config file support.
func BindGPUViperFlags(cmd *cobra.Command) {
	_ = viper.BindPFlag("tap.voip_filter.enabled", cmd.PersistentFlags().Lookup("enable-voip-filter"))
	_ = viper.BindPFlag("tap.voip_filter.gpu_backend", cmd.PersistentFlags().Lookup("gpu-backend"))
	_ = viper.BindPFlag("tap.voip_filter.gpu_batch_size", cmd.PersistentFlags().Lookup("gpu-batch-size"))
}

// GPUConfig holds GPU-related configuration for tap.
type GPUConfig struct {
	EnableVoIPFilter bool
	GPUBackend       string
	GPUBatchSize     int
}

// GetGPUConfig returns GPU configuration from flags/viper.
func GetGPUConfig() GPUConfig {
	return GPUConfig{
		EnableVoIPFilter: cmdutil.GetBoolConfig("tap.voip_filter.enabled", enableVoIPFilter),
		GPUBackend:       cmdutil.GetStringConfig("tap.voip_filter.gpu_backend", gpuBackend),
		GPUBatchSize:     cmdutil.GetIntConfig("tap.voip_filter.gpu_batch_size", gpuBatchSize),
	}
}
