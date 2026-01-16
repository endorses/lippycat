//go:build !cuda

package hunt

import "github.com/spf13/cobra"

// RegisterGPUFlags is a no-op in non-CUDA builds.
func RegisterGPUFlags(cmd *cobra.Command) {}

// BindGPUViperFlags is a no-op in non-CUDA builds.
func BindGPUViperFlags(cmd *cobra.Command) {}

// GPUConfig holds GPU-related configuration for the hunter.
type GPUConfig struct {
	EnableVoIPFilter bool
	GPUBackend       string
	GPUBatchSize     int
}

// GetGPUConfig returns empty GPU configuration in non-CUDA builds.
func GetGPUConfig() GPUConfig {
	return GPUConfig{}
}
