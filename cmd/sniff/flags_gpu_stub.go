//go:build !cuda

package sniff

import "github.com/spf13/cobra"

// RegisterGPUFlags is a no-op in non-CUDA builds.
func RegisterGPUFlags(cmd *cobra.Command) {}

// BindGPUViperFlags is a no-op in non-CUDA builds.
func BindGPUViperFlags(cmd *cobra.Command) {}

// ApplyGPUConfig is a no-op in non-CUDA builds.
func ApplyGPUConfig(cmd *cobra.Command) {}
