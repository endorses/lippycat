//go:build amd64 && !cuda
// +build amd64,!cuda

package voip

// Assembly function declarations - implemented in simd_amd64.s
// These are only available when NOT building with CUDA (CGo + asm conflict)

// bytesEqualAVX2 is implemented in assembly
func bytesEqualAVX2(a, b []byte) bool

// bytesEqualSSE2 is implemented in assembly
func bytesEqualSSE2(a, b []byte) bool

// indexByteAVX2 is implemented in assembly
func indexByteAVX2(data []byte, c byte) int

// indexByteSSE2 is implemented in assembly
func indexByteSSE2(data []byte, c byte) int
