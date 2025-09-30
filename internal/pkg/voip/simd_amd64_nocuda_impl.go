// +build amd64,!cuda

package voip

// Non-CUDA implementations of SIMD functions
// When building without CUDA, these are TODO assembly implementations

func bytesContainsAVX2(data []byte, pattern []byte) bool {
	// TODO: Implement in assembly (voip/simd_amd64.s)
	// For now, fall back to BMH
	return bytesContainsBMH(data, pattern)
}

func bytesContainsSSE42(data []byte, pattern []byte) bool {
	// TODO: Implement in assembly using PCMPESTRI instruction
	// For now, fall back to BMH
	return bytesContainsBMH(data, pattern)
}