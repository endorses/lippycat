package simd

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

// CPUFeatures holds detected CPU capabilities
type CPUFeatures struct {
	HasAVX2   bool
	HasSSE42  bool
	HasSSE41  bool
	HasSSSE3  bool
	HasSSE3   bool
	HasSSE2   bool
	HasPOPCNT bool
}

var cpuFeatures CPUFeatures

func init() {
	// Detect CPU features at startup
	cpuFeatures = CPUFeatures{
		HasAVX2:   cpu.X86.HasAVX2,
		HasSSE42:  cpu.X86.HasSSE42,
		HasSSE41:  cpu.X86.HasSSE41,
		HasSSSE3:  cpu.X86.HasSSSE3,
		HasSSE3:   cpu.X86.HasSSE3,
		HasSSE2:   cpu.X86.HasSSE2,
		HasPOPCNT: cpu.X86.HasPOPCNT,
	}
}

// GetCPUFeatures returns detected CPU features
func GetCPUFeatures() CPUFeatures {
	return cpuFeatures
}

// StringContains checks if string contains substring using SIMD when possible
// This is a general-purpose version for use across the codebase
func StringContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}

	// Convert strings to byte slices without allocation
	sBytes := unsafeStringToBytes(s)
	substrBytes := unsafeStringToBytes(substr)

	return BytesContains(sBytes, substrBytes)
}

// BytesContains checks if byte slice contains subslice using SIMD
func BytesContains(data []byte, substr []byte) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(data) {
		return false
	}

	// For very short patterns, scalar is faster
	if len(substr) < 4 {
		return bytesContainsSimple(data, substr)
	}

	// Use SIMD if available
	if cpuFeatures.HasAVX2 && len(substr) >= 8 {
		return bytesContainsAVX2(data, substr)
	}
	if cpuFeatures.HasSSE42 && len(substr) >= 4 {
		return bytesContainsSSE42(data, substr)
	}

	// Fallback to optimized scalar (BMH)
	return bytesContainsBMH(data, substr)
}

// BytesEqual compares two byte slices using SIMD
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	if len(a) == 0 {
		return true
	}

	// Use SIMD for larger comparisons
	if cpuFeatures.HasAVX2 && len(a) >= 32 {
		return bytesEqualAVX2(a, b)
	}
	if cpuFeatures.HasSSE2 && len(a) >= 16 {
		return bytesEqualSSE2(a, b)
	}

	// Fallback to built-in comparison
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// unsafeStringToBytes converts string to []byte without allocation
// WARNING: The returned byte slice MUST NOT be modified
func unsafeStringToBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	// #nosec G103 -- Audited: Zero-alloc conversion for SIMD operations, string data is never modified
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// Simple scalar implementation for short patterns
func bytesContainsSimple(data []byte, substr []byte) bool {
	if len(data) < len(substr) {
		return false
	}

	for i := 0; i <= len(data)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if data[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Boyer-Moore-Horspool algorithm for efficient string matching
func bytesContainsBMH(data []byte, pattern []byte) bool {
	if len(pattern) > len(data) {
		return false
	}

	// Build bad character table
	var badChar [256]int
	for i := range badChar {
		badChar[i] = len(pattern)
	}
	for i := 0; i < len(pattern)-1; i++ {
		badChar[pattern[i]] = len(pattern) - 1 - i
	}

	// Search
	i := 0
	for i <= len(data)-len(pattern) {
		j := len(pattern) - 1
		for j >= 0 && data[i+j] == pattern[j] {
			j--
		}
		if j < 0 {
			return true
		}
		i += badChar[data[i+len(pattern)-1]]
	}

	return false
}

// SIMD implementations are provided by platform-specific files:
// - simd_amd64.go + simd_amd64.s for x86-64 with SIMD
// - simd_fallback.go for other platforms
