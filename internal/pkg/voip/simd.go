package voip

import (
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

// BytesContainsSIMD uses SIMD instructions for fast pattern matching
// Falls back to scalar implementation if SIMD not available
func BytesContainsSIMD(data []byte, pattern []byte) bool {
	if len(pattern) == 0 {
		return true
	}
	if len(pattern) > len(data) {
		return false
	}

	// For very short patterns, scalar is faster due to setup overhead
	if len(pattern) < 4 {
		return bytesContainsSimple(data, pattern)
	}

	// Use SIMD if available
	if cpuFeatures.HasAVX2 && len(pattern) >= 8 {
		return bytesContainsAVX2(data, pattern)
	}
	if cpuFeatures.HasSSE42 && len(pattern) >= 4 {
		return bytesContainsSSE42(data, pattern)
	}

	// Fallback to optimized scalar
	return bytesContainsBMH(data, pattern)
}

// BytesEqualSIMD compares two byte slices using SIMD
func BytesEqualSIMD(a, b []byte) bool {
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

	// Fallback to scalar
	return BytesEqual(a, b)
}

// IndexByteSIMD finds first occurrence of byte using SIMD
func IndexByteSIMD(data []byte, c byte) int {
	if len(data) == 0 {
		return -1
	}

	// Use SIMD for larger data
	if cpuFeatures.HasAVX2 && len(data) >= 32 {
		return indexByteAVX2(data, c)
	}
	if cpuFeatures.HasSSE2 && len(data) >= 16 {
		return indexByteSSE2(data, c)
	}

	// Fallback to scalar
	return IndexByte(data, c)
}

// SIPMethodMatchSIMD performs parallel SIP method matching using SIMD
// This is particularly effective when checking multiple methods
func SIPMethodMatchSIMD(line []byte) string {
	if len(line) < 3 {
		return ""
	}

	// Use SIMD for parallel prefix matching if available
	if cpuFeatures.HasSSE42 && len(line) >= 8 {
		return sipMethodMatchSSE42(line)
	}

	// Fallback to scalar checks
	if BytesHasPrefixString(line, "INVITE") {
		return "INVITE"
	}
	if BytesHasPrefixString(line, "REGISTER") {
		return "REGISTER"
	}
	if BytesHasPrefixString(line, "BYE") {
		return "BYE"
	}
	if BytesHasPrefixString(line, "CANCEL") {
		return "CANCEL"
	}
	if BytesHasPrefixString(line, "ACK") {
		return "ACK"
	}
	if BytesHasPrefixString(line, "OPTIONS") {
		return "OPTIONS"
	}
	if BytesHasPrefixString(line, "SIP/2.0") {
		return ""
	}
	return ""
}

// bytesContainsAVX2 and bytesContainsSSE42 are implemented in:
// - simd_amd64_nocuda_impl.go (non-CUDA builds)
// - simd_cuda.go (CUDA builds - Go fallbacks)

// Assembly-based implementations are declared in:
// - simd_amd64_nocuda.go (when building without CUDA - links to simd_amd64.s)
// - simd_cuda.go (when building with CUDA - provides Go fallbacks due to CGo+asm conflict)

// sipMethodMatchDispatchFn is the dispatch function for SIP method matching.
// This is set to the assembly implementation on amd64 builds without CUDA.
var sipMethodMatchDispatchFn = sipMethodMatchFallback

// sipMethodMatchSSE42 uses SSE4.2 optimized matching for SIP method detection.
// On amd64 builds without CUDA, this uses assembly implementation with
// first-byte dispatch and 64-bit word comparison for fast prefix matching.
func sipMethodMatchSSE42(line []byte) string {
	// Dispatch to assembly or fallback implementation
	// Returns: 1=INVITE, 2=REGISTER, 3=BYE, 4=CANCEL, 5=ACK, 6=OPTIONS, -1=SIP/2.0, 0=no match
	result := sipMethodMatchDispatchFn(line)
	switch result {
	case 1:
		return "INVITE"
	case 2:
		return "REGISTER"
	case 3:
		return "BYE"
	case 4:
		return "CANCEL"
	case 5:
		return "ACK"
	case 6:
		return "OPTIONS"
	case -1:
		return "" // SIP/2.0 response
	default:
		return ""
	}
}

// sipMethodMatchFallback provides scalar fallback for non-amd64 or CUDA builds.
func sipMethodMatchFallback(line []byte) int {
	if len(line) < 3 {
		return 0
	}

	switch line[0] {
	case 'I':
		if len(line) >= 6 && BytesHasPrefixString(line, "INVITE") {
			return 1
		}
	case 'R':
		if len(line) >= 8 && BytesHasPrefixString(line, "REGISTER") {
			return 2
		}
	case 'B':
		if BytesHasPrefixString(line, "BYE") {
			return 3
		}
	case 'C':
		if len(line) >= 6 && BytesHasPrefixString(line, "CANCEL") {
			return 4
		}
	case 'A':
		if BytesHasPrefixString(line, "ACK") {
			return 5
		}
	case 'O':
		if len(line) >= 7 && BytesHasPrefixString(line, "OPTIONS") {
			return 6
		}
	case 'S':
		if len(line) >= 7 && BytesHasPrefixString(line, "SIP/2.0") {
			return -1
		}
	}
	return 0
}

// Optimized scalar implementations using unrolled loops

// bytesEqualUnrolled uses loop unrolling for better performance
func bytesEqualUnrolled(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	n := len(a)
	i := 0

	// Process 8 bytes at a time
	for i+8 <= n {
		if a[i] != b[i] || a[i+1] != b[i+1] || a[i+2] != b[i+2] || a[i+3] != b[i+3] ||
			a[i+4] != b[i+4] || a[i+5] != b[i+5] || a[i+6] != b[i+6] || a[i+7] != b[i+7] {
			return false
		}
		i += 8
	}

	// Process remaining bytes
	for i < n {
		if a[i] != b[i] {
			return false
		}
		i++
	}

	return true
}

// indexByteUnrolled uses loop unrolling for better performance
func indexByteUnrolled(data []byte, c byte) int {
	n := len(data)
	i := 0

	// Process 8 bytes at a time
	for i+8 <= n {
		if data[i] == c {
			return i
		}
		if data[i+1] == c {
			return i + 1
		}
		if data[i+2] == c {
			return i + 2
		}
		if data[i+3] == c {
			return i + 3
		}
		if data[i+4] == c {
			return i + 4
		}
		if data[i+5] == c {
			return i + 5
		}
		if data[i+6] == c {
			return i + 6
		}
		if data[i+7] == c {
			return i + 7
		}
		i += 8
	}

	// Process remaining bytes
	for i < n {
		if data[i] == c {
			return i
		}
		i++
	}

	return -1
}
