//go:build amd64

package simd

// Assembly implementations are in simd_amd64.s
// These declarations allow Go to call the assembly functions

//go:noescape
func bytesEqualAVX2(a, b []byte) bool

//go:noescape
func bytesEqualSSE2(a, b []byte) bool

// Note: bytesContainsAVX2 and bytesContainsSSE42 use Go fallbacks for now
// Full assembly implementation would be more complex
func bytesContainsAVX2(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}

func bytesContainsSSE42(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}
