//go:build !amd64

package simd

// Fallback implementations for non-x86 platforms
// Uses pure Go without SIMD instructions

func bytesEqualAVX2(a, b []byte) bool {
	// Simple byte-by-byte comparison
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesEqualSSE2(a, b []byte) bool {
	// Simple byte-by-byte comparison
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesContainsAVX2(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}

func bytesContainsSSE42(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}
