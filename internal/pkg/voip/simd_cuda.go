//go:build cuda
// +build cuda

package voip

// When building with CUDA, we can't use assembly (CGo limitation)
// Provide Go implementations of the SIMD functions

// bytesEqualAVX2 - Go fallback when assembly is not available
func bytesEqualAVX2(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return BytesEqual(a, b)
}

// bytesEqualSSE2 - Go fallback when assembly is not available
func bytesEqualSSE2(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return BytesEqual(a, b)
}

// indexByteAVX2 - Go fallback when assembly is not available
func indexByteAVX2(data []byte, c byte) int {
	for i, b := range data {
		if b == c {
			return i
		}
	}
	return -1
}

// indexByteSSE2 - Go fallback when assembly is not available
func indexByteSSE2(data []byte, c byte) int {
	for i, b := range data {
		if b == c {
			return i
		}
	}
	return -1
}

// bytesContainsAVX2 - Go fallback when assembly is not available
func bytesContainsAVX2(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}

// bytesContainsSSE42 - Go fallback when assembly is not available
func bytesContainsSSE42(data []byte, pattern []byte) bool {
	return bytesContainsBMH(data, pattern)
}
