//go:build !amd64

package voip

// CPUFeatures holds detected CPU capabilities
// On non-amd64 platforms, all x86-specific features are false
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
	// No x86 SIMD features on non-amd64 platforms
	cpuFeatures = CPUFeatures{}
}

// GetCPUFeatures returns detected CPU features
func GetCPUFeatures() CPUFeatures {
	return cpuFeatures
}

// BytesContainsSIMD uses optimized pattern matching
// Falls back to scalar implementation on non-amd64
func BytesContainsSIMD(data []byte, pattern []byte) bool {
	if len(pattern) == 0 {
		return true
	}
	if len(pattern) > len(data) {
		return false
	}

	// For very short patterns, use simple search
	if len(pattern) < 4 {
		return bytesContainsSimple(data, pattern)
	}

	// Use optimized scalar implementation
	return bytesContainsBMH(data, pattern)
}

// BytesEqualSIMD compares two byte slices
func BytesEqualSIMD(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	if len(a) == 0 {
		return true
	}

	return BytesEqual(a, b)
}

// IndexByteSIMD finds first occurrence of byte
func IndexByteSIMD(data []byte, c byte) int {
	if len(data) == 0 {
		return -1
	}

	return IndexByte(data, c)
}

// SIPMethodMatchSIMD performs SIP method matching
func SIPMethodMatchSIMD(line []byte) string {
	if len(line) < 3 {
		return ""
	}

	// Use scalar checks
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

// sipMethodMatchDispatchFn is the dispatch function for SIP method matching.
var sipMethodMatchDispatchFn = sipMethodMatchFallback

// sipMethodMatchFallback provides scalar fallback for non-amd64 platforms.
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
