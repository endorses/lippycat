package voip

import (
	"strconv"
	"sync"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/simd"
)

// Zero-allocation string operations for hot paths

// BytesContains checks if subslice is in slice without allocating
// Uses SIMD acceleration when available for better performance
func BytesContains(data []byte, substr []byte) bool {
	// Use general-purpose SIMD package
	return simd.BytesContains(data, substr)
}

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

// BytesHasPrefix checks if data starts with prefix
func BytesHasPrefix(data []byte, prefix []byte) bool {
	if len(prefix) > len(data) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

// BytesHasPrefixString checks if data starts with prefix string
func BytesHasPrefixString(data []byte, prefix string) bool {
	if len(prefix) > len(data) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

// BytesToString converts bytes to string without allocation
// WARNING: The returned string shares memory with the byte slice.
// Only use when the byte slice won't be modified.
func BytesToString(b []byte) string {
	// #nosec G103 -- Audited: Zero-alloc conversion for performance, byte slice is immutable after conversion
	return *(*string)(unsafe.Pointer(&b))
}

// StringToBytes converts string to bytes without allocation
// WARNING: The returned byte slice is read-only.
// Modifying it will cause a panic.
func StringToBytes(s string) []byte {
	// #nosec G103 -- Audited: Zero-alloc conversion for performance, string data is never modified
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// IntToBytes converts an integer to byte slice without allocation
// Returns a byte slice representation suitable for string operations
func IntToBytes(buf []byte, n int) []byte {
	if n == 0 {
		return []byte{'0'}
	}

	negative := n < 0
	if negative {
		n = -n
	}

	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if negative {
		i--
		buf[i] = '-'
	}

	return buf[i:]
}

// IntToString converts integer to string with minimal allocation
func IntToString(n int) string {
	// Use standard library for this as it's already optimized
	return strconv.Itoa(n)
}

// String interning for common SIP headers
type StringInterner struct {
	strings sync.Map // map[string]string
	hits    uint64
	misses  uint64
}

var (
	globalInterner     *StringInterner
	globalInternerOnce sync.Once
)

// GetInterner returns the global string interner
func GetInterner() *StringInterner {
	globalInternerOnce.Do(func() {
		globalInterner = &StringInterner{}
		// Pre-populate with common SIP headers
		commonHeaders := []string{
			"call-id", "from", "to", "via", "contact",
			"content-type", "content-length", "cseq",
			"max-forwards", "allow", "supported", "user-agent",
			"server", "accept", "accept-encoding", "accept-language",
			"authorization", "proxy-authorization", "www-authenticate",
			"proxy-authenticate", "expires", "min-expires", "timestamp",
			"route", "record-route", "refer-to", "referred-by",
			"replaces", "allow-events", "event", "subscription-state",
			// Common SIP methods
			"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
			// Common header values
			"application/sdp", "SIP/2.0", "UDP", "TCP", "TLS",
			"m=audio", "a=rtpmap", "c=IN", "IP4", "IP6",
		}
		for _, h := range commonHeaders {
			globalInterner.strings.Store(h, h)
		}
	})
	return globalInterner
}

// Intern returns a canonical representation of the string
// If the string was seen before, returns the existing copy
func (si *StringInterner) Intern(s string) string {
	if val, ok := si.strings.Load(s); ok {
		return val.(string)
	}

	// Store and return
	si.strings.Store(s, s)
	return s
}

// InternBytes interns a byte slice as a string
func (si *StringInterner) InternBytes(b []byte) string {
	s := string(b) // This allocates, but only once per unique string
	return si.Intern(s)
}

// Stats returns interner statistics
func (si *StringInterner) Stats() (hits, misses uint64) {
	return si.hits, si.misses
}

// ParseIntFast parses an integer from byte slice without allocation
func ParseIntFast(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}

	negative := false
	start := 0

	if b[0] == '-' {
		negative = true
		start = 1
	} else if b[0] == '+' {
		start = 1
	}

	if start >= len(b) {
		return 0, false
	}

	result := 0
	for i := start; i < len(b); i++ {
		if b[i] < '0' || b[i] > '9' {
			return 0, false
		}
		digit := int(b[i] - '0')
		result = result*10 + digit
	}

	if negative {
		result = -result
	}

	return result, true
}

// TrimSpace removes leading and trailing whitespace from byte slice
func TrimSpace(b []byte) []byte {
	// Trim leading space
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}

	// Trim trailing space
	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}

	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// BytesEqual compares two byte slices for equality
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BytesEqualString compares byte slice with string
func BytesEqualString(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// ToLower converts ASCII uppercase letters to lowercase in place
func ToLower(b []byte) {
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
}

// ToLowerCopy converts ASCII uppercase letters to lowercase without modifying original
func ToLowerCopy(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	}
	dst = dst[:len(src)]

	for i := 0; i < len(src); i++ {
		if src[i] >= 'A' && src[i] <= 'Z' {
			dst[i] = src[i] + ('a' - 'A')
		} else {
			dst[i] = src[i]
		}
	}
	return dst
}

// IndexByte finds the first occurrence of byte c in slice
func IndexByte(data []byte, c byte) int {
	for i := 0; i < len(data); i++ {
		if data[i] == c {
			return i
		}
	}
	return -1
}

// SplitN splits byte slice by delimiter, up to n times
func SplitN(data []byte, delim byte, n int) [][]byte {
	if n <= 0 {
		return nil
	}

	result := make([][]byte, 0, n)
	start := 0

	for i := 0; i < len(data) && len(result) < n-1; i++ {
		if data[i] == delim {
			result = append(result, data[start:i])
			start = i + 1
		}
	}

	// Add remaining data
	if start <= len(data) {
		result = append(result, data[start:])
	}

	return result
}
