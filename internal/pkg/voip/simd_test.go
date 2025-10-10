package voip

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCPUFeatures(t *testing.T) {
	features := GetCPUFeatures()

	// Just verify structure is populated
	// Actual values depend on CPU
	t.Logf("CPU Features detected:")
	t.Logf("  AVX2: %v", features.HasAVX2)
	t.Logf("  SSE4.2: %v", features.HasSSE42)
	t.Logf("  SSE4.1: %v", features.HasSSE41)
	t.Logf("  SSSE3: %v", features.HasSSSE3)
	t.Logf("  SSE3: %v", features.HasSSE3)
	t.Logf("  SSE2: %v", features.HasSSE2)
	t.Logf("  POPCNT: %v", features.HasPOPCNT)
}

func TestBytesContainsSIMD(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  []byte
		expected bool
	}{
		{"simple match", []byte("hello world"), []byte("world"), true},
		{"no match", []byte("hello world"), []byte("foo"), false},
		{"empty pattern", []byte("hello"), []byte(""), true},
		{"empty data", []byte(""), []byte("test"), false},
		{"exact match", []byte("test"), []byte("test"), true},
		{"pattern longer", []byte("hi"), []byte("hello"), false},

		// SIP-specific tests
		{"Call-ID header", []byte("INVITE sip:user@host SIP/2.0\r\nCall-ID: abc123\r\n"), []byte("Call-ID"), true},
		{"m=audio", []byte("v=0\r\nm=audio 5004 RTP/AVP 0\r\n"), []byte("m=audio"), true},
		{"SIP/2.0", []byte("SIP/2.0 200 OK\r\n"), []byte("SIP/2.0"), true},

		// Edge cases for SIMD
		{"short data", []byte("hi"), []byte("hi"), true},
		{"4 byte pattern", []byte("testing"), []byte("test"), true},
		{"8 byte pattern", []byte("hello world testing"), []byte("testing"), true},
		{"16 byte pattern", []byte("this is a longer test string"), []byte("longer test"), true},
		{"32 byte pattern", []byte("this is a much longer test string for SIMD"), []byte("longer test string"), true},

		// Large data
		{"large data", []byte(strings.Repeat("x", 1000) + "target" + strings.Repeat("y", 1000)), []byte("target"), true},
		{"large data no match", []byte(strings.Repeat("x", 2000)), []byte("target"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesContainsSIMD(tt.data, tt.pattern)
			assert.Equal(t, tt.expected, result)

			// Verify against stdlib
			stdResult := bytes.Contains(tt.data, tt.pattern)
			assert.Equal(t, stdResult, result, "SIMD result differs from bytes.Contains")
		})
	}
}

func TestBytesEqualSIMD(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal short", []byte("test"), []byte("test"), true},
		{"not equal short", []byte("test"), []byte("fest"), false},
		{"different length", []byte("test"), []byte("testing"), false},
		{"empty", []byte(""), []byte(""), true},

		// SIMD-sized inputs
		{"16 bytes equal", []byte("0123456789ABCDEF"), []byte("0123456789ABCDEF"), true},
		{"16 bytes not equal", []byte("0123456789ABCDEF"), []byte("0123456789ABCDEf"), false},
		{"32 bytes equal", []byte("0123456789ABCDEF0123456789ABCDEF"), []byte("0123456789ABCDEF0123456789ABCDEF"), true},
		{"32 bytes not equal", []byte("0123456789ABCDEF0123456789ABCDEF"), []byte("0123456789ABCDEF0123456789ABCDEf"), false},

		// Large data
		{"large equal", []byte(strings.Repeat("A", 1000)), []byte(strings.Repeat("A", 1000)), true},
		{"large not equal", []byte(strings.Repeat("A", 1000)), []byte(strings.Repeat("A", 999) + "B"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesEqualSIMD(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)

			// Verify against bytes.Equal
			stdResult := bytes.Equal(tt.a, tt.b)
			assert.Equal(t, stdResult, result, "SIMD result differs from bytes.Equal")
		})
	}
}

func TestIndexByteSIMD(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		c        byte
		expected int
	}{
		{"found at start", []byte("hello"), 'h', 0},
		{"found in middle", []byte("hello"), 'l', 2},
		{"found at end", []byte("hello"), 'o', 4},
		{"not found", []byte("hello"), 'x', -1},
		{"empty data", []byte(""), 'x', -1},

		// SIMD-sized inputs
		{"16 bytes found", []byte("0123456789ABCDEF"), 'C', 12},
		{"32 bytes found", []byte("0123456789ABCDEF0123456789ABCDEF"), 'F', 15},
		{"32 bytes found late", []byte("0123456789ABCDEF0123456789ABCDEF"), '9', 9},

		// Large data
		{"large found early", []byte("X" + strings.Repeat("Y", 1000)), 'X', 0},
		{"large found late", []byte(strings.Repeat("Y", 1000) + "X"), 'X', 1000},
		{"large not found", []byte(strings.Repeat("Y", 1000)), 'X', -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IndexByteSIMD(tt.data, tt.c)
			assert.Equal(t, tt.expected, result)

			// Verify against bytes.IndexByte
			stdResult := bytes.IndexByte(tt.data, tt.c)
			assert.Equal(t, stdResult, result, "SIMD result differs from bytes.IndexByte")
		})
	}
}

func TestSIPMethodMatchSIMD(t *testing.T) {
	tests := []struct {
		name     string
		line     []byte
		expected string
	}{
		{"INVITE", []byte("INVITE sip:user@host SIP/2.0"), "INVITE"},
		{"REGISTER", []byte("REGISTER sip:user@host SIP/2.0"), "REGISTER"},
		{"BYE", []byte("BYE sip:user@host SIP/2.0"), "BYE"},
		{"CANCEL", []byte("CANCEL sip:user@host SIP/2.0"), "CANCEL"},
		{"ACK", []byte("ACK sip:user@host SIP/2.0"), "ACK"},
		{"OPTIONS", []byte("OPTIONS sip:user@host SIP/2.0"), "OPTIONS"},
		{"SIP response", []byte("SIP/2.0 200 OK"), ""},
		{"invalid", []byte("INVALID"), ""},
		{"too short", []byte("IN"), ""},
		{"empty", []byte(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SIPMethodMatchSIMD(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBytesEqualUnrolled(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{"equal", []byte("hello world"), []byte("hello world"), true},
		{"not equal", []byte("hello world"), []byte("hello World"), false},
		{"different length", []byte("hello"), []byte("hello world"), false},
		{"empty", []byte(""), []byte(""), true},
		{"9 bytes", []byte("123456789"), []byte("123456789"), true},
		{"16 bytes", []byte("0123456789ABCDEF"), []byte("0123456789ABCDEF"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesEqualUnrolled(tt.a, tt.b)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestIndexByteUnrolled(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		c    byte
		want int
	}{
		{"found at 0", []byte("hello"), 'h', 0},
		{"found at 5", []byte("hello world"), 'o', 4},
		{"found at 9", []byte("hello world"), 'd', 10},
		{"not found", []byte("hello"), 'x', -1},
		{"empty", []byte(""), 'x', -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexByteUnrolled(tt.data, tt.c)
			assert.Equal(t, tt.want, result)
		})
	}
}

// Benchmarks

func BenchmarkBytesContainsSIMD_Short(b *testing.B) {
	data := []byte("INVITE sip:user@example.com SIP/2.0")
	pattern := []byte("SIP")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesContainsSIMD(data, pattern)
	}
}

func BenchmarkBytesContainsSIMD_Medium(b *testing.B) {
	data := []byte(strings.Repeat("INVITE sip:user@example.com SIP/2.0\r\n", 10))
	pattern := []byte("Call-ID")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesContainsSIMD(data, pattern)
	}
}

func BenchmarkBytesContainsSIMD_Long(b *testing.B) {
	data := []byte(strings.Repeat("X", 1000) + "target" + strings.Repeat("Y", 1000))
	pattern := []byte("target")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesContainsSIMD(data, pattern)
	}
}

func BenchmarkBytesEqualSIMD_16(b *testing.B) {
	a := []byte("0123456789ABCDEF")
	c := []byte("0123456789ABCDEF")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesEqualSIMD(a, c)
	}
}

func BenchmarkBytesEqualSIMD_32(b *testing.B) {
	a := []byte("0123456789ABCDEF0123456789ABCDEF")
	c := []byte("0123456789ABCDEF0123456789ABCDEF")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesEqualSIMD(a, c)
	}
}

func BenchmarkBytesEqualSIMD_1024(b *testing.B) {
	a := []byte(strings.Repeat("A", 1024))
	c := []byte(strings.Repeat("A", 1024))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesEqualSIMD(a, c)
	}
}

func BenchmarkBytesEqual_1024(b *testing.B) {
	a := []byte(strings.Repeat("A", 1024))
	c := []byte(strings.Repeat("A", 1024))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = bytes.Equal(a, c)
	}
}

func BenchmarkIndexByteSIMD_Short(b *testing.B) {
	data := []byte("hello world")
	c := byte('o')

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = IndexByteSIMD(data, c)
	}
}

func BenchmarkIndexByteSIMD_Long(b *testing.B) {
	data := []byte(strings.Repeat("X", 1000) + "Y")
	c := byte('Y')

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = IndexByteSIMD(data, c)
	}
}

func BenchmarkIndexByte_Long(b *testing.B) {
	data := []byte(strings.Repeat("X", 1000) + "Y")
	c := byte('Y')

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = bytes.IndexByte(data, c)
	}
}

func BenchmarkSIPMethodMatchSIMD(b *testing.B) {
	line := []byte("INVITE sip:user@example.com SIP/2.0")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = SIPMethodMatchSIMD(line)
	}
}

func BenchmarkBytesEqualUnrolled(b *testing.B) {
	a := []byte("0123456789ABCDEF0123456789ABCDEF")
	c := []byte("0123456789ABCDEF0123456789ABCDEF")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = bytesEqualUnrolled(a, c)
	}
}

func BenchmarkIndexByteUnrolled(b *testing.B) {
	data := []byte("hello world testing")
	c := byte('t')

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = indexByteUnrolled(data, c)
	}
}
