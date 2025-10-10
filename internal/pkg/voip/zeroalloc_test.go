package voip

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBytesContains(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		substr   []byte
		expected bool
	}{
		{"simple match", []byte("hello world"), []byte("world"), true},
		{"no match", []byte("hello world"), []byte("foo"), false},
		{"empty substr", []byte("hello"), []byte(""), true},
		{"empty data", []byte(""), []byte("test"), false},
		{"exact match", []byte("test"), []byte("test"), true},
		{"substr longer", []byte("hi"), []byte("hello"), false},
		{"SIP header", []byte("Call-ID: abc123"), []byte("Call-ID"), true},
		{"m=audio", []byte("v=0\r\nm=audio 5004 RTP/AVP 0"), []byte("m=audio"), true},
		{"long pattern", []byte("INVITE sip:user@example.com SIP/2.0"), []byte("example.com"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesContains(tt.data, tt.substr)
			assert.Equal(t, tt.expected, result)

			// Verify against stdlib
			stdResult := strings.Contains(string(tt.data), string(tt.substr))
			assert.Equal(t, stdResult, result, "Result differs from strings.Contains")
		})
	}
}

func TestBytesHasPrefix(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		prefix   []byte
		expected bool
	}{
		{"has prefix", []byte("INVITE sip:"), []byte("INVITE"), true},
		{"no prefix", []byte("BYE sip:"), []byte("INVITE"), false},
		{"exact match", []byte("ACK"), []byte("ACK"), true},
		{"empty prefix", []byte("test"), []byte(""), true},
		{"prefix longer", []byte("hi"), []byte("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesHasPrefix(tt.data, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBytesHasPrefixString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		prefix   string
		expected bool
	}{
		{"INVITE", []byte("INVITE sip:user@host"), "INVITE", true},
		{"BYE", []byte("BYE sip:user@host"), "BYE", true},
		{"no match", []byte("REGISTER"), "INVITE", false},
		{"SIP/2.0", []byte("SIP/2.0 200 OK"), "SIP/2.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesHasPrefixString(tt.data, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBytesToString(t *testing.T) {
	data := []byte("hello world")
	str := BytesToString(data)
	assert.Equal(t, "hello world", str)
	assert.Equal(t, len(data), len(str))
}

func TestStringToBytes(t *testing.T) {
	str := "hello world"
	data := StringToBytes(str)
	assert.Equal(t, []byte(str), data)
	assert.Equal(t, len(str), len(data))
}

func TestIntToBytes(t *testing.T) {
	tests := []struct {
		name     string
		n        int
		expected string
	}{
		{"zero", 0, "0"},
		{"positive", 123, "123"},
		{"negative", -456, "-456"},
		{"large", 999999, "999999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 32)
			result := IntToBytes(buf, tt.n)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestStringInterner(t *testing.T) {
	interner := &StringInterner{}

	s1 := interner.Intern("call-id")
	s2 := interner.Intern("call-id")

	// Should return same pointer
	assert.Equal(t, s1, s2)

	// Test with different strings
	s3 := interner.Intern("from")
	assert.NotEqual(t, s1, s3)
}

func TestStringInterner_Bytes(t *testing.T) {
	interner := &StringInterner{}

	b1 := []byte("call-id")
	s1 := interner.InternBytes(b1)

	b2 := []byte("call-id")
	s2 := interner.InternBytes(b2)

	assert.Equal(t, s1, s2)
}

func TestGetInterner(t *testing.T) {
	interner := GetInterner()
	require.NotNil(t, interner)

	// Common headers should be pre-populated
	s1 := interner.Intern("call-id")
	assert.Equal(t, "call-id", s1)
}

func TestParseIntFast(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
		valid    bool
	}{
		{"zero", []byte("0"), 0, true},
		{"positive", []byte("123"), 123, true},
		{"negative", []byte("-456"), -456, true},
		{"with plus", []byte("+789"), 789, true},
		{"empty", []byte(""), 0, false},
		{"invalid", []byte("abc"), 0, false},
		{"mixed", []byte("12a3"), 0, false},
		{"large", []byte("65536"), 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, valid := ParseIntFast(tt.input)
			assert.Equal(t, tt.valid, valid)
			if valid {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"no space", []byte("hello"), []byte("hello")},
		{"leading", []byte("  hello"), []byte("hello")},
		{"trailing", []byte("hello  "), []byte("hello")},
		{"both", []byte("  hello  "), []byte("hello")},
		{"tabs", []byte("\t\thello\t\t"), []byte("hello")},
		{"newlines", []byte("\nhello\n"), []byte("hello")},
		{"mixed", []byte(" \t\nhello\n\t "), []byte("hello")},
		{"all space", []byte("   "), []byte("")},
		{"empty", []byte(""), []byte("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimSpace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal", []byte("test"), []byte("test"), true},
		{"not equal", []byte("test"), []byte("fest"), false},
		{"different length", []byte("test"), []byte("testing"), false},
		{"empty", []byte(""), []byte(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesEqual(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBytesEqualString(t *testing.T) {
	tests := []struct {
		name     string
		b        []byte
		s        string
		expected bool
	}{
		{"equal", []byte("test"), "test", true},
		{"not equal", []byte("test"), "fest", false},
		{"different length", []byte("test"), "testing", false},
		{"SIP method", []byte("INVITE"), "INVITE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesEqualString(tt.b, tt.s)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"uppercase", []byte("HELLO"), []byte("hello")},
		{"mixed", []byte("HeLLo"), []byte("hello")},
		{"already lower", []byte("hello"), []byte("hello")},
		{"with numbers", []byte("Test123"), []byte("test123")},
		{"SIP header", []byte("Call-ID"), []byte("call-id")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy since ToLower modifies in place
			input := make([]byte, len(tt.input))
			copy(input, tt.input)

			ToLower(input)
			assert.Equal(t, tt.expected, input)
		})
	}
}

func TestToLowerCopy(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{"uppercase", []byte("HELLO"), []byte("hello")},
		{"mixed", []byte("HeLLo"), []byte("hello")},
		{"already lower", []byte("hello"), []byte("hello")},
		{"SIP header", []byte("Call-ID"), []byte("call-id")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, 0, len(tt.input))
			result := ToLowerCopy(dst, tt.input)
			assert.Equal(t, tt.expected, result)

			// Verify original is unchanged
			assert.Equal(t, tt.input, tt.input)
		})
	}
}

func TestIndexByte(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		c        byte
		expected int
	}{
		{"found", []byte("hello:world"), ':', 5},
		{"not found", []byte("hello"), 'x', -1},
		{"first char", []byte("hello"), 'h', 0},
		{"last char", []byte("hello"), 'o', 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IndexByte(tt.data, tt.c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplitN(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		delim    byte
		n        int
		expected [][]byte
	}{
		{
			"simple split",
			[]byte("a:b:c"),
			':',
			3,
			[][]byte{[]byte("a"), []byte("b"), []byte("c")},
		},
		{
			"limit split",
			[]byte("a:b:c:d"),
			':',
			2,
			[][]byte{[]byte("a"), []byte("b:c:d")},
		},
		{
			"no delimiter",
			[]byte("hello"),
			':',
			2,
			[][]byte{[]byte("hello")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitN(tt.data, tt.delim, tt.n)
			require.Equal(t, len(tt.expected), len(result))
			for i := range result {
				assert.Equal(t, tt.expected[i], result[i])
			}
		})
	}
}

// Benchmarks

func BenchmarkBytesContains(b *testing.B) {
	data := []byte("INVITE sip:user@example.com SIP/2.0\r\nCall-ID: abc123@host\r\n")
	substr := []byte("Call-ID")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesContains(data, substr)
	}
}

func BenchmarkStringsContains(b *testing.B) {
	data := "INVITE sip:user@example.com SIP/2.0\r\nCall-ID: abc123@host\r\n"
	substr := "Call-ID"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = strings.Contains(data, substr)
	}
}

func BenchmarkBytesHasPrefix(b *testing.B) {
	data := []byte("INVITE sip:user@host")
	prefix := []byte("INVITE")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesHasPrefix(data, prefix)
	}
}

func BenchmarkStringsHasPrefix(b *testing.B) {
	data := "INVITE sip:user@host"
	prefix := "INVITE"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = strings.HasPrefix(data, prefix)
	}
}

func BenchmarkStringInterner(b *testing.B) {
	interner := GetInterner()
	headers := []string{"call-id", "from", "to", "via", "contact"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = interner.Intern(headers[i%len(headers)])
	}
}

func BenchmarkParseIntFast(b *testing.B) {
	data := []byte("12345")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ParseIntFast(data)
	}
}

func BenchmarkTrimSpace(b *testing.B) {
	data := []byte("  hello world  ")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = TrimSpace(data)
	}
}

func BenchmarkBytesToString(b *testing.B) {
	data := []byte("hello world test string for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = BytesToString(data)
	}
}

func BenchmarkStandardBytesToString(b *testing.B) {
	data := []byte("hello world test string for benchmarking")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = string(data)
	}
}
