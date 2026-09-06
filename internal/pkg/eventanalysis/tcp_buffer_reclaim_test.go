package eventanalysis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplicationBufferReclaimsConsumedPrefixBetweenCallbacks(t *testing.T) {
	s := &applicationStream{}
	s.appendBuffer([]byte("abcdefgh"))
	backing := &s.buffer[0]
	frame := s.buffer[:6]
	s.consume(6)
	require.Equal(t, "abcdef", string(frame), "consume must preserve parser aliases")
	require.Equal(t, "gh", string(s.buffer))
	s.appendBuffer([]byte("ijklmn"))
	require.Equal(t, "ghijklmn", string(s.buffer))
	require.Same(t, backing, &s.buffer[0], "next callback reuses consumed prefix")
	s.consume(len(s.buffer))
	s.appendBuffer([]byte("opqrstuv"))
	require.Equal(t, "opqrstuv", string(s.buffer))
	require.Same(t, backing, &s.buffer[0])
}

func BenchmarkApplicationBufferFragmentedFrames(b *testing.B) {
	s := &applicationStream{}
	chunk := make([]byte, 1460)
	b.ReportAllocs()
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		s.appendBuffer(chunk)
		for len(s.buffer) >= 4096 {
			s.consume(4096)
		}
	}
}
