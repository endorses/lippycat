//go:build hunter || tap || all

package protocolmeta

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func hintTLSHello() []byte {
	payload := make([]byte, 52)
	copy(payload, []byte{22, 3, 3, 0, 47, 1, 0, 0, 43, 3, 3})
	copy(payload[44:], []byte{0, 2, 0x13, 1, 1, 0, 0, 0})
	return payload
}

func TestReassemblyHintMatchesDiscardedFullMetadata(t *testing.T) {
	payloads := [][]byte{
		nil, []byte("random payload"), hintTLSHello(),
		[]byte("GET /search?q=cat HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"),
		[]byte("HTTP/1.1 999 Invalid\r\n\r\n"),
		[]byte("INVALID / HTTP/1.1\r\n\r\n"),
		[]byte("GET /" + strings.Repeat("x", 8192) + " HTTP/1.1\r\n\r\n"),
	}
	for _, payload := range payloads {
		for end := 0; end <= len(payload); end++ {
			packet := testTCPPacket(t, payload[:end])
			full := Enrich(packet, nil, true)
			wantHint := ""
			if full.Http != nil {
				wantHint = "http"
			} else if full.Tls != nil {
				wantHint = "tls"
			}
			full.Http, full.Tls = nil, nil
			actual, hint := EnrichForReassembly(packet)
			require.Equal(t, full, actual)
			require.Equal(t, wantHint, hint)
		}
	}
}

func BenchmarkReassemblyHintTLS(b *testing.B) {
	// Packet construction is outside the measured loops.
	packet := testTCPPacket(b, hintTLSHello())
	for _, full := range []bool{true, false} {
		b.Run(fmt.Sprintf("full=%t", full), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if full {
					Enrich(packet, nil, false)
				} else {
					EnrichForReassembly(packet)
				}
			}
		})
	}
}
