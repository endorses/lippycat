//go:build cli || hunter || tap || tui || all

package tls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecognizesPayloadMatchesFullTLSParser(t *testing.T) {
	p := NewParser()
	payload := clientHelloFixture(t)
	for end := 0; end <= len(payload); end++ {
		require.Equal(t, p.ParsePayload(payload[:end]) != nil, p.RecognizesPayload(payload[:end]), "prefix %d", end)
	}
	for offset := range payload {
		for _, value := range []byte{0, 1, 3, 4, 22, 255} {
			mutated := append([]byte(nil), payload...)
			mutated[offset] = value
			require.Equal(t, p.ParsePayload(mutated) != nil, p.RecognizesPayload(mutated), "offset %d value %d", offset, value)
		}
	}
}
