package sip

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseExtensionMethodTokens(t *testing.T) {
	for _, method := range []string{"SERVICE", "X-CUSTOM", "Extension_1", "!extension"} {
		raw := []byte(method + " sip:bob@example.test SIP/2.0\r\nCall-ID: extension\r\nCSeq: 1 " + method + "\r\nContent-Length: 0\r\n\r\n")
		ev, err := Parse(raw, ParseOptions{})
		require.NoError(t, err)
		require.Equal(t, method, ev.Method)
		require.Equal(t, strings.ToUpper(method), ev.CSeqMethod)
		require.Equal(t, "extension", ev.CallID)
	}
	for _, method := range []string{"", "X/CUSTOM", "X:CUSTOM", "X(CUSTOM)", "X\x00CUSTOM", "X CUSTOM"} {
		require.False(t, IsRequestMethod(method))
	}
}
