package smsflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasTrailingPayloadHonorsBinaryExtent(t *testing.T) {
	// A body can contain both separator bytes and terminal-looking control bytes.
	body := []byte{0, 0xff, '\r', '\n', '\r', '\n', 0}
	frame := append([]byte("MESSAGE sip:b@example.test SIP/2.0\r\nContent-Length: 7\r\n\r\n"), body...)
	for _, tc := range []struct {
		name     string
		tail     []byte
		trailing bool
	}{
		{"exact", nil, false}, {"CRLF", []byte("\r\n\r\n"), false}, {"other message", []byte("MESSAGE sip:x@example.test SIP/2.0\r\n\r\nsecret"), true}, {"binary", []byte{0}, true}, {"CRLF then message", []byte("\r\nMESSAGE sip:x@example.test SIP/2.0\r\n\r\n"), true}, {"incomplete CRLF", []byte("\r"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := append(append([]byte(nil), frame...), tc.tail...)
			require.Equal(t, tc.trailing, HasTrailingPayload(payload, len(body)))
		})
	}
	require.False(t, HasTrailingPayload(nil, 0))
	require.False(t, HasTrailingPayload([]byte("unavailable headers"), 0))
	require.False(t, HasTrailingPayload(frame, len(body)+1), "incomplete raw bytes cannot invalidate supplied decoding")
	require.False(t, HasTrailingPayload(frame, -1))
	require.False(t, HasTrailingPayload([]byte("MESSAGE sip:b SIP/2.0\nContent-Length: 0\n\n\r\n"), 0))
	require.True(t, HasTrailingPayload([]byte("MESSAGE sip:b SIP/2.0\nContent-Length: 0\n\nextra"), 0))
}
