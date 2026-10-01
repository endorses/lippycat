package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/require"
)

func TestSIPSignatureDetectsExtensionMethods(t *testing.T) {
	signature := NewSIPSignature()
	for _, method := range []string{"SERVICE", "X-EXTENSION", "!extension"} {
		payload := []byte(method + " sip:bob@example.test SIP/2.0\r\nCall-ID: extension\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:bob@example.test>\r\nContent-Length: 0\r\n\r\n")
		result := signature.Detect(&signatures.DetectionContext{Payload: payload, Transport: "TCP", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 5060, DstPort: 5060})
		require.NotNil(t, result)
		require.Equal(t, "SIP", result.Protocol)
		require.Equal(t, method, result.Metadata["method"])
		require.Equal(t, method, result.Metadata["matched_method"])
		require.Equal(t, "extension", result.Metadata["call_id"])
	}
	for _, payload := range []string{"X/CUSTOM sip:bob@example.test SIP/2.0\r\n\r\n", "SERVICE sip:bob@example.test HTTP/1.1\r\n\r\n", "SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 6\r\n\r\nx"} {
		require.Nil(t, signature.Detect(&signatures.DetectionContext{Payload: []byte(payload)}))
	}
}
