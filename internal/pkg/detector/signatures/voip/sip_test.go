package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSIPSignature_Detect(t *testing.T) {
	sig := NewSIPSignature()

	tests := []struct {
		name         string
		payload      string
		shouldDetect bool
		confidence   float64
	}{
		{
			name: "SIP INVITE request",
			payload: `INVITE sip:robb@example.com SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060
From: Alicent <sip:alicent@example.com>
To: Robb <sip:robb@example.com>
Call-ID: 12345@example.com
CSeq: 1 INVITE

`,
			shouldDetect: true,
			confidence:   0.8,
		},
		{
			name: "SIP 200 OK response",
			payload: `SIP/2.0 200 OK
Via: SIP/2.0/UDP client.example.com:5060
From: Alicent <sip:alicent@example.com>
To: Robb <sip:robb@example.com>
Call-ID: 12345@example.com
CSeq: 1 INVITE

`,
			shouldDetect: true,
			confidence:   0.8,
		},
		{
			name:         "Not SIP - random text",
			payload:      "This is not a SIP message",
			shouldDetect: false,
		},
		{
			name:         "Too short",
			payload:      "INV",
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload:   []byte(tt.payload),
				Transport: "UDP",
				SrcPort:   5060,
				DstPort:   5060,
			}

			result := sig.Detect(ctx)

			if tt.shouldDetect {
				require.NotNil(t, result, "Expected SIP to be detected")
				assert.Equal(t, "SIP", result.Protocol)
				assert.GreaterOrEqual(t, result.Confidence, tt.confidence)
			} else {
				assert.Nil(t, result, "Expected SIP not to be detected")
			}
		})
	}
}

func TestSIPSignature_ExtractMetadata(t *testing.T) {
	sig := NewSIPSignature()

	payload := `INVITE sip:robb@example.com SIP/2.0
From: Alicent <sip:alicent@example.com>
To: Robb <sip:robb@example.com>
Call-ID: abc123@example.com

`

	metadata := sig.extractMetadata(payload)

	assert.Equal(t, "request", metadata["type"])
	assert.Equal(t, "INVITE", metadata["method"])
	assert.Equal(t, "alicent", metadata["from_user"])
	assert.Contains(t, metadata, "headers")
}
