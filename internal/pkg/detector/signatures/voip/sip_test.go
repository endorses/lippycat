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

// TestSIPSignature_CaseInsensitiveHeaders verifies that SIP header parsing
// is case-insensitive as required by RFC 3261 Section 7.3.1
func TestSIPSignature_CaseInsensitiveHeaders(t *testing.T) {
	sig := NewSIPSignature()

	tests := []struct {
		name           string
		payload        string
		expectedCallID string
		expectedFrom   string
		expectedTo     string
	}{
		{
			name: "Standard case (Call-ID)",
			payload: `INVITE sip:bob@example.com SIP/2.0
From: Alice <sip:alice@example.com>
To: Bob <sip:bob@example.com>
Call-ID: standard-case-123

`,
			expectedCallID: "standard-case-123",
			expectedFrom:   "Alice <sip:alice@example.com>",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
		{
			name: "Lowercase headers (call-id, from, to)",
			payload: `INVITE sip:bob@example.com SIP/2.0
from: Alice <sip:alice@example.com>
to: Bob <sip:bob@example.com>
call-id: lowercase-456

`,
			expectedCallID: "lowercase-456",
			expectedFrom:   "Alice <sip:alice@example.com>",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
		{
			name: "Uppercase headers (CALL-ID, FROM, TO)",
			payload: `INVITE sip:bob@example.com SIP/2.0
FROM: Alice <sip:alice@example.com>
TO: Bob <sip:bob@example.com>
CALL-ID: uppercase-789

`,
			expectedCallID: "uppercase-789",
			expectedFrom:   "Alice <sip:alice@example.com>",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
		{
			name: "Mixed case headers (Call-Id, call-ID)",
			payload: `INVITE sip:bob@example.com SIP/2.0
FrOm: Alice <sip:alice@example.com>
tO: Bob <sip:bob@example.com>
Call-Id: mixedcase-abc

`,
			expectedCallID: "mixedcase-abc",
			expectedFrom:   "Alice <sip:alice@example.com>",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
		{
			name: "Compact form headers (i, f, t)",
			payload: `INVITE sip:bob@example.com SIP/2.0
f: Alice <sip:alice@example.com>
t: Bob <sip:bob@example.com>
i: compact-form-xyz

`,
			expectedCallID: "compact-form-xyz",
			expectedFrom:   "Alice <sip:alice@example.com>",
			expectedTo:     "Bob <sip:bob@example.com>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := sig.extractMetadata(tt.payload)

			assert.Equal(t, tt.expectedCallID, metadata["call_id"],
				"Call-ID should be extracted regardless of header case")
			assert.Equal(t, tt.expectedFrom, metadata["from"],
				"From should be extracted regardless of header case")
			assert.Equal(t, tt.expectedTo, metadata["to"],
				"To should be extracted regardless of header case")
		})
	}
}
