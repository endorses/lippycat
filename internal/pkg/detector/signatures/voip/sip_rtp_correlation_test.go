package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
)

// TestSIPRTPCorrelation tests that SIP extracts media ports and RTP uses them
func TestSIPRTPCorrelation(t *testing.T) {
	sipSig := NewSIPSignature()
	rtpSig := NewRTPSignature()

	// SIP INVITE with SDP containing media port 49170
	sipPayload := `INVITE sip:robb@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776
From: Alicent <sip:alicent@atlanta.com>;tag=1928301774
To: Robb <sip:robb@biloxi.com>
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alicent@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alicent 2890844526 2890844526 IN IP4 pc33.atlanta.com
s=Session SDP
c=IN IP4 pc33.atlanta.com
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
`

	// Create flow context
	flowCtx := &signatures.FlowContext{
		FlowID:    "test-flow",
		Protocols: make([]string, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Detect SIP (should extract media port 49170)
	sipCtx := &signatures.DetectionContext{
		Payload:   []byte(sipPayload),
		Transport: "UDP",
		SrcPort:   5060,
		DstPort:   5060,
		Flow:      flowCtx,
	}

	sipResult := sipSig.Detect(sipCtx)
	assert.NotNil(t, sipResult, "SIP should be detected")
	assert.Equal(t, "SIP", sipResult.Protocol)

	// Check that media ports were extracted
	if mediaPorts, ok := sipResult.Metadata["media_ports"].([]uint16); ok {
		assert.Contains(t, mediaPorts, uint16(49170), "Should extract port 49170")
	} else {
		t.Fatal("media_ports not found in metadata")
	}

	// Check that flow state was updated
	assert.NotNil(t, flowCtx.State, "Flow state should be set")
	if sipState, ok := flowCtx.State.(*SIPFlowState); ok {
		assert.Contains(t, sipState.MediaPorts, uint16(49170))
		assert.Equal(t, "a84b4c76e66710@pc33.atlanta.com", sipState.CallID)
	} else {
		t.Fatal("Flow state is not SIPFlowState")
	}

	// Now detect RTP on port 49170 (should have very high confidence)
	rtpPayload := []byte{
		0x80,       // V=2, P=0, X=0, CC=0
		0x00,       // M=0, PT=0 (PCMU)
		0x12, 0x34, // Sequence number
		0x00, 0x00, 0x00, 0x10, // Timestamp
		0x12, 0x34, 0x56, 0x78, // SSRC
		// Payload data
		0xFF, 0xFF, 0xFF, 0xFF,
	}

	rtpCtx := &signatures.DetectionContext{
		Payload:   rtpPayload,
		Transport: "UDP",
		SrcPort:   49170, // Port negotiated in SIP
		DstPort:   5004,
		Flow:      flowCtx, // Same flow context
	}

	rtpResult := rtpSig.Detect(rtpCtx)
	assert.NotNil(t, rtpResult, "RTP should be detected")
	assert.Equal(t, "RTP", rtpResult.Protocol)

	// Should have very high confidence because port was negotiated in SIP
	assert.Equal(t, signatures.ConfidenceVeryHigh, rtpResult.Confidence,
		"RTP should have very high confidence when correlated with SIP")

	// Check that RTP metadata includes SIP correlation
	assert.True(t, rtpResult.Metadata["sip_correlated"].(bool))
	assert.Equal(t, "a84b4c76e66710@pc33.atlanta.com", rtpResult.Metadata["call_id"])
}

// TestSIPSDPExtraction tests SDP port extraction
func TestSIPSDPExtraction(t *testing.T) {
	sig := NewSIPSignature()

	tests := []struct {
		name          string
		payload       string
		expectedPorts []uint16
	}{
		{
			name: "Single audio port",
			payload: `INVITE sip:user@example.com SIP/2.0

v=0
o=- 123 456 IN IP4 10.0.0.1
s=Test
m=audio 12345 RTP/AVP 0
`,
			expectedPorts: []uint16{12345},
		},
		{
			name: "Audio and video ports",
			payload: `INVITE sip:user@example.com SIP/2.0

v=0
m=audio 10000 RTP/AVP 0
m=video 10002 RTP/AVP 96
`,
			expectedPorts: []uint16{10000, 10002},
		},
		{
			name: "No SDP",
			payload: `REGISTER sip:server.com SIP/2.0
From: <sip:user@example.com>
To: <sip:user@example.com>
`,
			expectedPorts: []uint16{},
		},
		{
			name: "Invalid port",
			payload: `INVITE sip:user@example.com SIP/2.0

m=audio 70000 RTP/AVP 0
`,
			expectedPorts: []uint16{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := sig.extractSDPMediaPorts(tt.payload)
			assert.Equal(t, tt.expectedPorts, ports)
		})
	}
}
