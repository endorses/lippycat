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

// TestRTPRejectsDNSPort tests that DNS traffic on port 53 is not misdetected as RTP
func TestRTPRejectsDNSPort(t *testing.T) {
	rtpSig := NewRTPSignature()

	// DNS response that could accidentally match RTP header pattern:
	// - First byte 0x94 has version bits = 10 (matches RTP version 2)
	// - Second byte 0x89 has payload type 9 (G.722, valid static type)
	// This is a real scenario where DNS transaction IDs can look like RTP headers
	dnsPayload := []byte{
		0x94, 0x89, // DNS transaction ID + flags that match RTP V=2, PT=9
		0x84, 0x13, // More DNS flags/counts
		0x00, 0x01, 0x00, 0x00, // DNS counts
		0x00, 0x08, 0x00, 0x01, // More DNS data
		0x03, 0x6e, 0x65, 0x74, // "net" in DNS name
	}

	tests := []struct {
		name    string
		srcPort uint16
		dstPort uint16
	}{
		{"DNS server source", 53, 17108},  // Response from DNS server
		{"DNS server dest", 45788, 53},    // Query to DNS server
		{"DNS both ports", 53, 53},        // Unusual but possible
		{"NTP server source", 123, 32000}, // NTP response
		{"DHCP server", 67, 68},           // DHCP traffic
		{"SNMP", 161, 49000},              // SNMP
		{"SNMP trap", 50000, 162},         // SNMP trap
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload:   dnsPayload,
				Transport: "UDP",
				SrcPort:   tt.srcPort,
				DstPort:   tt.dstPort,
			}

			result := rtpSig.Detect(ctx)
			assert.Nil(t, result, "Should NOT detect RTP on well-known UDP port")
		})
	}
}

// TestRTPAllowsLegitimateTraffic ensures the UDP port filter doesn't break real RTP
func TestRTPAllowsLegitimateTraffic(t *testing.T) {
	rtpSig := NewRTPSignature()

	// Valid RTP packet with static payload type 0 (PCMU)
	rtpPayload := []byte{
		0x80,       // V=2, P=0, X=0, CC=0
		0x00,       // M=0, PT=0 (PCMU)
		0x12, 0x34, // Sequence number
		0x00, 0x00, 0x00, 0x10, // Timestamp
		0x12, 0x34, 0x56, 0x78, // SSRC
		// Payload data
		0xFF, 0xFF, 0xFF, 0xFF,
	}

	// RTP on typical port range should still be detected
	ctx := &signatures.DetectionContext{
		Payload:   rtpPayload,
		Transport: "UDP",
		SrcPort:   16384, // IANA RTP range
		DstPort:   5004,
	}

	result := rtpSig.Detect(ctx)
	assert.NotNil(t, result, "Should detect RTP on typical RTP ports")
	assert.Equal(t, "RTP", result.Protocol)
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
