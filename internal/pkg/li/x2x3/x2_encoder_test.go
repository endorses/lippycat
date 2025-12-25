package x2x3

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestNewX2Encoder(t *testing.T) {
	encoder := NewX2Encoder()
	assert.NotNil(t, encoder)
	assert.NotNil(t, encoder.attrBuilder)
	assert.Equal(t, uint32(0), encoder.GetSequenceNumber())
}

func TestX2Encoder_EncodeIRI_SessionBegin(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "INVITE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify PDU header
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, xid, pdu.Header.XID)
	assert.Equal(t, uint16(Version), pdu.Header.Version)

	// Verify IRI type attribute
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRISessionBegin, iriType)

	// Verify SIP attributes
	callIDAttr := FindAttribute(pdu.Attributes, AttrSIPCallID)
	require.NotNil(t, callIDAttr)
	assert.Equal(t, "abc123@192.168.1.100", string(callIDAttr.Value))

	fromAttr := FindAttribute(pdu.Attributes, AttrSIPFromURI)
	require.NotNil(t, fromAttr)
	assert.Equal(t, "alice@example.com", string(fromAttr.Value))

	toAttr := FindAttribute(pdu.Attributes, AttrSIPToURI)
	require.NotNil(t, toAttr)
	assert.Equal(t, "bob@example.com", string(toAttr.Value))

	methodAttr := FindAttribute(pdu.Attributes, AttrSIPMethod)
	require.NotNil(t, methodAttr)
	assert.Equal(t, "INVITE", string(methodAttr.Value))

	// Verify sequence number incremented
	assert.Equal(t, uint32(1), encoder.GetSequenceNumber())
}

func TestX2Encoder_EncodeIRI_SessionAnswer(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Status:  200,
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
			ToTag:   "tag-to-456", // Presence of ToTag indicates established dialog
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify IRI type is SessionAnswer
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRISessionAnswer, iriType)

	// Verify response code
	respCodeAttr := FindAttribute(pdu.Attributes, AttrSIPResponseCode)
	require.NotNil(t, respCodeAttr)
	respCode := uint16(respCodeAttr.Value[0])<<8 | uint16(respCodeAttr.Value[1])
	assert.Equal(t, uint16(200), respCode)
}

func TestX2Encoder_EncodeIRI_SessionEnd(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "BYE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
			ToTag:   "tag-to-456",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify IRI type is SessionEnd
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRISessionEnd, iriType)
}

func TestX2Encoder_EncodeIRI_SessionAttempt_Cancel(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "CANCEL",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify IRI type is SessionAttempt
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRISessionAttempt, iriType)
}

func TestX2Encoder_EncodeIRI_SessionAttempt_Failure(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Status:  486, // Busy Here
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify IRI type is SessionAttempt
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRISessionAttempt, iriType)

	// Verify response code
	respCodeAttr := FindAttribute(pdu.Attributes, AttrSIPResponseCode)
	require.NotNil(t, respCodeAttr)
	respCode := uint16(respCodeAttr.Value[0])<<8 | uint16(respCodeAttr.Value[1])
	assert.Equal(t, uint16(486), respCode)
}

func TestX2Encoder_EncodeIRI_Registration(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.1",
		SrcPort:   "5060",
		DstPort:   "5060",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "reg123@192.168.1.100",
			Method: "REGISTER",
			From:   "alice@example.com",
			To:     "alice@example.com",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify IRI type is Registration
	iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
	require.NotNil(t, iriTypeAttr)
	iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
	assert.Equal(t, IRIRegistration, iriType)
}

func TestX2Encoder_EncodeIRI_NoVoIPData(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "TCP",
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	assert.ErrorIs(t, err, ErrNotVoIP)
	assert.Nil(t, pdu)
}

func TestX2Encoder_EncodeIRI_NoCallID(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			Method: "INVITE",
			// Missing CallID
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	assert.ErrorIs(t, err, ErrNoCallID)
	assert.Nil(t, pdu)
}

func TestX2Encoder_EncodeIRI_ProvisionalResponse(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	// 180 Ringing should not generate an IRI
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "abc123@192.168.1.100",
			Status: 180, // Ringing
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	assert.NoError(t, err)
	assert.Nil(t, pdu) // No IRI for provisional responses
}

func TestX2Encoder_CorrelationID_Deterministic(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	callID := "test-call-id@192.168.1.100"

	// Two packets with the same Call-ID should have the same correlation ID
	pkt1 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			CallID: callID,
			Method: "INVITE",
		},
	}

	pkt2 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		VoIPData: &types.VoIPMetadata{
			CallID: callID,
			Status: 200,
			ToTag:  "tag-to-456",
		},
	}

	pdu1, err := encoder.EncodeIRI(pkt1, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu1)

	pdu2, err := encoder.EncodeIRI(pkt2, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu2)

	// Same Call-ID = same correlation ID
	assert.Equal(t, pdu1.Header.CorrelationID, pdu2.Header.CorrelationID)
}

func TestX2Encoder_SequenceNumber_Monotonic(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			CallID: "test@192.168.1.100",
			Method: "INVITE",
		},
	}

	// Encode multiple IRIs
	for i := 1; i <= 10; i++ {
		_, err := encoder.EncodeIRI(pkt, xid)
		require.NoError(t, err)
		assert.Equal(t, uint32(i), encoder.GetSequenceNumber())
	}
}

func TestX2Encoder_NetworkAttributes_IPv4(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5061",
		VoIPData: &types.VoIPMetadata{
			CallID: "test@192.168.1.100",
			Method: "INVITE",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify source IPv4
	srcIPAttr := FindAttribute(pdu.Attributes, AttrSourceIPv4)
	require.NotNil(t, srcIPAttr)
	assert.Equal(t, []byte{192, 168, 1, 100}, srcIPAttr.Value)

	// Verify destination IPv4
	dstIPAttr := FindAttribute(pdu.Attributes, AttrDestIPv4)
	require.NotNil(t, dstIPAttr)
	assert.Equal(t, []byte{192, 168, 1, 200}, dstIPAttr.Value)

	// Verify source port
	srcPortAttr := FindAttribute(pdu.Attributes, AttrSourcePort)
	require.NotNil(t, srcPortAttr)
	assert.Equal(t, []byte{0x13, 0xC4}, srcPortAttr.Value) // 5060 = 0x13C4

	// Verify destination port
	dstPortAttr := FindAttribute(pdu.Attributes, AttrDestPort)
	require.NotNil(t, dstPortAttr)
	assert.Equal(t, []byte{0x13, 0xC5}, dstPortAttr.Value) // 5061 = 0x13C5
}

func TestX2Encoder_NetworkAttributes_IPv6(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "2001:db8::1",
		DstIP:     "2001:db8::2",
		SrcPort:   "5060",
		DstPort:   "5060",
		VoIPData: &types.VoIPMetadata{
			CallID: "test@example.com",
			Method: "INVITE",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify source IPv6
	srcIPAttr := FindAttribute(pdu.Attributes, AttrSourceIPv6)
	require.NotNil(t, srcIPAttr)
	assert.Equal(t, 16, len(srcIPAttr.Value))

	// Verify destination IPv6
	dstIPAttr := FindAttribute(pdu.Attributes, AttrDestIPv6)
	require.NotNil(t, dstIPAttr)
	assert.Equal(t, 16, len(dstIPAttr.Value))
}

func TestX2Encoder_PDU_Serialization(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "5060",
		DstPort:   "5060",
		VoIPData: &types.VoIPMetadata{
			CallID: "abc123@192.168.1.100",
			Method: "INVITE",
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Serialize to binary
	data, err := pdu.MarshalBinary()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Deserialize and verify
	decoded := &PDU{}
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, pdu.Header.Type, decoded.Header.Type)
	assert.Equal(t, pdu.Header.XID, decoded.Header.XID)
	assert.Equal(t, pdu.Header.CorrelationID, decoded.Header.CorrelationID)
	assert.Equal(t, len(pdu.Attributes), len(decoded.Attributes))
}

func TestX2Encoder_DirectMethods(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			CallID: "test@192.168.1.100",
			Method: "INVITE",
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	t.Run("EncodeSessionBegin", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionBegin(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)

		iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
		require.NotNil(t, iriTypeAttr)
		iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
		assert.Equal(t, IRISessionBegin, iriType)
	})

	t.Run("EncodeSessionAnswer", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionAnswer(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)

		iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
		require.NotNil(t, iriTypeAttr)
		iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
		assert.Equal(t, IRISessionAnswer, iriType)
	})

	t.Run("EncodeSessionEnd", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionEnd(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)

		iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
		require.NotNil(t, iriTypeAttr)
		iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
		assert.Equal(t, IRISessionEnd, iriType)
	})

	t.Run("EncodeSessionAttempt", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionAttempt(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)

		iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
		require.NotNil(t, iriTypeAttr)
		iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
		assert.Equal(t, IRISessionAttempt, iriType)
	})

	t.Run("EncodeRegistration", func(t *testing.T) {
		pdu, err := encoder.EncodeRegistration(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)

		iriTypeAttr := FindAttribute(pdu.Attributes, AttrIRIType)
		require.NotNil(t, iriTypeAttr)
		iriType := IRIType(uint16(iriTypeAttr.Value[0])<<8 | uint16(iriTypeAttr.Value[1]))
		assert.Equal(t, IRIRegistration, iriType)
	})
}

func TestIRIType_String(t *testing.T) {
	tests := []struct {
		iriType  IRIType
		expected string
	}{
		{IRISessionBegin, "SessionBegin"},
		{IRISessionAnswer, "SessionAnswer"},
		{IRISessionEnd, "SessionEnd"},
		{IRISessionAttempt, "SessionAttempt"},
		{IRIRegistration, "Registration"},
		{IRIRegistrationEnd, "RegistrationEnd"},
		{IRIType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.iriType.String())
		})
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input    string
		expected uint16
		ok       bool
	}{
		{"5060", 5060, true},
		{"80", 80, true},
		{"65535", 65535, true},
		{"0", 0, false},     // 0 is not a valid port
		{"", 0, false},      // empty string
		{"abc", 0, false},   // non-numeric
		{"5060a", 0, false}, // mixed
		{"99999", 0, false}, // overflow
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			port, ok := parsePort(tt.input)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.expected, port)
			}
		})
	}
}
