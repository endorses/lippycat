package x2x3

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestNewX2Encoder(t *testing.T) {
	encoder := NewX2Encoder()
	assert.NotNil(t, encoder)
	assert.NotNil(t, encoder.attrBuilder)
	assert.Equal(t, uint32(0), encoder.GetSequenceNumber())
}

func TestFindSIPStartPrefersFirstValidMessage(t *testing.T) {
	response := []byte("SIP/2.0 200 OK\r\nSubject: INVITE sip:wrong@example.test SIP/2.0\r\nContent-Length: 7\r\n\r\nINVITE ")
	request := []byte("INVITE sip:bob@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	for _, tc := range []struct {
		name string
		data []byte
		want int
	}{
		{"response with later request token", response, 0},
		{"binary frame prefix", append([]byte{0x45, 0x00, 0x13, 0xc4}, response...), 4},
		{"binary frame prefix containing LF", append([]byte{0x45, 0x00, '\n', 0xc4}, response...), 4},
		{"request", request, 0},
		{"request midline rejected", []byte("Subject: " + string(request)), -1},
		{"invalid response code rejected", []byte("SIP/2.0 abc Invalid\r\n\r\n"), -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FindSIPStart(tc.data))
		})
	}

	pkt := &types.PacketDisplay{RawData: append([]byte{0x45, 0x00}, response...), VoIPData: &types.VoIPMetadata{CallID: "call", Status: 200}}
	pdu, err := NewX2Encoder().EncodeIRI(pkt, uuid.New())
	require.NoError(t, err)
	require.NotNil(t, pdu)
	assert.Equal(t, response, pdu.Payload)

	pkt.VoIPData.RawSIP = append([]byte(nil), response...)
	pkt.RawData = []byte("INVITE sip:wrong@example.test SIP/2.0\r\n\r\n")
	pdu, err = NewX2Encoder().EncodeIRI(pkt, uuid.New())
	require.NoError(t, err)
	require.NotNil(t, pdu)
	assert.Equal(t, response, pdu.Payload, "RawSIP must take precedence over a fallback scan")

	for _, raw := range [][]byte{
		[]byte("SIP/2.0 200 OK\r\nContent-Length: 7\r\n\r\nINV"),
		[]byte("SIP/2.0 200 OK\r\nContent-Length: bad\r\n\r\nINVITE "),
		[]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n"),
	} {
		pkt.VoIPData.RawSIP = nil
		pkt.RawData = raw
		pdu, err = NewX2Encoder().EncodeIRI(pkt, uuid.New())
		require.ErrorIs(t, err, ErrNoSIPPayload)
		require.Nil(t, pdu)
	}
}

func TestFindSIPStartBoundedUppercaseWithoutNewline(t *testing.T) {
	// RawData may come from an untrusted packet source. A long line of
	// candidate initial letters must not cause a suffix scan per byte.
	raw := append([]byte{0x45, 0x00}, bytes.Repeat([]byte{'A'}, 4*sip.MaxMessageSize)...)
	assert.Equal(t, -1, FindSIPStart(raw))
	assert.Nil(t, FindSIPMessage(raw))
}

func TestX2Encoder_BidirectionalSIPAttributesFollowPacketSender(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()
	for _, tc := range []struct {
		name        string
		payload     []byte
		meta        *types.VoIPMetadata
		srcIP       string
		dstIP       string
		srcPort     string
		dstPort     string
		wantSrcIP   []byte
		wantDstIP   []byte
		wantSrcPort []byte
		wantDstPort []byte
	}{
		{
			name: "request UE to P-CSCF", payload: []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: direction\r\nContent-Length: 0\r\n\r\n"),
			meta:  &types.VoIPMetadata{CallID: "direction", Method: "INVITE"},
			srcIP: "192.0.2.10", dstIP: "198.51.100.20", srcPort: "9202", dstPort: "63781",
			wantSrcIP: []byte{192, 0, 2, 10}, wantDstIP: []byte{198, 51, 100, 20}, wantSrcPort: []byte{0x23, 0xf2}, wantDstPort: []byte{0xf9, 0x25},
		},
		{
			name: "response P-CSCF to UE", payload: []byte("SIP/2.0 200 OK\r\nWarning: 399 proxy INVITE check\r\nCall-ID: direction\r\nContent-Length: 0\r\n\r\n"),
			meta:  &types.VoIPMetadata{CallID: "direction", Status: 200, CSeqMethod: "INVITE"},
			srcIP: "198.51.100.20", dstIP: "192.0.2.10", srcPort: "63781", dstPort: "9202",
			wantSrcIP: []byte{198, 51, 100, 20}, wantDstIP: []byte{192, 0, 2, 10}, wantSrcPort: []byte{0xf9, 0x25}, wantDstPort: []byte{0x23, 0xf2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := &types.PacketDisplay{
				Timestamp: time.Now(), SrcIP: tc.srcIP, DstIP: tc.dstIP, SrcPort: tc.srcPort, DstPort: tc.dstPort,
				VoIPData: tc.meta, RawData: append([]byte{0x45, 0x00}, tc.payload...),
			}
			packet.VoIPData.RawSIP = tc.payload
			pdu, err := encoder.EncodeIRI(packet, xid)
			require.NoError(t, err)
			require.NotNil(t, pdu)
			assert.Equal(t, tc.payload, pdu.Payload)
			for _, attr := range []struct {
				typ  AttributeType
				want []byte
			}{
				{AttrSourceIPv4, tc.wantSrcIP}, {AttrDestIPv4, tc.wantDstIP},
				{AttrSourcePort, tc.wantSrcPort}, {AttrDestPort, tc.wantDstPort},
			} {
				got := FindAttribute(pdu.Attributes, attr.typ)
				require.NotNil(t, got)
				assert.Equal(t, attr.want, got.Value)
			}
		})
	}
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{
			CallID:  "abc123@192.168.1.100",
			Method:  "INVITE",
			From:    "alice@example.com",
			To:      "bob@example.com",
			FromTag: "tag-from-123",
			RawSIP:  []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123@192.168.1.100\r\n\r\n"),
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify PDU header
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, xid, pdu.Header.XID)
	assert.Equal(t, uint16(Version), pdu.Header.Version)

	// SIP is carried via Payload Format 9 (SIP) + the raw SIP payload, NOT via
	// per-header TLV attributes. The MDF derives the IRI type from the payload.
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
	assert.Equal(t, PayloadDirectionUnknown, pdu.Header.PayloadDirection)
	assert.Equal(t, pkt.VoIPData.RawSIP, pdu.Payload)

	// Standard conditional attributes are present (timestamp, seq, 5-tuple).
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrTimestamp))
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrSequenceNumber))
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrSourceIPv4))
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrDestIPv4))
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrSourcePort))
	require.NotNil(t, FindAttribute(pdu.Attributes, AttrDestPort))

	// The first sequence number in an ETSI context is zero.
	assert.Equal(t, uint32(0), encoder.GetSequenceNumber())
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// A 200 OK with a To-tag still produces an X2 SIP PDU; the IRI type
	// (SessionAnswer) and response code are derived by the MDF from the payload.
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// A BYE produces an X2 SIP PDU; SessionEnd is derived by the MDF.
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// A CANCEL produces an X2 SIP PDU; SessionAttempt is derived by the MDF.
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// A 486 failure response produces an X2 SIP PDU; SessionAttempt and the
	// response code are derived by the MDF from the payload.
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// A REGISTER produces an X2 SIP PDU; Registration is derived by the MDF.
	assert.Equal(t, PDUTypeX2, pdu.Header.Type)
	assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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
		RawData:   []byte("OPTIONS sip:test@example.com SIP/2.0\r\n\r\n"),
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

	// 180 Ringing is signaling and must generate an IRI.
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		Protocol:  "SIP",
		RawData:   []byte("SIP/2.0 180 Ringing\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{
			CallID: "abc123@192.168.1.100",
			Status: 180, // Ringing
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	pdu, err := encoder.EncodeIRI(pkt, xid)
	assert.NoError(t, err)
	require.NotNil(t, pdu)
	assert.Equal(t, pkt.RawData, pdu.Payload)
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{
			CallID: callID,
			Method: "INVITE",
		},
	}

	pkt2 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		RawData:   []byte("SIP/2.0 200 OK\r\n\r\n"),
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{
			CallID: "test@192.168.1.100",
			Method: "INVITE",
		},
	}

	// Encode multiple IRIs
	for i := 0; i < 10; i++ {
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
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
		RawData:   []byte("INVITE sip:test@example.com SIP/2.0\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{
			CallID: "test@192.168.1.100",
			Method: "INVITE",
			From:   "alice@example.com",
			To:     "bob@example.com",
		},
	}

	// Each direct method produces an X2 SIP PDU (Payload Format 9). The specific
	// IRI type is derived by the MDF from the raw SIP payload, not a TLV attribute.
	t.Run("EncodeSessionBegin", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionBegin(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)
		assert.Equal(t, PDUTypeX2, pdu.Header.Type)
		assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
	})

	t.Run("EncodeSessionAnswer", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionAnswer(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)
		assert.Equal(t, PDUTypeX2, pdu.Header.Type)
		assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
	})

	t.Run("EncodeSessionEnd", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionEnd(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)
		assert.Equal(t, PDUTypeX2, pdu.Header.Type)
		assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
	})

	t.Run("EncodeSessionAttempt", func(t *testing.T) {
		pdu, err := encoder.EncodeSessionAttempt(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)
		assert.Equal(t, PDUTypeX2, pdu.Header.Type)
		assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
	})

	t.Run("EncodeRegistration", func(t *testing.T) {
		pdu, err := encoder.EncodeRegistration(pkt, xid)
		require.NoError(t, err)
		require.NotNil(t, pdu)
		assert.Equal(t, PDUTypeX2, pdu.Header.Type)
		assert.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
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

func TestX2Encoder_AllSignallingSharesCorrelationAndSequence(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()
	starts := []string{"SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 183 Session Progress", "SIP/2.0 302 Moved Temporarily", "SERVICE sip:bob@example.test SIP/2.0", "SIP/2.0 200 OK", "SIP/2.0 486 Busy Here"}
	var correlation uint64
	for i, start := range starts {
		t.Run(start, func(t *testing.T) {
			raw := []byte(start + "\r\nCall-ID: coverage\r\nCSeq: 1 SERVICE\r\nContent-Length: 0\r\n\r\n")
			ev, err := sip.Parse(raw, sip.ParseOptions{})
			require.NoError(t, err)
			packet := &types.PacketDisplay{Timestamp: time.Unix(42, 0), SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "12345", DstPort: "5060", VoIPData: &types.VoIPMetadata{CallID: ev.CallID, Method: ev.Method, Status: ev.ResponseCode, RawSIP: raw}}
			pdu, err := encoder.EncodeIRI(packet, xid)
			require.NoError(t, err)
			require.NotNil(t, pdu)
			require.Equal(t, raw, pdu.Payload)
			require.Equal(t, PayloadFormatSIP, pdu.Header.PayloadFormat)
			require.Equal(t, xid, pdu.Header.XID)
			if i == 0 {
				correlation = pdu.Header.CorrelationID
			}
			require.Equal(t, correlation, pdu.Header.CorrelationID)
			require.EqualValues(t, i, encoder.GetSequenceNumber())
			require.Equal(t, []byte{192, 0, 2, 1}, FindAttribute(pdu.Attributes, AttrSourceIPv4).Value)
			require.Equal(t, []byte{192, 0, 2, 2}, FindAttribute(pdu.Attributes, AttrDestIPv4).Value)
			require.Equal(t, []byte{0x30, 0x39}, FindAttribute(pdu.Attributes, AttrSourcePort).Value)
			require.Equal(t, []byte{0x13, 0xc4}, FindAttribute(pdu.Attributes, AttrDestPort).Value)
		})
	}
}

func TestX2Encoder_RejectsMalformedRawSIPBeforeSequencing(t *testing.T) {
	encoder := NewX2Encoder()
	xid := uuid.New()
	packet := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{CallID: "valid", Method: "SERVICE"}, RawData: []byte("INVITE sip:valid@example.test SIP/2.0\r\n\r\n")}
	for _, raw := range []string{
		"SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 4\r\n\r\nx",
		"SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: bad\r\n\r\n",
		"SERVICE sip:bob@example.test SIP/2.0\r\nContent-Length: 1\r\nContent-Length: 0\r\n\r\nx",
		"SIP/2.0 700 Invalid\r\n\r\n",
		"SIP/2.0 abc Invalid\r\n\r\n",
		"SERVICE sip:bob@example.test SIP/2.0\r\n",
		"malformed\r\nINVITE sip:bob@example.test SIP/2.0\r\n\r\n",
	} {
		packet.VoIPData.RawSIP = []byte(raw)
		pdu, err := encoder.EncodeIRI(packet, xid)
		require.ErrorIs(t, err, ErrNoSIPPayload, raw)
		require.Nil(t, pdu)
	}
	packet.VoIPData.RawSIP = packet.RawData
	pdu, err := encoder.EncodeIRI(packet, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)
	require.Zero(t, encoder.GetSequenceNumber(), "invalid messages must not consume a sequence")
}

func TestX2Encoder_IRIOnlyBodyPolicy(t *testing.T) {
	for _, start := range []string{"MESSAGE sip:bob@example.test SIP/2.0", "SERVICE sip:bob@example.test SIP/2.0", "SIP/2.0 183 Session Progress", "SIP/2.0 302 Moved Temporarily"} {
		for _, ct := range []string{"text/plain", "application/vnd.3gpp.sms", "multipart/mixed; boundary=part", "application/evil-application/sdp", "application/sdp+foo", "application/sdp", "Application/SDP; charset=utf-8"} {
			t.Run(start+"/"+ct, func(t *testing.T) {
				raw := []byte(start + "\r\nCall-ID: body-policy\r\nContent-Type: " + ct + "\r\nContent-Length: 6\r\nl: 6\r\n\r\nsecret")
				packet := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{CallID: "body-policy", RawSIP: raw}}
				encoder := NewX2Encoder()
				full, err := encoder.EncodeIRIWithPolicy(packet, uuid.New(), SIPContentFull)
				require.NoError(t, err)
				require.Equal(t, raw, full.Payload)
				iri, err := encoder.EncodeIRIWithPolicy(packet, uuid.New(), SIPContentIRIOnly)
				require.NoError(t, err)
				parsed, err := sip.Parse(iri.Payload, sip.ParseOptions{})
				require.NoError(t, err)
				if ct == "application/sdp" || ct == "Application/SDP; charset=utf-8" {
					require.Equal(t, raw, iri.Payload, "SDP remains signaling information")
				} else {
					require.Empty(t, parsed.Body)
					require.Equal(t, "0", parsed.Headers["content-length"])
					require.NotContains(t, string(iri.Payload), "secret")
				}
				require.Equal(t, raw, packet.VoIPData.RawSIP, "a task must never mutate the shared capture")
			})
		}
	}
	for _, raw := range []string{
		"MESSAGE sip:bob@example.test SIP/2.0\r\nContent-Length:\r\n 6\r\nContent-Type: text/plain\r\n\r\nsecret",
		"MESSAGE sip:bob@example.test SIP/2.0\nContent-Type: text/plain\n\nsecret",
	} {
		packet := &types.PacketDisplay{VoIPData: &types.VoIPMetadata{CallID: "body-policy", RawSIP: []byte(raw)}}
		pdu, err := NewX2Encoder().EncodeIRIWithPolicy(packet, uuid.New(), SIPContentIRIOnly)
		require.NoError(t, err)
		parsed, err := sip.Parse(pdu.Payload, sip.ParseOptions{})
		require.NoError(t, err)
		require.Empty(t, parsed.Body)
		require.Equal(t, "0", parsed.Headers["content-length"])
		require.NotContains(t, string(pdu.Payload), "secret")
	}
}
