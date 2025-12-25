package x2x3

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPDUHeader_MarshalBinary(t *testing.T) {
	xid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	correlationID := uint64(0x123456789ABCDEF0)

	header := NewPDUHeader(PDUTypeX2, xid, correlationID)

	data, err := header.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, HeaderMinSize)

	// Verify wire format (big-endian)
	// Version at offset 0
	version := binary.BigEndian.Uint16(data[0:2])
	assert.Equal(t, uint16(Version), version)

	// PDU Type at offset 2
	pduType := binary.BigEndian.Uint16(data[2:4])
	assert.Equal(t, uint16(PDUTypeX2), pduType)

	// Header Length at offset 4
	headerLen := binary.BigEndian.Uint16(data[4:6])
	assert.Equal(t, uint16(HeaderMinSize), headerLen)

	// Payload Format at offset 6
	payloadFmt := binary.BigEndian.Uint16(data[6:8])
	assert.Equal(t, uint16(PayloadFormatEtsi), payloadFmt)

	// Payload Length at offset 8 (should be 0)
	payloadLen := binary.BigEndian.Uint32(data[8:12])
	assert.Equal(t, uint32(0), payloadLen)

	// XID at offset 12 (16 bytes)
	var gotXID uuid.UUID
	copy(gotXID[:], data[12:28])
	assert.Equal(t, xid, gotXID)

	// Correlation ID at offset 28 (8 bytes)
	gotCorr := binary.BigEndian.Uint64(data[28:36])
	assert.Equal(t, correlationID, gotCorr)
}

func TestPDUHeader_UnmarshalBinary(t *testing.T) {
	xid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	correlationID := uint64(0x123456789ABCDEF0)

	original := NewPDUHeader(PDUTypeX3, xid, correlationID)
	original.PayloadLength = 1000

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	// Manually set payload length (since MarshalBinary doesn't include it)
	binary.BigEndian.PutUint32(data[8:12], 1000)

	var decoded PDUHeader
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.HeaderLength, decoded.HeaderLength)
	assert.Equal(t, original.PayloadFormat, decoded.PayloadFormat)
	assert.Equal(t, uint32(1000), decoded.PayloadLength)
	assert.Equal(t, original.XID, decoded.XID)
	assert.Equal(t, original.CorrelationID, decoded.CorrelationID)
}

func TestPDUHeader_UnmarshalBinary_Errors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{
			name:    "buffer too small",
			data:    make([]byte, HeaderMinSize-1),
			wantErr: ErrBufferTooSmall,
		},
		{
			name: "invalid version (major too high)",
			data: func() []byte {
				d := make([]byte, HeaderMinSize)
				binary.BigEndian.PutUint16(d[0:2], (VersionMajor+1)<<8) // Major version too high
				binary.BigEndian.PutUint16(d[2:4], uint16(PDUTypeX2))
				binary.BigEndian.PutUint16(d[4:6], HeaderMinSize)
				return d
			}(),
			wantErr: ErrInvalidVersion,
		},
		{
			name: "invalid PDU type",
			data: func() []byte {
				d := make([]byte, HeaderMinSize)
				binary.BigEndian.PutUint16(d[0:2], Version)
				binary.BigEndian.PutUint16(d[2:4], 99) // Invalid type
				binary.BigEndian.PutUint16(d[4:6], HeaderMinSize)
				return d
			}(),
			wantErr: ErrInvalidPDUType,
		},
		{
			name: "header length too small",
			data: func() []byte {
				d := make([]byte, HeaderMinSize)
				binary.BigEndian.PutUint16(d[0:2], Version)
				binary.BigEndian.PutUint16(d[2:4], uint16(PDUTypeX2))
				binary.BigEndian.PutUint16(d[4:6], HeaderMinSize-1) // Too small
				return d
			}(),
			wantErr: ErrInvalidHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h PDUHeader
			err := h.UnmarshalBinary(tt.data)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestTLVAttribute_MarshalBinary(t *testing.T) {
	attr := TLVAttribute{
		Type:  AttrSequenceNumber,
		Value: []byte{0x00, 0x00, 0x00, 0x42},
	}

	data, err := attr.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, TLVHeaderSize+4)

	// Type at offset 0
	attrType := binary.BigEndian.Uint16(data[0:2])
	assert.Equal(t, uint16(AttrSequenceNumber), attrType)

	// Length at offset 2
	length := binary.BigEndian.Uint16(data[2:4])
	assert.Equal(t, uint16(4), length)

	// Value at offset 4
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x42}, data[4:8])
}

func TestTLVAttribute_UnmarshalBinary(t *testing.T) {
	original := TLVAttribute{
		Type:  AttrTargetIdentifier,
		Value: []byte("sip:alice@example.com"),
	}

	data, err := original.MarshalBinary()
	require.NoError(t, err)

	var decoded TLVAttribute
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Value, decoded.Value)
}

func TestTLVAttribute_Size(t *testing.T) {
	attr := TLVAttribute{
		Type:  AttrSourceIPv4,
		Value: []byte{192, 168, 1, 100},
	}
	assert.Equal(t, TLVHeaderSize+4, attr.Size())

	attr.Value = []byte{}
	assert.Equal(t, TLVHeaderSize, attr.Size())
}

func TestTLVAttribute_EncodeTo(t *testing.T) {
	attr := TLVAttribute{
		Type:  AttrSourcePort,
		Value: []byte{0x1F, 0x90}, // port 8080
	}

	buf := make([]byte, 100)
	n, err := attr.EncodeTo(buf)
	require.NoError(t, err)
	assert.Equal(t, TLVHeaderSize+2, n)

	// Verify content
	attrType := binary.BigEndian.Uint16(buf[0:2])
	assert.Equal(t, uint16(AttrSourcePort), attrType)
	length := binary.BigEndian.Uint16(buf[2:4])
	assert.Equal(t, uint16(2), length)
}

func TestTLVAttribute_EncodeTo_BufferTooSmall(t *testing.T) {
	attr := TLVAttribute{
		Type:  AttrSourceIPv4,
		Value: []byte{192, 168, 1, 100},
	}

	buf := make([]byte, attr.Size()-1)
	_, err := attr.EncodeTo(buf)
	assert.ErrorIs(t, err, ErrTLVBufferTooSmall)
}

func TestPDU_FullRoundTrip(t *testing.T) {
	xid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	correlationID := uint64(0xDEADBEEFCAFEBABE)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)

	// Add attributes
	encoder := TLVEncoder{}
	pdu.AddAttribute(encoder.EncodeUint32(AttrSequenceNumber, 12345))
	pdu.AddAttribute(encoder.EncodeBytes(AttrSourceIPv4, []byte{10, 0, 0, 1}))
	pdu.AddAttribute(encoder.EncodeBytes(AttrDestIPv4, []byte{10, 0, 0, 2}))
	pdu.AddAttribute(encoder.EncodeUint16(AttrSourcePort, 5060))
	pdu.AddAttribute(encoder.EncodeUint16(AttrDestPort, 5061))
	pdu.AddAttribute(encoder.EncodeString(AttrTargetIdentifier, "sip:target@example.com"))

	// Set payload
	payload := []byte("SIP/2.0 200 OK\r\nCall-ID: test\r\n\r\n")
	pdu.SetPayload(payload)

	// Marshal
	data, err := pdu.MarshalBinary()
	require.NoError(t, err)

	// Verify size calculation
	assert.Equal(t, pdu.Size(), len(data))

	// Unmarshal
	var decoded PDU
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify header
	assert.Equal(t, pdu.Header.Version, decoded.Header.Version)
	assert.Equal(t, pdu.Header.Type, decoded.Header.Type)
	assert.Equal(t, pdu.Header.HeaderLength, decoded.Header.HeaderLength)
	assert.Equal(t, pdu.Header.PayloadFormat, decoded.Header.PayloadFormat)
	assert.Equal(t, pdu.Header.PayloadLength, decoded.Header.PayloadLength)
	assert.Equal(t, pdu.Header.XID, decoded.Header.XID)
	assert.Equal(t, pdu.Header.CorrelationID, decoded.Header.CorrelationID)

	// Verify attributes
	assert.Len(t, decoded.Attributes, 6)
	for i, attr := range pdu.Attributes {
		assert.Equal(t, attr.Type, decoded.Attributes[i].Type)
		assert.Equal(t, attr.Value, decoded.Attributes[i].Value)
	}

	// Verify payload
	assert.Equal(t, payload, decoded.Payload)
}

func TestPDU_WriteTo(t *testing.T) {
	xid := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	pdu := NewPDU(PDUTypeX3, xid, 0)
	pdu.SetPayload([]byte{0x80, 0x00, 0x01, 0x02}) // Minimal RTP-like payload

	var buf bytes.Buffer
	n, err := pdu.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(pdu.Size()), n)
	assert.Equal(t, pdu.Size(), buf.Len())
}

func TestPDU_EmptyPayload(t *testing.T) {
	xid := uuid.New()
	pdu := NewPDU(PDUTypeX2, xid, 123)

	data, err := pdu.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, HeaderMinSize, len(data))

	var decoded PDU
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Empty(t, decoded.Payload)
	assert.Empty(t, decoded.Attributes)
}

func TestTLVEncoder_Types(t *testing.T) {
	encoder := TLVEncoder{}

	t.Run("EncodeUint8", func(t *testing.T) {
		attr := encoder.EncodeUint8(AttrDirection, 1)
		assert.Equal(t, AttrDirection, attr.Type)
		assert.Equal(t, []byte{1}, attr.Value)
	})

	t.Run("EncodeUint16", func(t *testing.T) {
		attr := encoder.EncodeUint16(AttrSourcePort, 5060)
		assert.Equal(t, AttrSourcePort, attr.Type)
		assert.Equal(t, []byte{0x13, 0xC4}, attr.Value)
	})

	t.Run("EncodeUint32", func(t *testing.T) {
		attr := encoder.EncodeUint32(AttrSequenceNumber, 0x12345678)
		assert.Equal(t, AttrSequenceNumber, attr.Type)
		assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, attr.Value)
	})

	t.Run("EncodeUint64", func(t *testing.T) {
		attr := encoder.EncodeUint64(AttrTimestamp, 0x123456789ABCDEF0)
		assert.Equal(t, AttrTimestamp, attr.Type)
		assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}, attr.Value)
	})

	t.Run("EncodeString", func(t *testing.T) {
		attr := encoder.EncodeString(AttrTargetIdentifier, "sip:alice@example.com")
		assert.Equal(t, AttrTargetIdentifier, attr.Type)
		assert.Equal(t, "sip:alice@example.com", string(attr.Value))
	})

	t.Run("EncodeBytes", func(t *testing.T) {
		ipv4 := []byte{192, 168, 1, 100}
		attr := encoder.EncodeBytes(AttrSourceIPv4, ipv4)
		assert.Equal(t, AttrSourceIPv4, attr.Type)
		assert.Equal(t, ipv4, attr.Value)
	})
}

func TestTLVDecoder_Types(t *testing.T) {
	encoder := TLVEncoder{}
	decoder := TLVDecoder{}

	t.Run("DecodeUint8", func(t *testing.T) {
		attr := encoder.EncodeUint8(AttrDirection, 2)
		val, err := decoder.DecodeUint8(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint8(2), val)
	})

	t.Run("DecodeUint16", func(t *testing.T) {
		attr := encoder.EncodeUint16(AttrSourcePort, 8080)
		val, err := decoder.DecodeUint16(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint16(8080), val)
	})

	t.Run("DecodeUint32", func(t *testing.T) {
		attr := encoder.EncodeUint32(AttrSequenceNumber, 0xDEADBEEF)
		val, err := decoder.DecodeUint32(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint32(0xDEADBEEF), val)
	})

	t.Run("DecodeUint64", func(t *testing.T) {
		attr := encoder.EncodeUint64(AttrTimestamp, 0xCAFEBABEDEADBEEF)
		val, err := decoder.DecodeUint64(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint64(0xCAFEBABEDEADBEEF), val)
	})

	t.Run("DecodeString", func(t *testing.T) {
		attr := encoder.EncodeString(AttrTargetIdentifier, "test@example.com")
		val := decoder.DecodeString(&attr)
		assert.Equal(t, "test@example.com", val)
	})
}

func TestTLVDecoder_Errors(t *testing.T) {
	decoder := TLVDecoder{}

	t.Run("DecodeUint8 empty", func(t *testing.T) {
		attr := TLVAttribute{Type: AttrDirection, Value: []byte{}}
		_, err := decoder.DecodeUint8(&attr)
		assert.ErrorIs(t, err, ErrBufferTooSmall)
	})

	t.Run("DecodeUint16 too short", func(t *testing.T) {
		attr := TLVAttribute{Type: AttrSourcePort, Value: []byte{0x00}}
		_, err := decoder.DecodeUint16(&attr)
		assert.ErrorIs(t, err, ErrBufferTooSmall)
	})

	t.Run("DecodeUint32 too short", func(t *testing.T) {
		attr := TLVAttribute{Type: AttrSequenceNumber, Value: []byte{0x00, 0x01, 0x02}}
		_, err := decoder.DecodeUint32(&attr)
		assert.ErrorIs(t, err, ErrBufferTooSmall)
	})

	t.Run("DecodeUint64 too short", func(t *testing.T) {
		attr := TLVAttribute{Type: AttrTimestamp, Value: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}}
		_, err := decoder.DecodeUint64(&attr)
		assert.ErrorIs(t, err, ErrBufferTooSmall)
	})
}

func TestPDUType_String(t *testing.T) {
	assert.Equal(t, "X2", PDUTypeX2.String())
	assert.Equal(t, "X3", PDUTypeX3.String())
	assert.Equal(t, "Unknown(99)", PDUType(99).String())
}

func TestNetworkByteOrder(t *testing.T) {
	// Verify that all encoding is big-endian (network byte order)
	encoder := TLVEncoder{}

	// Test uint16: 0x1234 should encode as [0x12, 0x34]
	attr16 := encoder.EncodeUint16(AttrSourcePort, 0x1234)
	assert.Equal(t, []byte{0x12, 0x34}, attr16.Value)

	// Test uint32: 0x12345678 should encode as [0x12, 0x34, 0x56, 0x78]
	attr32 := encoder.EncodeUint32(AttrSequenceNumber, 0x12345678)
	assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, attr32.Value)

	// Test uint64: 0x123456789ABCDEF0 should encode in order
	attr64 := encoder.EncodeUint64(AttrTimestamp, 0x123456789ABCDEF0)
	expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	assert.Equal(t, expected, attr64.Value)
}

func TestHeaderMinSize(t *testing.T) {
	// Verify the constant matches the calculated size:
	// Version(2) + PDUType(2) + HeaderLen(2) + PayloadFormat(2) + PayloadLen(4) + XID(16) + CorrelationID(8)
	expected := 2 + 2 + 2 + 2 + 4 + 16 + 8
	assert.Equal(t, expected, HeaderMinSize)
}
