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

// TestETSI_TS_103_221_2_ByteCompliance verifies byte-level compliance with ETSI TS 103 221-2.
// This test constructs a PDU and verifies each byte matches the specification.
func TestETSI_TS_103_221_2_ByteCompliance(t *testing.T) {
	t.Run("X2_PDU_header_layout", func(t *testing.T) {
		// Create a PDU with known values for deterministic testing
		xid := uuid.MustParse("01234567-89ab-cdef-0123-456789abcdef")
		correlationID := uint64(0xFEDCBA9876543210)

		pdu := NewPDU(PDUTypeX2, xid, correlationID)
		pdu.SetPayload([]byte{0xAA, 0xBB, 0xCC, 0xDD})

		data, err := pdu.MarshalBinary()
		require.NoError(t, err)

		// Verify header layout per ETSI TS 103 221-2 Section 5.2
		// Offset 0-1: Version (2 bytes, big-endian)
		assert.Equal(t, byte(VersionMajor), data[0], "Version major byte")
		assert.Equal(t, byte(VersionMinor), data[1], "Version minor byte")

		// Offset 2-3: PDU Type (2 bytes, big-endian)
		assert.Equal(t, byte(0), data[2], "PDU type high byte")
		assert.Equal(t, byte(1), data[3], "PDU type low byte (1=X2)")

		// Offset 4-5: Header Length (2 bytes, big-endian)
		headerLen := binary.BigEndian.Uint16(data[4:6])
		assert.Equal(t, uint16(HeaderMinSize), headerLen, "Header length")

		// Offset 6-7: Payload Format (2 bytes, big-endian)
		assert.Equal(t, byte(0), data[6], "Payload format high byte")
		assert.Equal(t, byte(1), data[7], "Payload format low byte (1=ETSI)")

		// Offset 8-11: Payload Length (4 bytes, big-endian)
		payloadLen := binary.BigEndian.Uint32(data[8:12])
		assert.Equal(t, uint32(4), payloadLen, "Payload length")

		// Offset 12-27: XID (16 bytes, UUID in network byte order)
		assert.Equal(t, xid[:], data[12:28], "XID bytes")

		// Offset 28-35: Correlation ID (8 bytes, big-endian)
		assert.Equal(t, []byte{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}, data[28:36], "Correlation ID bytes")

		// Offset 36+: Payload
		assert.Equal(t, []byte{0xAA, 0xBB, 0xCC, 0xDD}, data[36:40], "Payload bytes")
	})

	t.Run("X3_PDU_header_layout", func(t *testing.T) {
		xid := uuid.MustParse("fedcba98-7654-3210-fedc-ba9876543210")
		correlationID := uint64(0x0102030405060708)

		pdu := NewPDU(PDUTypeX3, xid, correlationID)
		data, err := pdu.MarshalBinary()
		require.NoError(t, err)

		// Verify X3 PDU type encoding
		assert.Equal(t, byte(0), data[2], "PDU type high byte")
		assert.Equal(t, byte(2), data[3], "PDU type low byte (2=X3)")
	})

	t.Run("TLV_attribute_layout", func(t *testing.T) {
		// Per ETSI TS 103 221-2 Section 5.3: TLV format
		// Offset 0-1: Type (2 bytes, big-endian)
		// Offset 2-3: Length (2 bytes, big-endian)
		// Offset 4+: Value (Length bytes)

		attr := TLVAttribute{
			Type:  AttrSIPCallID, // 0x0100
			Value: []byte("call-123@example.com"),
		}

		data, err := attr.MarshalBinary()
		require.NoError(t, err)

		// Verify type encoding (0x0100)
		assert.Equal(t, byte(0x01), data[0], "Type high byte")
		assert.Equal(t, byte(0x00), data[1], "Type low byte")

		// Verify length encoding
		assert.Equal(t, byte(0x00), data[2], "Length high byte")
		assert.Equal(t, byte(20), data[3], "Length low byte (20 chars)")

		// Verify value
		assert.Equal(t, "call-123@example.com", string(data[4:24]))
	})

	t.Run("timestamp_POSIX_timespec_format", func(t *testing.T) {
		// Per ETSI TS 103 221-2: Timestamp is POSIX timespec
		// 8 bytes for seconds (int64, signed) + 4 bytes for nanoseconds (int32)
		ts := Timestamp{
			Seconds:     1703500000, // 2023-12-25 12:26:40 UTC
			Nanoseconds: 123456789,
		}

		data, err := ts.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, data, 12)

		// Verify seconds encoding (big-endian, signed 64-bit)
		secs := int64(binary.BigEndian.Uint64(data[0:8]))
		assert.Equal(t, int64(1703500000), secs)

		// Verify nanoseconds encoding (big-endian, signed 32-bit)
		nanos := int32(binary.BigEndian.Uint32(data[8:12]))
		assert.Equal(t, int32(123456789), nanos)
	})

	t.Run("IPv4_address_encoding", func(t *testing.T) {
		// IPv4 addresses are 4 bytes in network byte order
		encoder := TLVEncoder{}
		attr := encoder.EncodeBytes(AttrSourceIPv4, []byte{192, 168, 1, 100})

		data, err := attr.MarshalBinary()
		require.NoError(t, err)

		// Type: 0x0003 (AttrSourceIPv4)
		assert.Equal(t, byte(0x00), data[0])
		assert.Equal(t, byte(0x03), data[1])

		// Length: 4 bytes
		assert.Equal(t, byte(0x00), data[2])
		assert.Equal(t, byte(0x04), data[3])

		// Value: 192.168.1.100
		assert.Equal(t, []byte{192, 168, 1, 100}, data[4:8])
	})

	t.Run("IPv6_address_encoding", func(t *testing.T) {
		// IPv6 addresses are 16 bytes in network byte order
		ipv6 := []byte{
			0x20, 0x01, 0x0d, 0xb8, // 2001:0db8
			0x00, 0x00, 0x00, 0x00, // ::
			0x00, 0x00, 0x00, 0x00, // ::
			0x00, 0x00, 0x00, 0x01, // ::1
		}

		encoder := TLVEncoder{}
		attr := encoder.EncodeBytes(AttrSourceIPv6, ipv6)

		data, err := attr.MarshalBinary()
		require.NoError(t, err)

		// Type: 0x0005 (AttrSourceIPv6)
		assert.Equal(t, byte(0x00), data[0])
		assert.Equal(t, byte(0x05), data[1])

		// Length: 16 bytes
		assert.Equal(t, byte(0x00), data[2])
		assert.Equal(t, byte(0x10), data[3])

		// Value
		assert.Equal(t, ipv6, data[4:20])
	})

	t.Run("RTP_attributes_encoding", func(t *testing.T) {
		encoder := TLVEncoder{}

		// SSRC: 0x12345678
		ssrcAttr := encoder.EncodeUint32(AttrRTPSSRC, 0x12345678)
		ssrcData, _ := ssrcAttr.MarshalBinary()
		assert.Equal(t, byte(0x02), ssrcData[0], "SSRC type high byte")
		assert.Equal(t, byte(0x00), ssrcData[1], "SSRC type low byte")
		assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, ssrcData[4:8], "SSRC value")

		// RTP Sequence Number: 0xABCD
		seqAttr := encoder.EncodeUint16(AttrRTPSequenceNumber, 0xABCD)
		seqData, _ := seqAttr.MarshalBinary()
		assert.Equal(t, byte(0x02), seqData[0], "Seq type high byte")
		assert.Equal(t, byte(0x01), seqData[1], "Seq type low byte")
		assert.Equal(t, []byte{0xAB, 0xCD}, seqData[4:6], "Seq value")

		// RTP Timestamp: 0x11223344
		tsAttr := encoder.EncodeUint32(AttrRTPTimestamp, 0x11223344)
		tsData, _ := tsAttr.MarshalBinary()
		assert.Equal(t, byte(0x02), tsData[0], "TS type high byte")
		assert.Equal(t, byte(0x02), tsData[1], "TS type low byte")
		assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, tsData[4:8], "TS value")

		// RTP Payload Type: 0 (PCMU)
		ptAttr := encoder.EncodeUint8(AttrRTPPayloadType, 0)
		ptData, _ := ptAttr.MarshalBinary()
		assert.Equal(t, byte(0x02), ptData[0], "PT type high byte")
		assert.Equal(t, byte(0x03), ptData[1], "PT type low byte")
		assert.Equal(t, byte(0x00), ptData[4], "PT value")
	})

	t.Run("complete_X2_PDU_with_attributes", func(t *testing.T) {
		xid := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		pdu := NewPDU(PDUTypeX2, xid, 1)

		encoder := TLVEncoder{}
		pdu.AddAttribute(encoder.EncodeUint32(AttrSequenceNumber, 1))

		data, err := pdu.MarshalBinary()
		require.NoError(t, err)

		// Total size: 36 (header) + 8 (seq attr: 4 type/len + 4 value) = 44
		assert.Len(t, data, 44)

		// Header length should include attribute
		headerLen := binary.BigEndian.Uint16(data[4:6])
		assert.Equal(t, uint16(44), headerLen)

		// Attribute starts at offset 36
		attrType := binary.BigEndian.Uint16(data[36:38])
		assert.Equal(t, uint16(AttrSequenceNumber), attrType)

		attrLen := binary.BigEndian.Uint16(data[38:40])
		assert.Equal(t, uint16(4), attrLen)

		attrVal := binary.BigEndian.Uint32(data[40:44])
		assert.Equal(t, uint32(1), attrVal)
	})
}
