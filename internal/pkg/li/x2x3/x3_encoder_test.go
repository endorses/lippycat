package x2x3

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestNewX3Encoder(t *testing.T) {
	encoder := NewX3Encoder()
	assert.NotNil(t, encoder)
	assert.NotNil(t, encoder.attrBuilder)
	assert.Equal(t, uint32(0), encoder.GetSequenceNumber())
}

func TestX3Encoder_EncodeCC_Basic(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	rtpPayload := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x12, 0x34, 0x56, 0x78}

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		RawData:   rtpPayload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			PayloadType: 0, // PCMU
			SequenceNum: 1,
			Timestamp:   160,
			CallID:      "call-123@192.168.1.100",
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// Verify PDU header
	assert.Equal(t, PDUTypeX3, pdu.Header.Type)
	assert.Equal(t, xid, pdu.Header.XID)
	assert.Equal(t, uint16(Version), pdu.Header.Version)

	// Verify payload
	assert.Equal(t, rtpPayload, pdu.Payload)

	// Verify SSRC attribute
	ssrcAttr := FindAttribute(pdu.Attributes, AttrRTPSSRC)
	require.NotNil(t, ssrcAttr)
	ssrc := uint32(ssrcAttr.Value[0])<<24 | uint32(ssrcAttr.Value[1])<<16 |
		uint32(ssrcAttr.Value[2])<<8 | uint32(ssrcAttr.Value[3])
	assert.Equal(t, uint32(0x12345678), ssrc)

	// Verify RTP sequence number attribute
	rtpSeqAttr := FindAttribute(pdu.Attributes, AttrRTPSequenceNumber)
	require.NotNil(t, rtpSeqAttr)
	rtpSeq := uint16(rtpSeqAttr.Value[0])<<8 | uint16(rtpSeqAttr.Value[1])
	assert.Equal(t, uint16(1), rtpSeq)

	// Verify RTP timestamp attribute
	rtpTsAttr := FindAttribute(pdu.Attributes, AttrRTPTimestamp)
	require.NotNil(t, rtpTsAttr)
	rtpTs := uint32(rtpTsAttr.Value[0])<<24 | uint32(rtpTsAttr.Value[1])<<16 |
		uint32(rtpTsAttr.Value[2])<<8 | uint32(rtpTsAttr.Value[3])
	assert.Equal(t, uint32(160), rtpTs)

	// Verify payload type attribute
	ptAttr := FindAttribute(pdu.Attributes, AttrRTPPayloadType)
	require.NotNil(t, ptAttr)
	assert.Equal(t, uint8(0), ptAttr.Value[0])

	// Verify stream ID attribute
	streamAttr := FindAttribute(pdu.Attributes, AttrStreamID)
	require.NotNil(t, streamAttr)

	// Verify sequence number incremented
	assert.Equal(t, uint32(1), encoder.GetSequenceNumber())
}

func TestX3Encoder_EncodeCC_NotRTP(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Non-RTP packet
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "SIP",
		VoIPData: &types.VoIPMetadata{
			CallID: "call-123@192.168.1.100",
			Method: "INVITE",
			IsRTP:  false,
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	assert.ErrorIs(t, err, ErrNotRTP)
	assert.Nil(t, pdu)
}

func TestX3Encoder_EncodeCC_NoVoIPData(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "UDP",
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	assert.ErrorIs(t, err, ErrNotRTP)
	assert.Nil(t, pdu)
}

func TestX3Encoder_EncodeCC_NoSSRC(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "RTP",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0, // Missing SSRC
			SequenceNum: 1,
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	assert.ErrorIs(t, err, ErrNoSSRC)
	assert.Nil(t, pdu)
}

func TestX3Encoder_EncodeCCWithPayload(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Separate payload
	rtpPayload := []byte("audio-data-here")

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		Protocol:  "RTP",
		// No RawData - using explicit payload
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0xABCDEF01,
			PayloadType: 8, // PCMA
			SequenceNum: 100,
			Timestamp:   8000,
		},
	}

	pdu, err := encoder.EncodeCCWithPayload(pkt, xid, rtpPayload)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	assert.Equal(t, rtpPayload, pdu.Payload)
	assert.Equal(t, PDUTypeX3, pdu.Header.Type)
}

func TestX3Encoder_EncodeCCWithPayload_NoPayload(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		Protocol:  "RTP",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0xABCDEF01,
			SequenceNum: 100,
		},
	}

	pdu, err := encoder.EncodeCCWithPayload(pkt, xid, nil)
	assert.ErrorIs(t, err, ErrNoPayload)
	assert.Nil(t, pdu)

	pdu, err = encoder.EncodeCCWithPayload(pkt, xid, []byte{})
	assert.ErrorIs(t, err, ErrNoPayload)
	assert.Nil(t, pdu)
}

func TestX3Encoder_CorrelationID_Deterministic(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	callID := "call-123@192.168.1.100"
	ssrc := uint32(0x12345678)

	// Two packets with the same SSRC and Call-ID should have the same correlation ID
	pkt1 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        ssrc,
			CallID:      callID,
			SequenceNum: 1,
		},
	}

	pkt2 := &types.PacketDisplay{
		Timestamp: time.Now().Add(20 * time.Millisecond),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        ssrc,
			CallID:      callID,
			SequenceNum: 2,
		},
	}

	pdu1, err := encoder.EncodeCC(pkt1, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu1)

	pdu2, err := encoder.EncodeCC(pkt2, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu2)

	// Same SSRC + CallID = same correlation ID
	assert.Equal(t, pdu1.Header.CorrelationID, pdu2.Header.CorrelationID)
}

func TestX3Encoder_CorrelationID_DifferentSSRC(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	callID := "call-123@192.168.1.100"

	pkt1 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x11111111,
			CallID:      callID,
			SequenceNum: 1,
		},
	}

	pkt2 := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.200",
		DstIP:     "192.168.1.100",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x22222222, // Different SSRC (reverse stream)
			CallID:      callID,
			SequenceNum: 1,
		},
	}

	pdu1, err := encoder.EncodeCC(pkt1, xid)
	require.NoError(t, err)
	pdu2, err := encoder.EncodeCC(pkt2, xid)
	require.NoError(t, err)

	// Same CallID but different SSRC = different correlation IDs
	// (This allows distinguishing forward/reverse RTP streams)
	assert.NotEqual(t, pdu1.Header.CorrelationID, pdu2.Header.CorrelationID)
}

func TestX3Encoder_SequenceNumber_Monotonic(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1,
		},
	}

	// Encode multiple CCs
	for i := 1; i <= 10; i++ {
		_, err := encoder.EncodeCC(pkt, xid)
		require.NoError(t, err)
		assert.Equal(t, uint32(i), encoder.GetSequenceNumber())
	}
}

func TestX3Encoder_NetworkAttributes_IPv4(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1,
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
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

	// Verify source port (10000 = 0x2710)
	srcPortAttr := FindAttribute(pdu.Attributes, AttrSourcePort)
	require.NotNil(t, srcPortAttr)
	assert.Equal(t, []byte{0x27, 0x10}, srcPortAttr.Value)

	// Verify destination port (20000 = 0x4E20)
	dstPortAttr := FindAttribute(pdu.Attributes, AttrDestPort)
	require.NotNil(t, dstPortAttr)
	assert.Equal(t, []byte{0x4E, 0x20}, dstPortAttr.Value)
}

func TestX3Encoder_NetworkAttributes_IPv6(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "2001:db8::1",
		DstIP:     "2001:db8::2",
		SrcPort:   "10000",
		DstPort:   "20000",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1,
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
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

func TestX3Encoder_PDU_Serialization(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	rtpPayload := []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0}

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		RawData:   rtpPayload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			PayloadType: 0,
			SequenceNum: 1,
			Timestamp:   160,
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
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
	assert.Equal(t, pdu.Payload, decoded.Payload)
}

func TestX3Encoder_EncodeCCBatch(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	packets := make([]*types.PacketDisplay, 5)
	for i := 0; i < 5; i++ {
		packets[i] = &types.PacketDisplay{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			RawData:   []byte{0x80, 0x00, byte(i), 0x00},
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        0x12345678,
				SequenceNum: uint16(i),
				Timestamp:   uint32(i * 160),
			},
		}
	}

	pdus, errs := encoder.EncodeCCBatch(packets, xid)
	assert.Len(t, pdus, 5)
	assert.Len(t, errs, 0)

	// Verify each PDU
	for i, pdu := range pdus {
		assert.Equal(t, PDUTypeX3, pdu.Header.Type)
		rtpSeqAttr := FindAttribute(pdu.Attributes, AttrRTPSequenceNumber)
		require.NotNil(t, rtpSeqAttr)
		rtpSeq := uint16(rtpSeqAttr.Value[0])<<8 | uint16(rtpSeqAttr.Value[1])
		assert.Equal(t, uint16(i), rtpSeq)
	}
}

func TestX3Encoder_EncodeCCBatch_WithErrors(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	packets := []*types.PacketDisplay{
		// Valid RTP packet
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        0x12345678,
				SequenceNum: 1,
			},
		},
		// Invalid: not RTP
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			VoIPData: &types.VoIPMetadata{
				IsRTP:  false,
				CallID: "call-123",
			},
		},
		// Valid RTP packet
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        0x87654321,
				SequenceNum: 2,
			},
		},
		// Invalid: no SSRC
		{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        0,
				SequenceNum: 3,
			},
		},
	}

	pdus, errs := encoder.EncodeCCBatch(packets, xid)
	assert.Len(t, pdus, 2) // Only 2 valid packets
	assert.Len(t, errs, 2) // 2 errors
	assert.ErrorIs(t, errs[0], ErrNotRTP)
	assert.ErrorIs(t, errs[1], ErrNoSSRC)
}

func TestX3Encoder_SeqNumber_Fallback(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Test using SeqNumber when SequenceNum is 0
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 0,     // Not set
			SeqNumber:   12345, // Fallback field
		},
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	rtpSeqAttr := FindAttribute(pdu.Attributes, AttrRTPSequenceNumber)
	require.NotNil(t, rtpSeqAttr)
	rtpSeq := uint16(rtpSeqAttr.Value[0])<<8 | uint16(rtpSeqAttr.Value[1])
	assert.Equal(t, uint16(12345), rtpSeq)
}

func TestX3Encoder_NoRawData(t *testing.T) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Packet without raw data (just metadata)
	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			SequenceNum: 1,
		},
		// No RawData
	}

	pdu, err := encoder.EncodeCC(pkt, xid)
	require.NoError(t, err)
	require.NotNil(t, pdu)

	// PDU should be valid but with empty payload
	assert.Empty(t, pdu.Payload)
	assert.Equal(t, uint32(0), pdu.Header.PayloadLength)
}

// BenchmarkX3Encoder_EncodeCC benchmarks the X3 encoder for high-volume streaming.
func BenchmarkX3Encoder_EncodeCC(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Simulate a typical G.711 RTP packet (160 bytes of audio)
	rtpPayload := make([]byte, 172) // 12 byte header + 160 bytes payload
	rtpPayload[0] = 0x80            // V=2, P=0, X=0, CC=0
	rtpPayload[1] = 0x00            // M=0, PT=0 (PCMU)

	pkt := &types.PacketDisplay{
		Timestamp: time.Now(),
		SrcIP:     "192.168.1.100",
		DstIP:     "192.168.1.200",
		SrcPort:   "10000",
		DstPort:   "20000",
		RawData:   rtpPayload,
		VoIPData: &types.VoIPMetadata{
			IsRTP:       true,
			SSRC:        0x12345678,
			PayloadType: 0,
			SequenceNum: 1,
			Timestamp:   160,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt.VoIPData.SequenceNum = uint16(i)
		pkt.VoIPData.Timestamp = uint32(i * 160)
		_, err := encoder.EncodeCC(pkt, xid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkX3Encoder_EncodeCCBatch benchmarks batch encoding.
func BenchmarkX3Encoder_EncodeCCBatch(b *testing.B) {
	encoder := NewX3Encoder()
	xid := uuid.New()

	// Create a batch of 50 packets (50 packets * 20ms = 1 second of audio)
	batchSize := 50
	packets := make([]*types.PacketDisplay, batchSize)
	for i := 0; i < batchSize; i++ {
		rtpPayload := make([]byte, 172)
		rtpPayload[0] = 0x80
		rtpPayload[1] = 0x00
		packets[i] = &types.PacketDisplay{
			Timestamp: time.Now(),
			SrcIP:     "192.168.1.100",
			DstIP:     "192.168.1.200",
			RawData:   rtpPayload,
			VoIPData: &types.VoIPMetadata{
				IsRTP:       true,
				SSRC:        0x12345678,
				SequenceNum: uint16(i),
				Timestamp:   uint32(i * 160),
			},
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pdus, _ := encoder.EncodeCCBatch(packets, xid)
		if len(pdus) != batchSize {
			b.Fatal("unexpected number of PDUs")
		}
	}
}
