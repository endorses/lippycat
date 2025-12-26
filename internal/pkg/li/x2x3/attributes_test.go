package x2x3

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimestamp_MarshalUnmarshal(t *testing.T) {
	// Test specific time
	testTime := time.Date(2025, 12, 25, 10, 30, 45, 123456789, time.UTC)
	ts := NewTimestamp(testTime)

	data, err := ts.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, TimestampSize)

	var decoded Timestamp
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, ts.Seconds, decoded.Seconds)
	assert.Equal(t, ts.Nanoseconds, decoded.Nanoseconds)

	// Verify roundtrip to time.Time
	roundTrip := decoded.Time()
	assert.Equal(t, testTime.Unix(), roundTrip.Unix())
	assert.Equal(t, testTime.Nanosecond(), roundTrip.Nanosecond())
}

func TestTimestamp_NetworkByteOrder(t *testing.T) {
	// Verify big-endian encoding
	ts := Timestamp{
		Seconds:     0x0102030405060708,
		Nanoseconds: 0x0A0B0C0D,
	}

	data, err := ts.MarshalBinary()
	require.NoError(t, err)

	// Seconds: big-endian
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, data[0:8])
	// Nanoseconds: big-endian
	assert.Equal(t, []byte{0x0A, 0x0B, 0x0C, 0x0D}, data[8:12])
}

func TestTimestamp_UnmarshalError(t *testing.T) {
	var ts Timestamp
	err := ts.UnmarshalBinary([]byte{1, 2, 3}) // Too short
	assert.ErrorIs(t, err, ErrInvalidTimestamp)
}

func TestAttributeBuilder_Timestamp(t *testing.T) {
	builder := NewAttributeBuilder()
	testTime := time.Date(2025, 1, 15, 12, 0, 0, 500000000, time.UTC)

	attr := builder.Timestamp(testTime)
	assert.Equal(t, AttrTimestamp, attr.Type)
	assert.Len(t, attr.Value, TimestampSize)

	// Parse it back
	parser := NewAttributeParser()
	parsedTime, err := parser.ParseTimestamp(&attr)
	require.NoError(t, err)
	assert.Equal(t, testTime.Unix(), parsedTime.Unix())
	assert.Equal(t, testTime.Nanosecond(), parsedTime.Nanosecond())
}

func TestAttributeBuilder_TimestampNow(t *testing.T) {
	builder := NewAttributeBuilder()
	before := time.Now()
	attr := builder.TimestampNow()
	after := time.Now()

	assert.Equal(t, AttrTimestamp, attr.Type)
	assert.Len(t, attr.Value, TimestampSize)

	parser := NewAttributeParser()
	parsedTime, err := parser.ParseTimestamp(&attr)
	require.NoError(t, err)

	// Verify the timestamp is between before and after
	assert.True(t, !parsedTime.Before(before.Truncate(time.Second)))
	assert.True(t, !parsedTime.After(after.Add(time.Second)))
}

func TestAttributeBuilder_SequenceNumber(t *testing.T) {
	builder := NewAttributeBuilder()
	attr := builder.SequenceNumber(0xDEADBEEF)

	assert.Equal(t, AttrSequenceNumber, attr.Type)
	assert.Len(t, attr.Value, SequenceNumberSize)
	// Verify big-endian
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, attr.Value)

	parser := NewAttributeParser()
	seq, err := parser.ParseSequenceNumber(&attr)
	require.NoError(t, err)
	assert.Equal(t, uint32(0xDEADBEEF), seq)
}

func TestAttributeBuilder_IPv4(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	t.Run("SourceIPv4", func(t *testing.T) {
		addr := netip.MustParseAddr("192.168.1.100")
		attr, err := builder.SourceIPv4(addr)
		require.NoError(t, err)

		assert.Equal(t, AttrSourceIPv4, attr.Type)
		assert.Len(t, attr.Value, IPv4Size)
		assert.Equal(t, []byte{192, 168, 1, 100}, attr.Value)

		parsed, err := parser.ParseSourceIPv4(&attr)
		require.NoError(t, err)
		assert.Equal(t, addr, parsed)
	})

	t.Run("DestIPv4", func(t *testing.T) {
		addr := netip.MustParseAddr("10.0.0.1")
		attr, err := builder.DestIPv4(addr)
		require.NoError(t, err)

		assert.Equal(t, AttrDestIPv4, attr.Type)
		assert.Equal(t, []byte{10, 0, 0, 1}, attr.Value)

		parsed, err := parser.ParseDestIPv4(&attr)
		require.NoError(t, err)
		assert.Equal(t, addr, parsed)
	})

	t.Run("InvalidIPv6AsIPv4", func(t *testing.T) {
		addr := netip.MustParseAddr("::1")
		_, err := builder.SourceIPv4(addr)
		assert.ErrorIs(t, err, ErrInvalidIPv4)
	})
}

func TestAttributeBuilder_IPv6(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	t.Run("SourceIPv6", func(t *testing.T) {
		addr := netip.MustParseAddr("2001:db8::1")
		attr, err := builder.SourceIPv6(addr)
		require.NoError(t, err)

		assert.Equal(t, AttrSourceIPv6, attr.Type)
		assert.Len(t, attr.Value, IPv6Size)

		parsed, err := parser.ParseSourceIPv6(&attr)
		require.NoError(t, err)
		assert.Equal(t, addr, parsed)
	})

	t.Run("DestIPv6", func(t *testing.T) {
		addr := netip.MustParseAddr("fe80::1")
		attr, err := builder.DestIPv6(addr)
		require.NoError(t, err)

		assert.Equal(t, AttrDestIPv6, attr.Type)

		parsed, err := parser.ParseDestIPv6(&attr)
		require.NoError(t, err)
		assert.Equal(t, addr, parsed)
	})

	t.Run("InvalidIPv4AsIPv6", func(t *testing.T) {
		addr := netip.MustParseAddr("192.168.1.1")
		_, err := builder.SourceIPv6(addr)
		assert.ErrorIs(t, err, ErrInvalidIPv6)
	})
}

func TestAttributeBuilder_SourceIP_AutoDetect(t *testing.T) {
	builder := NewAttributeBuilder()

	t.Run("IPv4", func(t *testing.T) {
		addr := netip.MustParseAddr("172.16.0.1")
		attr, err := builder.SourceIP(addr)
		require.NoError(t, err)
		assert.Equal(t, AttrSourceIPv4, attr.Type)
	})

	t.Run("IPv6", func(t *testing.T) {
		addr := netip.MustParseAddr("::ffff:192.168.1.1")
		attr, err := builder.SourceIP(addr)
		require.NoError(t, err)
		// ::ffff:x.x.x.x is IPv4-mapped IPv6, so it's classified as IPv6
		assert.Equal(t, AttrSourceIPv6, attr.Type)
	})
}

func TestAttributeBuilder_DestIP_AutoDetect(t *testing.T) {
	builder := NewAttributeBuilder()

	t.Run("IPv4", func(t *testing.T) {
		addr := netip.MustParseAddr("8.8.8.8")
		attr, err := builder.DestIP(addr)
		require.NoError(t, err)
		assert.Equal(t, AttrDestIPv4, attr.Type)
	})

	t.Run("IPv6", func(t *testing.T) {
		addr := netip.MustParseAddr("2001:4860:4860::8888")
		attr, err := builder.DestIP(addr)
		require.NoError(t, err)
		assert.Equal(t, AttrDestIPv6, attr.Type)
	})
}

func TestAttributeBuilder_Ports(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	t.Run("SourcePort", func(t *testing.T) {
		attr := builder.SourcePort(5060)
		assert.Equal(t, AttrSourcePort, attr.Type)
		assert.Len(t, attr.Value, PortSize)
		// Verify big-endian: 5060 = 0x13C4
		assert.Equal(t, []byte{0x13, 0xC4}, attr.Value)

		port, err := parser.ParseSourcePort(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint16(5060), port)
	})

	t.Run("DestPort", func(t *testing.T) {
		attr := builder.DestPort(8080)
		assert.Equal(t, AttrDestPort, attr.Type)

		port, err := parser.ParseDestPort(&attr)
		require.NoError(t, err)
		assert.Equal(t, uint16(8080), port)
	})
}

func TestAttributeBuilder_IPProtocol(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	// UDP = 17, TCP = 6
	attr := builder.IPProtocol(17)
	assert.Equal(t, AttrIPProtocol, attr.Type)
	assert.Len(t, attr.Value, ProtocolSize)

	proto, err := parser.ParseIPProtocol(&attr)
	require.NoError(t, err)
	assert.Equal(t, uint8(17), proto)
}

func TestAttributeBuilder_TargetIdentifier(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	target := "sip:alice@example.com"
	attr := builder.TargetIdentifier(target)
	assert.Equal(t, AttrTargetIdentifier, attr.Type)
	assert.Equal(t, target, string(attr.Value))

	parsed, err := parser.ParseTargetIdentifier(&attr)
	require.NoError(t, err)
	assert.Equal(t, target, parsed)
}

func TestAttributeBuilder_NFID(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	// Test with processor-id style NFID
	nfid := "processor-central-01"
	attr := builder.NFID(nfid)
	assert.Equal(t, AttrNFID, attr.Type)
	assert.Equal(t, nfid, string(attr.Value))

	parsed, err := parser.ParseNFID(&attr)
	require.NoError(t, err)
	assert.Equal(t, nfid, parsed)

	// Test with tap-id style NFID
	tapNfid := "edge-tap-voip-01"
	tapAttr := builder.NFID(tapNfid)
	assert.Equal(t, AttrNFID, tapAttr.Type)

	parsedTap, err := parser.ParseNFID(&tapAttr)
	require.NoError(t, err)
	assert.Equal(t, tapNfid, parsedTap)
}

func TestAttributeBuilder_IPID(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	// Test with hunter-id style IPID
	ipid := "hunter-eth0-sip"
	attr := builder.IPID(ipid)
	assert.Equal(t, AttrIPID, attr.Type)
	assert.Equal(t, ipid, string(attr.Value))

	parsed, err := parser.ParseIPID(&attr)
	require.NoError(t, err)
	assert.Equal(t, ipid, parsed)
}

func TestAttributeBuilder_Direction(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	tests := []struct {
		dir  Direction
		name string
	}{
		{DirectionUnknown, "Unknown"},
		{DirectionFromTarget, "FromTarget"},
		{DirectionToTarget, "ToTarget"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := builder.TrafficDirection(tt.dir)
			assert.Equal(t, AttrDirection, attr.Type)
			assert.Len(t, attr.Value, DirectionSize)

			parsed, err := parser.ParseDirection(&attr)
			require.NoError(t, err)
			assert.Equal(t, tt.dir, parsed)
		})
	}
}

func TestFindAttribute(t *testing.T) {
	builder := NewAttributeBuilder()
	attrs := []TLVAttribute{
		builder.SequenceNumber(1),
		builder.SourcePort(5060),
		builder.DestPort(5061),
		builder.TargetIdentifier("test"),
	}

	t.Run("Found", func(t *testing.T) {
		attr := FindAttribute(attrs, AttrSourcePort)
		require.NotNil(t, attr)
		assert.Equal(t, AttrSourcePort, attr.Type)
	})

	t.Run("NotFound", func(t *testing.T) {
		attr := FindAttribute(attrs, AttrSourceIPv4)
		assert.Nil(t, attr)
	})
}

func TestFindAllAttributes(t *testing.T) {
	// Create multiple timestamp attributes
	builder := NewAttributeBuilder()
	time1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	time2 := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)

	attrs := []TLVAttribute{
		builder.Timestamp(time1),
		builder.SequenceNumber(1),
		builder.Timestamp(time2),
		builder.SourcePort(5060),
	}

	timestamps := FindAllAttributes(attrs, AttrTimestamp)
	assert.Len(t, timestamps, 2)

	sequences := FindAllAttributes(attrs, AttrSequenceNumber)
	assert.Len(t, sequences, 1)

	notFound := FindAllAttributes(attrs, AttrSourceIPv6)
	assert.Empty(t, notFound)
}

func TestAttributeParser_WrongType(t *testing.T) {
	builder := NewAttributeBuilder()
	parser := NewAttributeParser()

	// Try to parse wrong attribute type
	attr := builder.SourcePort(5060)

	_, err := parser.ParseSequenceNumber(&attr)
	assert.Error(t, err)

	_, err = parser.ParseSourceIPv4(&attr)
	assert.Error(t, err)

	_, err = parser.ParseTimestamp(&attr)
	assert.Error(t, err)
}

func TestAttributeBuilder_PDUIntegration(t *testing.T) {
	// Test that attributes integrate correctly with PDU
	builder := NewAttributeBuilder()

	pdu := NewPDU(PDUTypeX2, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 0x12345678)

	pdu.AddAttribute(builder.TimestampNow())
	pdu.AddAttribute(builder.SequenceNumber(42))

	srcIP := netip.MustParseAddr("192.168.1.10")
	dstIP := netip.MustParseAddr("192.168.1.20")

	srcAttr, err := builder.SourceIPv4(srcIP)
	require.NoError(t, err)
	pdu.AddAttribute(srcAttr)

	dstAttr, err := builder.DestIPv4(dstIP)
	require.NoError(t, err)
	pdu.AddAttribute(dstAttr)

	pdu.AddAttribute(builder.SourcePort(5060))
	pdu.AddAttribute(builder.DestPort(5061))
	pdu.AddAttribute(builder.IPProtocol(17)) // UDP
	pdu.AddAttribute(builder.TrafficDirection(DirectionFromTarget))
	pdu.AddAttribute(builder.TargetIdentifier("sip:target@example.com"))

	// Serialize and deserialize
	data, err := pdu.MarshalBinary()
	require.NoError(t, err)

	var decoded PDU
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify attributes
	assert.Len(t, decoded.Attributes, 9)

	parser := NewAttributeParser()

	// Find and parse sequence number
	seqAttr := FindAttribute(decoded.Attributes, AttrSequenceNumber)
	require.NotNil(t, seqAttr)
	seq, err := parser.ParseSequenceNumber(seqAttr)
	require.NoError(t, err)
	assert.Equal(t, uint32(42), seq)

	// Find and parse source IP
	srcIPAttr := FindAttribute(decoded.Attributes, AttrSourceIPv4)
	require.NotNil(t, srcIPAttr)
	parsedSrcIP, err := parser.ParseSourceIPv4(srcIPAttr)
	require.NoError(t, err)
	assert.Equal(t, srcIP, parsedSrcIP)

	// Find and parse target identifier
	targetAttr := FindAttribute(decoded.Attributes, AttrTargetIdentifier)
	require.NotNil(t, targetAttr)
	target, err := parser.ParseTargetIdentifier(targetAttr)
	require.NoError(t, err)
	assert.Equal(t, "sip:target@example.com", target)
}
