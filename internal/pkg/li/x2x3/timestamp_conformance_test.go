package x2x3

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestTimestampBothLayouts(t *testing.T) {
	for _, seconds := range []int64{0, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32} {
		for _, nanos := range []int32{0, 123456789, 999999999} {
			for _, format := range []TimestampFormat{TimestampFormatETSI8, TimestampFormatLegacy12} {
				t.Run(fmt.Sprintf("%s/%d/%d", format, seconds, nanos), func(t *testing.T) {
					want := Timestamp{Seconds: seconds, Nanoseconds: nanos}
					wire, err := want.MarshalBinaryWithFormat(format)
					require.NoError(t, err)
					if format == TimestampFormatETSI8 {
						require.Len(t, wire, StandardTimestampSize)
						require.Equal(t, uint32(seconds), binary.BigEndian.Uint32(wire[:4]))
					} else {
						require.Len(t, wire, LegacyTimestampSize)
						require.Equal(t, uint64(seconds), binary.BigEndian.Uint64(wire[:8]))
					}
					require.Equal(t, uint32(nanos), binary.BigEndian.Uint32(wire[len(wire)-4:]))
					var got Timestamp
					require.NoError(t, got.UnmarshalBinary(wire))
					require.Equal(t, want, got)
					parsed, err := NewAttributeParser().ParseTimestamp(&TLVAttribute{Type: AttrTimestamp, Value: wire})
					require.NoError(t, err)
					require.Equal(t, time.Unix(seconds, int64(nanos)), parsed)
				})
			}
		}
	}
	// The wider signed legacy layout remains valid for historical product.
	for _, seconds := range []int64{math.MinInt64, -1, math.MaxUint32 + 1, math.MaxInt64} {
		want := Timestamp{Seconds: seconds, Nanoseconds: 999999999}
		wire, err := want.MarshalBinary()
		require.NoError(t, err)
		var got Timestamp
		require.NoError(t, got.UnmarshalBinary(wire))
		require.Equal(t, want, got)
	}
}

func TestTimestampRejectsMalformedWire(t *testing.T) {
	for length := 0; length <= 32; length++ {
		if length == StandardTimestampSize || length == LegacyTimestampSize {
			continue
		}
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			wire := make([]byte, length)
			before := Timestamp{Seconds: 42, Nanoseconds: 1}
			got := before
			require.ErrorIs(t, got.UnmarshalBinary(wire), ErrInvalidTimestamp)
			require.Equal(t, before, got, "invalid input must not partially replace a timestamp")
			_, err := NewAttributeParser().ParseTimestamp(&TLVAttribute{Type: AttrTimestamp, Value: wire})
			require.ErrorIs(t, err, ErrInvalidTimestamp)
		})
	}
	for _, length := range []int{StandardTimestampSize, LegacyTimestampSize} {
		for _, nanos := range []uint32{1_000_000_000, math.MaxInt32, 1 << 31, math.MaxUint32} {
			t.Run(fmt.Sprintf("length_%d/nanos_%d", length, nanos), func(t *testing.T) {
				wire := make([]byte, length)
				binary.BigEndian.PutUint32(wire[length-4:], nanos)
				var got Timestamp
				require.ErrorIs(t, got.UnmarshalBinary(wire), ErrInvalidTimestamp)
				_, err := NewAttributeParser().ParseTimestamp(&TLVAttribute{Type: AttrTimestamp, Value: wire})
				require.ErrorIs(t, err, ErrInvalidTimestamp)
			})
		}
	}
}

func TestTimestampMarshalBounds(t *testing.T) {
	for _, format := range []TimestampFormat{TimestampFormatLegacy12, TimestampFormatETSI8} {
		for _, nanos := range []int32{-1, math.MinInt32, 1_000_000_000, math.MaxInt32} {
			wire, err := (Timestamp{Nanoseconds: nanos}).MarshalBinaryWithFormat(format)
			require.ErrorIs(t, err, ErrInvalidTimestamp)
			require.Nil(t, wire)
		}
	}
	for _, seconds := range []int64{math.MinInt64, -1, math.MaxUint32 + 1, math.MaxInt64} {
		wire, err := (Timestamp{Seconds: seconds}).MarshalBinaryWithFormat(TimestampFormatETSI8)
		require.ErrorIs(t, err, ErrTimestampRange)
		require.Nil(t, wire)
	}
	// A known literal proves both integers use network byte order.
	wire, err := (Timestamp{Seconds: 0x81828384, Nanoseconds: 0x01020304}).MarshalBinaryWithFormat(TimestampFormatETSI8)
	require.NoError(t, err)
	require.Equal(t, []byte{0x81, 0x82, 0x83, 0x84, 1, 2, 3, 4}, wire)
}

func TestTimestampFormatsValidatedAtConstruction(t *testing.T) {
	for _, value := range []string{"", "legacy-12", "etsi-8", "standard", "ETSI-8", "etsi-8 "} {
		format, err := ParseTimestampFormat(value)
		valid := value == "" || value == "legacy-12" || value == "etsi-8"
		if valid {
			require.NoError(t, err)
			if value == "" {
				require.Equal(t, TimestampFormatLegacy12, format)
			} else {
				require.Equal(t, TimestampFormat(value), format)
			}
		} else {
			require.ErrorIs(t, err, ErrTimestampFormat)
		}
		x2, x2err := NewX2EncoderWithTimestampFormat(nil, "", "", TimestampFormat(value))
		x3, x3err := NewX3EncoderWithTimestampFormat(nil, "", "", TimestampFormat(value))
		rad, raderr := NewRADIUSEncoderWithTimestampFormat(nil, "", "", "", TimestampFormat(value))
		if valid {
			require.NoError(t, x2err)
			require.NoError(t, x3err)
			require.NoError(t, raderr)
			require.Equal(t, format, x2.timestampFormat)
			require.Equal(t, format, x3.timestampFormat)
			require.Equal(t, format, rad.timestampFormat)
		} else {
			require.ErrorIs(t, x2err, ErrTimestampFormat)
			require.ErrorIs(t, x3err, ErrTimestampFormat)
			require.ErrorIs(t, raderr, ErrTimestampFormat)
			require.Nil(t, x2)
			require.Nil(t, x3)
			require.Nil(t, rad)
			wire, err := (Timestamp{}).MarshalBinaryWithFormat(TimestampFormat(value))
			require.ErrorIs(t, err, ErrTimestampFormat)
			require.Nil(t, wire)
			attr, err := NewAttributeBuilder().TimestampWithFormat(time.Unix(0, 0), TimestampFormat(value))
			require.ErrorIs(t, err, ErrTimestampFormat)
			require.Empty(t, attr)
		}
	}
}

func conformancePacket(timestamp time.Time, rtp bool) *types.PacketDisplay {
	return &types.PacketDisplay{
		Timestamp: timestamp,
		SrcIP:     "192.0.2.1", DstIP: "198.51.100.1", SrcPort: "5060", DstPort: "5060",
		RawData:  append([]byte(nil), goldenRTP...),
		VoIPData: &types.VoIPMetadata{CallID: "conformance@example.test", IsRTP: rtp, SSRC: 0xdeadbeef, RawSIP: []byte(goldenINVITE)},
	}
}

func TestEncoderTimestampFormatsAndBoundaries(t *testing.T) {
	for _, name := range []string{"sip_x2", "rtp_x3", "radius_x2"} {
		for _, format := range []TimestampFormat{TimestampFormatLegacy12, TimestampFormatETSI8} {
			t.Run(name+"/"+string(format), func(t *testing.T) {
				sequencer := NewSequencer(0)
				x2, err := NewX2EncoderWithTimestampFormat(sequencer, "", "", format)
				require.NoError(t, err)
				x3, err := NewX3EncoderWithTimestampFormat(sequencer, "", "", format)
				require.NoError(t, err)
				rad, err := NewRADIUSEncoderWithTimestampFormat(sequencer, "", "", "", format)
				require.NoError(t, err)
				encode := func(timestamp time.Time) (*PDU, error) {
					switch name {
					case "sip_x2":
						return x2.EncodeIRIWithPolicyAndCorrelationID(conformancePacket(timestamp, false), goldenXID, SIPContentFull, goldenCorr)
					case "rtp_x3":
						return x3.EncodeCCWithCorrelationID(conformancePacket(timestamp, true), goldenXID, goldenCorr)
					default:
						observation := radiusEncoderObservation(t)
						observation.Capture.Timestamp = timestamp
						return rad.Encode(observation, goldenXID, goldenCorr)
					}
				}
				// Invalid standard seconds must be rejected before allocating a
				// sequence context, with no product or format fallback.
				if format == TimestampFormatETSI8 {
					for _, seconds := range []int64{-1, math.MaxUint32 + 1} {
						pdu, err := encode(time.Unix(seconds, 0))
						require.ErrorIs(t, err, ErrTimestampRange)
						require.Nil(t, pdu)
						require.Zero(t, sequencer.Len())
					}
				}
				for index, seconds := range []int64{0, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32} {
					timestamp := time.Unix(seconds, 999999999)
					pdu, err := encode(timestamp)
					require.NoError(t, err)
					attr := FindAttribute(pdu.Attributes, AttrTimestamp)
					require.NotNil(t, attr)
					size := LegacyTimestampSize
					if format == TimestampFormatETSI8 {
						size = StandardTimestampSize
					}
					require.Len(t, attr.Value, size)
					got, err := NewAttributeParser().ParseTimestamp(attr)
					require.NoError(t, err)
					require.Equal(t, timestamp, got)
					require.Equal(t, uint32(index), binary.BigEndian.Uint32(FindAttribute(pdu.Attributes, AttrSequenceNumber).Value))
				}
			})
		}
	}
}

func TestEncoderTimestampFormatsAreIndependent(t *testing.T) {
	selected := TimestampFormatETSI8
	x2, err := NewX2EncoderWithTimestampFormat(nil, "", "", selected)
	require.NoError(t, err)
	x3, err := NewX3EncoderWithTimestampFormat(nil, "", "", selected)
	require.NoError(t, err)
	rad, err := NewRADIUSEncoderWithTimestampFormat(nil, "", "", "", selected)
	require.NoError(t, err)
	selected = TimestampFormatLegacy12
	legacyX2 := NewX2Encoder()
	legacyX3 := NewX3Encoder()
	legacyRADIUS := NewRADIUSEncoder(nil, "", "", "")
	for _, format := range []TimestampFormat{x2.timestampFormat, x3.timestampFormat, rad.timestampFormat} {
		require.Equal(t, TimestampFormatETSI8, format)
	}
	for _, format := range []TimestampFormat{legacyX2.timestampFormat, legacyX3.timestampFormat, legacyRADIUS.timestampFormat} {
		require.Equal(t, selected, format)
	}
	for _, encoder := range []*X2Encoder{x2, legacyX2, x2} {
		pdu, err := encoder.EncodeIRI(conformancePacket(goldenTS, false), goldenXID)
		require.NoError(t, err)
		want := StandardTimestampSize
		if encoder == legacyX2 {
			want = LegacyTimestampSize
		}
		require.Len(t, FindAttribute(pdu.Attributes, AttrTimestamp).Value, want)
	}
}
