//go:build li

package x2x3

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestPhase5CaptureTimestampAndCorrelationWireInvariant(t *testing.T) {
	xid := uuid.New()
	capturedAt := time.Date(2026, time.August, 24, 12, 34, 56, 789123456, time.UTC)
	const callID = "reused-call-id@example.net"
	sip := &types.PacketDisplay{
		Timestamp: capturedAt,
		RawData:   []byte("INVITE sip:bob@example.net SIP/2.0\r\nCall-ID: " + callID + "\r\n\r\n"),
		VoIPData:  &types.VoIPMetadata{CallID: callID, Method: "INVITE"},
	}
	x2PDU, err := NewX2Encoder().EncodeSessionBegin(sip, xid)
	require.NoError(t, err)
	x2Wire, err := x2PDU.MarshalBinary()
	require.NoError(t, err)
	var decodedX2 PDU
	require.NoError(t, decodedX2.UnmarshalBinary(x2Wire))
	parser := NewAttributeParser()
	x2Timestamp, err := parser.ParseTimestamp(FindAttribute(decodedX2.Attributes, AttrTimestamp))
	require.NoError(t, err)
	require.Equal(t, capturedAt.UnixNano(), x2Timestamp.UnixNano())

	for _, media := range []struct {
		ssrc        uint32
		src, dst    string
		description string
	}{
		{0x11111111, "192.0.2.10", "198.51.100.20", "caller to callee"},
		{0x22222222, "198.51.100.20", "192.0.2.10", "callee to caller"},
		{0x33333333, "192.0.2.30", "198.51.100.40", "re-INVITE media"},
		{0x44444444, "203.0.113.50", "203.0.113.60", "Call-ID reuse"},
	} {
		t.Run(media.description, func(t *testing.T) {
			rtp := &types.PacketDisplay{
				Timestamp: capturedAt,
				SrcIP:     media.src,
				DstIP:     media.dst,
				RawData:   []byte{0x80, 0x00},
				VoIPData:  &types.VoIPMetadata{IsRTP: true, CallID: callID, SSRC: media.ssrc},
			}
			x3PDU, encodeErr := NewX3Encoder().EncodeCC(rtp, xid)
			require.NoError(t, encodeErr)
			x3Wire, marshalErr := x3PDU.MarshalBinary()
			require.NoError(t, marshalErr)
			var decodedX3 PDU
			require.NoError(t, decodedX3.UnmarshalBinary(x3Wire))
			require.Equal(t, decodedX2.Header.CorrelationID, decodedX3.Header.CorrelationID)
			x3Timestamp, parseErr := parser.ParseTimestamp(FindAttribute(decodedX3.Attributes, AttrTimestamp))
			require.NoError(t, parseErr)
			require.Equal(t, capturedAt.UnixNano(), x3Timestamp.UnixNano())
		})
	}
}
