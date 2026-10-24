package grpcadapter

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func smsFixture() *sms.Message {
	return &sms.Message{Text: "Part €", Status: sms.StatusDecoded, Encoding: sms.EncodingGSM7, Direction: sms.DirectionMT, RPType: 1, TPType: 0, Reference: 17, DCS: 0, PID: 0, From: "+491234", Timestamp: time.Unix(1720000000, 0).UTC(), Concat: &sms.Concatenation{Reference: 513, ReferenceBits: 16, Total: 2, Part: 2}, Header: []byte{5, 4, 1, 2, 3, 4}, Assembly: sms.AssemblyInfo{ID: "scope-id", Status: sms.AssemblyComplete, Text: "Full Part €", Received: []uint8{1, 2}}}
}

func TestSMSAdapterRoundTripAndOwnership(t *testing.T) {
	original := smsFixture()
	encoded := ToProtoSMS(original)
	wire, err := proto.Marshal(encoded)
	require.NoError(t, err)
	var received data.SMSMetadata
	require.NoError(t, proto.Unmarshal(wire, &received))
	result := FromProtoSMS(&received)
	require.Equal(t, original, result)
	original.Header[0] = 99
	original.Concat.Part = 1
	original.Assembly.Received[0] = 99
	require.EqualValues(t, 5, encoded.Header[0])
	require.EqualValues(t, 2, encoded.Concat.Part)
	require.EqualValues(t, 1, encoded.Assembly.Received[0])
	received.Header[0] = 99
	received.Concat.Part = 1
	received.Assembly.Received[0] = 99
	require.EqualValues(t, 5, result.Header[0])
	require.EqualValues(t, 2, result.Concat.Part)
	require.EqualValues(t, 1, result.Assembly.Received[0])
	require.Nil(t, ToProtoSMS(nil))
	require.Nil(t, FromProtoSMS(nil))
	require.Equal(t, &sms.Message{}, FromProtoSMS(&data.SMSMetadata{}))
}

func TestSMSMetadataSurvivesPipelineRelayAndTapConversion(t *testing.T) {
	original := &data.PacketBatch{HunterId: "tap", Packets: []*data.CapturedPacket{{TimestampNs: 1, Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "sms-call", Method: "MESSAGE", Sms: ToProtoSMS(smsFixture())}}}}}
	current := original
	for range 2 {
		normalized, err := FromPacketBatch(current)
		require.NoError(t, err)
		current, err = ToPacketBatch(normalized)
		require.NoError(t, err)
		require.True(t, proto.Equal(original, current))
	}
	current.Packets[0].Metadata.Sip.Sms.Assembly.Received[0] = 99
	require.EqualValues(t, 1, original.Packets[0].Metadata.Sip.Sms.Assembly.Received[0])
}

func TestSMSAdapterInvalidAndFutureClaims(t *testing.T) {
	for _, message := range []*data.SMSMetadata{
		{Text: "claim", RpType: 256},
		{Text: "claim", Dcs: 256},
		{Text: "claim", Concat: &data.SMSMetadata_Concatenation{ReferenceBits: 8, Reference: 256, Total: 2, Part: 1}},
		{Text: "claim", Assembly: &data.SMSMetadata_Assembly{Status: data.SMSMetadata_ASSEMBLY_STATUS_COMPLETE, Text: "invalid", Received: []uint32{256}}},
	} {
		decoded := FromProtoSMS(message)
		require.Equal(t, sms.StatusMalformed, decoded.Status)
		require.Empty(t, decoded.Text)
		require.Empty(t, decoded.Assembly.Text)
	}
	decoded := FromProtoSMS(&data.SMSMetadata{Status: 999, Encoding: 999, Direction: 999, Assembly: &data.SMSMetadata_Assembly{Status: 999}})
	require.Empty(t, decoded.Status)
	require.Empty(t, decoded.Encoding)
	require.Empty(t, decoded.Direction)
	require.Empty(t, decoded.Assembly.Status)
	invalid := &sms.Message{Status: sms.StatusDecoded, Text: string([]byte{0xff})}
	encoded := ToProtoSMS(invalid)
	require.Equal(t, data.SMSMetadata_DECODE_STATUS_MALFORMED, encoded.Status)
	require.Empty(t, encoded.Text)
	_, err := proto.Marshal(encoded)
	require.NoError(t, err)
}

func TestSMSAdapterPreservesEveryDefinedStatus(t *testing.T) {
	for _, status := range []sms.DecodeStatus{"", sms.StatusDecoded, sms.StatusControl, sms.StatusUnsupported, sms.StatusMalformed, sms.StatusIncomplete} {
		require.Equal(t, status, FromProtoSMS(ToProtoSMS(&sms.Message{Status: status})).Status)
	}
	for _, encoding := range []sms.Encoding{"", sms.EncodingGSM7, sms.EncodingUCS2, sms.EncodingBinary, sms.EncodingUnknown} {
		require.Equal(t, encoding, FromProtoSMS(ToProtoSMS(&sms.Message{Encoding: encoding})).Encoding)
	}
	for _, direction := range []sms.Direction{"", sms.DirectionMO, sms.DirectionMT, sms.DirectionUnknown} {
		require.Equal(t, direction, FromProtoSMS(ToProtoSMS(&sms.Message{Direction: direction})).Direction)
	}
	for _, status := range []sms.AssemblyStatus{"", sms.AssemblyNone, sms.AssemblyPending, sms.AssemblyComplete, sms.AssemblyConflict, sms.AssemblyExpired, sms.AssemblyResourceLimited} {
		require.Equal(t, status, FromProtoSMS(ToProtoSMS(&sms.Message{Assembly: sms.AssemblyInfo{Status: status}})).Assembly.Status)
	}
}
