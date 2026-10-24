package data

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestSMSMetadataWireCompatibility(t *testing.T) {
	// This descriptor represents a peer predating SIPMetadata.sms. Unlike a
	// round trip through the new generated type, it cannot interpret field 17.
	legacyFile := protodesc.ToFileDescriptorProto(File_data_proto)
	for _, message := range legacyFile.MessageType {
		if message.GetName() != "SIPMetadata" {
			continue
		}
		fields := message.Field[:0]
		for _, field := range message.Field {
			if field.GetNumber() != 17 {
				fields = append(fields, field)
			}
		}
		message.Field = fields
	}
	descriptor, err := protodesc.NewFile(legacyFile, protoregistry.GlobalFiles)
	require.NoError(t, err)
	legacy := dynamicpb.NewMessage(descriptor.Messages().ByName("SIPMetadata"))
	require.Nil(t, legacy.Descriptor().Fields().ByNumber(17))

	original := &SIPMetadata{CallId: "sms", Method: "MESSAGE", Sms: &SMSMetadata{Status: SMSMetadata_DECODE_STATUS_DECODED, Text: "A € message", Encoding: SMSMetadata_ENCODING_GSM7, Concat: &SMSMetadata_Concatenation{Reference: 17, ReferenceBits: 8, Total: 2, Part: 2}, Assembly: &SMSMetadata_Assembly{Id: "opaque-capture-id", Status: SMSMetadata_ASSEMBLY_STATUS_COMPLETE, Text: "Full A € message", Received: []uint32{1, 2}}}}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)
	require.NoError(t, proto.Unmarshal(wire, legacy))
	require.Equal(t, "MESSAGE", legacy.Get(legacy.Descriptor().Fields().ByName("method")).String())
	require.NotEmpty(t, legacy.GetUnknown())
	forwarded, err := proto.Marshal(legacy)
	require.NoError(t, err)
	var restored SIPMetadata
	require.NoError(t, proto.Unmarshal(forwarded, &restored))
	require.True(t, proto.Equal(original, &restored), "an older relay preserves unknown SMS metadata")

	// An older terminal consumer can intentionally ignore the new record.
	require.NoError(t, (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, legacy))
	require.Empty(t, legacy.GetUnknown())
}

func TestSMSMetadataAbsentAndEmptyTextRemainDistinct(t *testing.T) {
	// Wire bytes only contain preexisting method and Call-ID fields.
	wire := []byte{0x0a, 7, 'M', 'E', 'S', 'S', 'A', 'G', 'E', 0x12, 3, 'o', 'l', 'd'}
	var decoded SIPMetadata
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.Nil(t, decoded.Sms)
	for _, status := range []SMSMetadata_DecodeStatus{SMSMetadata_DECODE_STATUS_UNSPECIFIED, SMSMetadata_DECODE_STATUS_DECODED, SMSMetadata_DECODE_STATUS_CONTROL, SMSMetadata_DECODE_STATUS_UNSUPPORTED} {
		original := &SIPMetadata{Sms: &SMSMetadata{Status: status}}
		wire, err := proto.Marshal(original)
		require.NoError(t, err)
		require.NoError(t, proto.Unmarshal(wire, &decoded))
		require.NotNil(t, decoded.Sms)
		require.Empty(t, decoded.Sms.Text)
		require.Equal(t, status, decoded.Sms.Status)
	}
}
