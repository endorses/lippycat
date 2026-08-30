package eventsv1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestProtocolEventPreservesUnknownFields(t *testing.T) {
	t.Parallel()

	original := &ProtocolEvent{
		EventId:       "node/session/1",
		EventSequence: 1,
		Payload:       &ProtocolEvent_Dns{Dns: &DNSEvent{Query: "example.test"}},
	}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)

	unknown := protowire.AppendTag(nil, 100, protowire.BytesType)
	unknown = protowire.AppendString(unknown, "future-event-data")
	wire = append(wire, unknown...)

	decoded := new(ProtocolEvent)
	require.NoError(t, proto.Unmarshal(wire, decoded))
	require.IsType(t, &ProtocolEvent_Dns{}, decoded.GetPayload())
	require.Equal(t, unknown, []byte(decoded.ProtoReflect().GetUnknown()))

	reencoded, err := proto.Marshal(decoded)
	require.NoError(t, err)
	roundTripped := new(ProtocolEvent)
	require.NoError(t, proto.Unmarshal(reencoded, roundTripped))
	require.Equal(t, unknown, []byte(roundTripped.ProtoReflect().GetUnknown()))
}

func TestProtocolEventUnknownPayloadIsAnOmission(t *testing.T) {
	t.Parallel()

	// Field 99 represents a payload alternative added by a future API-compatible
	// producer. Older generated code retains it while exposing no known payload.
	wire := protowire.AppendTag(nil, 99, protowire.BytesType)
	wire = protowire.AppendBytes(wire, []byte{1, 2, 3})

	decoded := new(ProtocolEvent)
	require.NoError(t, proto.Unmarshal(wire, decoded))
	require.Nil(t, decoded.GetPayload())
	require.Equal(t, wire, []byte(decoded.ProtoReflect().GetUnknown()))
}
