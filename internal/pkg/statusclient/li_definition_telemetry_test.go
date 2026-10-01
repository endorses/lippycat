package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLIDefinitionTelemetrySurvivesWireAndStatusJSON(t *testing.T) {
	original := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{
		LiDefinitions: &management.LIDefinitionStats{Incomplete: 2, PullOnly: 3, Conflicts: 5, UnknownWindows: 7, OpenEnded: 11, Repairs: 13},
	}}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)
	var decoded management.StatusResponse
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.True(t, proto.Equal(original, &decoded))
	require.EqualValues(t, 15, decoded.ProcessorStats.ProtoReflect().Descriptor().Fields().ByName("li_definitions").Number())
	for _, pretty := range []bool{false, true} {
		data, err := StatusResponseToJSON(&decoded, pretty)
		require.NoError(t, err)
		var public map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &public))
		require.JSONEq(t, `{"incomplete":2,"pull_only":3,"conflicts":5,"unknown_windows":7,"open_ended":11,"repairs":13}`, string(public["li_definitions"]))
	}
	data, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, false)
	require.NoError(t, err)
	require.NotContains(t, string(data), "li_definitions")
}
