package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCallCorrelationStatusWireAndJSON(t *testing.T) {
	stats := &management.LICallCorrelationStats{
		Storage: &management.StorageStatus{Mode: "encrypted", State: "ready", ActiveKeyId: "correlation-1", PriorKeyIds: []string{"correlation-0"}, Commits: 2, Uncertain: 3, KeyUsage: &management.EncryptionUsageStats{ReservedInvocations: 4, ReservedBlocks: 5}},
		Adopted: map[string]uint64{"H": 1}, Standalone: map[string]uint64{"blind": 2}, Sdp: map[string]uint64{"unusable": 3},
		Records: 4, Candidates: 5, Transactions: 6, Origins: 7, SuspendedOrigins: 8, GroupsTwo: 9, GroupsThree: 10, GroupsFourOrMore: 11,
		MaxRecords: 100, MaxCandidates: 200, MaxOrigins: 300, Blind: true, BlindCause: "startup", BlindRemainingNs: 400, Persistence: true, UncertainWrites: 12, UnresolvedWrites: 13, SdpDisabled: true, UnrecordedDecisions: 15,
	}
	sent := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{LiCallCorrelation: stats}}
	wire, err := proto.Marshal(sent)
	require.NoError(t, err)
	var decoded management.StatusResponse
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.True(t, proto.Equal(sent, &decoded))
	for _, pretty := range []bool{false, true} {
		data, err := StatusResponseToJSON(&decoded, pretty)
		require.NoError(t, err)
		var document map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &document))
		var got management.LICallCorrelationStats
		require.NoError(t, json.Unmarshal(document["li_call_correlation"], &got))
		require.True(t, proto.Equal(stats, &got))
		for _, private := range []string{"call_id", "session_id", "from_tag", "source_address", "headers"} {
			require.NotContains(t, string(document["li_call_correlation"]), private)
		}
	}
}
func TestCallCorrelationStatusAbsentWhenDisabled(t *testing.T) {
	for _, pretty := range []bool{false, true} {
		data, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, pretty)
		require.NoError(t, err)
		require.NotContains(t, string(data), "li_call_correlation")
	}
}
