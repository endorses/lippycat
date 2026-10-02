package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLIReconciliationSurvivesWireAndStatusJSON(t *testing.T) {
	original := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{LiReconciliation: &management.LIReconciliationStats{
		Source: "startup", State: "partial", Attempts: 3, LastAttempt: "2026-10-01T12:00:00Z",
		TaskFailures: 33, DestinationFailures: 1, TotalFailures: 34, FailuresTruncated: 2,
		TaskOrphanRemovalSuppressed: true, DestinationOrphanRemovalSuppressed: true, WarningsSuppressed: 2,
		Failures: []*management.LIReconciliationFailure{{Kind: "task", Category: "conversion_failed", EntryIndex: 0, Uuid: uuid.NewString()}, {Kind: "destination", Category: "missing_list", EntryIndex: -1}},
	}}}
	wire, err := proto.Marshal(original)
	require.NoError(t, err)
	var decoded management.StatusResponse
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.True(t, proto.Equal(original, &decoded))
	for _, pretty := range []bool{false, true} {
		data, err := StatusResponseToJSON(&decoded, pretty)
		require.NoError(t, err)
		var public map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &public))
		var diagnostics management.LIReconciliationStats
		require.NoError(t, json.Unmarshal(public["li_reconciliation"], &diagnostics))
		require.True(t, proto.Equal(original.ProcessorStats.LiReconciliation, &diagnostics))
	}
	data, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, false)
	require.NoError(t, err)
	require.NotContains(t, string(data), "li_reconciliation")
}
