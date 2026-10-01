package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLIStartupSyncSurvivesWireAndStatusJSON(t *testing.T) {
	for _, state := range []string{"pending", "retryable_failure", "succeeded", "unsupported"} {
		t.Run(state, func(t *testing.T) {
			original := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{
				LiStartupSync: &management.LIStartupSyncStats{
					State: state, Attempts: 3, LastFailure: "ADMF synchronization timed out",
					LastAttempt: "2026-10-01T12:00:00Z", RecoveredAt: "2026-10-01T12:00:01Z",
				},
			}}
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
				var sync management.LIStartupSyncStats
				require.NoError(t, json.Unmarshal(public["li_startup_sync"], &sync))
				require.True(t, proto.Equal(original.ProcessorStats.LiStartupSync, &sync))
			}
		})
	}
	data, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, false)
	require.NoError(t, err)
	require.NotContains(t, string(data), "li_startup_sync")
}
