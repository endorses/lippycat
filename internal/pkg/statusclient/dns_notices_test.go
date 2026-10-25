package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestDNSNoticeStatusJSONPreservesDecisionAndOutcomeBoundaries(t *testing.T) {
	input := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{DnsNotices: &management.DNSNoticeStats{Enabled: true, Emitted: 3, Suppressed: 9, Dropped: 1, CommandCompleted: 1, CommandFailed: 1, LogErrors: 2}}}
	encoded, err := StatusResponseToJSON(input, false)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	notices := decoded["dns_notices"].(map[string]any)
	require.Equal(t, float64(3), notices["emitted"])
	require.Equal(t, float64(9), notices["suppressed"])
	require.Equal(t, float64(1), notices["command_failed"])
	require.Equal(t, float64(2), notices["log_errors"])
	input.ProcessorStats.DnsNotices = nil
	encoded, err = StatusResponseToJSON(input, false)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "dns_notices")
}
