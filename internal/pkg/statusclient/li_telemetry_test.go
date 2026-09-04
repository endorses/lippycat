package statusclient

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusResponseToJSONIncludesOptionalLITelemetry(t *testing.T) {
	data, err := StatusResponseToJSON(&management.StatusResponse{
		ProcessorStats: &management.ProcessorStats{
			LiEncoding: &management.LIEncodingStats{
				X3FinalizedOrStaleSuppressed: 3,
				X3BufferedDiscarded:          5,
			},
		},
	}, false)
	require.NoError(t, err)
	assert.JSONEq(t, `{"processor_id":"","status":"healthy","total_hunters":0,"healthy_hunters":0,"warning_hunters":0,"error_hunters":0,"total_packets_received":0,"total_packets_forwarded":0,"total_filters":0,"li_encoding":{"x3_finalized_or_stale_suppressed":3,"x3_buffered_discarded":5}}`, string(data))
}

func TestStatusResponseToJSONOmitsLITelemetryWhenUnavailable(t *testing.T) {
	data, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, false)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "li_encoding")
}
