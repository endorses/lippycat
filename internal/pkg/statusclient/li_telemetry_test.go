package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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
	assert.NotContains(t, string(data), "li_delivery")
}

func TestLIDeliveryTelemetrySurvivesWireAndStatusJSON(t *testing.T) {
	response := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{
		LiDelivery: &management.LIDeliveryStats{
			X2EnqueueCalls: 4, X3EnqueueCalls: 5,
			X2Written: 6, X3Written: 7, X2Dropped: 1, X3Dropped: 2,
			Retries: 3, QueueDepth: 8,
			Destinations: map[string]*management.LIDestinationDeliveryStats{
				"destination-uuid": {
					X2QueueDepth: 2, X3QueueDepth: 6,
					X2QueueCapacity: 100, X3QueueCapacity: 100,
					DroppedByReason:   map[string]uint64{"queue_overflow": 2},
					OldestQueuedAgeMs: 1500, LastWriteUnixMs: 1700000000000,
					ConnectionState: "disconnected", LastConnectionError: "connection refused",
					X2Keepalive: &management.LIInterfaceKeepaliveStats{
						Enabled: true, TimeoutMs: 3000, Timeouts: 1, ReconnectReason: "ack timeout",
					},
					X3Keepalive: &management.LIInterfaceKeepaliveStats{Enabled: true, Acknowledged: 9},
				},
			},
		},
	}}
	wire, err := proto.Marshal(response)
	require.NoError(t, err)
	var received management.StatusResponse
	require.NoError(t, proto.Unmarshal(wire, &received))

	for _, pretty := range []bool{false, true} {
		body, err := StatusResponseToJSON(&received, pretty)
		require.NoError(t, err)
		var got map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &got))
		require.Contains(t, got, "li_delivery")
		assert.JSONEq(t, `{
			"x2_enqueue_calls":4,"x3_enqueue_calls":5,
			"x2_written":6,"x3_written":7,"x2_dropped":1,"x3_dropped":2,
			"retries":3,"queue_depth":8,
			"destinations":{"destination-uuid":{
				"x2_queue_depth":2,"x3_queue_depth":6,
				"x2_queue_capacity":100,"x3_queue_capacity":100,
				"dropped_by_reason":{"queue_overflow":2},
				"oldest_queued_age_ms":1500,"last_write_unix_ms":1700000000000,
				"connection_state":"disconnected","last_connection_error":"connection refused",
				"x2_keepalive":{"enabled":true,"timeout_ms":3000,"timeouts":1,"reconnect_reason":"ack timeout"},
				"x3_keepalive":{"enabled":true,"acknowledged":9}
			}}
		}`, string(got["li_delivery"]))
	}
}
