package statusclient

import (
	"encoding/json"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/admissiontelemetry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestAdmissionTelemetryTransportAndJSON(t *testing.T) {
	s := mediaadmission.Snapshot{Enabled: true, ConfiguredMode: mediaadmission.ModeShadow, EndpointCapacity: 20, Scopes: []mediaadmission.ScopeTelemetry{{ScopeStatus: mediaadmission.ScopeStatus{Domain: 2, State: mediaadmission.StateControlFailed, ControlUncertain: true, DesiredGeneration: 5, InstalledGeneration: 4, Reason: "sensitive-value", PendingUpdates: 3, DegradedDuration: 123, Uncertainty: mediaadmission.UncertaintyStats{UnknownCalls: 2, Reasons: [mediaadmission.UncertaintyReasonCount]uint64{mediaadmission.ReasonFaultyPRACK: 2}, IdenticalDuplicates: 8, ConflictingDuplicates: 3}}, Counters: [16]uint64{0: 11, 11: 7}}}, Metadata: mediaadmission.MetadataStats{Expired: 6}, Evidence: mediaadmission.EvidenceStats{ReadErrors: 1, Incomplete: true}}
	stats := admissiontelemetry.ToProto(s)
	wire, err := proto.Marshal(&management.HunterStats{RtpEbpf: stats})
	require.NoError(t, err)
	var decoded management.HunterStats
	require.NoError(t, proto.Unmarshal(wire, &decoded))
	require.Equal(t, uint64(11), decoded.RtpEbpf.Scopes[0].DecisionCounters[0])
	require.NotContains(t, decoded.RtpEbpf.Scopes[0].Reason, "sensitive")
	bytes, err := HuntersToJSON([]*management.ConnectedHunter{{HunterId: "h", Stats: &decoded}}, false)
	require.NoError(t, err)
	require.Contains(t, string(bytes), "rtp_ebpf")
	require.Contains(t, string(bytes), "control-failed")
	require.Contains(t, string(bytes), `"unknown_calls":2`)
	require.Contains(t, string(bytes), `"faulty_prack":2`)
	require.Contains(t, string(bytes), `"degraded_duration_ns":123`)
	bytes, err = StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{RtpEbpf: stats}}, false)
	require.NoError(t, err)
	var object map[string]any
	require.NoError(t, json.Unmarshal(bytes, &object))
	require.Contains(t, object, "rtp_ebpf")
	bytes, err = StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, false)
	require.NoError(t, err)
	require.NotContains(t, string(bytes), "rtp_ebpf")
}
