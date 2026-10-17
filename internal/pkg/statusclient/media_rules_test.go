package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestMediaAndDuplicateStatusTransportAndJSON(t *testing.T) {
	media := &management.MediaRuleStatus{Enabled: true, Ready: true, Generation: 3, Revision: 7, Sequence: 9, Rules: 2, Endpoints: 4, Bytes: 512, Subscribers: 1, Expired: 8, StaleUpdates: 6, Resyncs: 5, ActiveCalls: 2, ApplicationFailed: true}
	duplicates := &management.PacketDuplicateStatus{Attempts: 30, Committed: 10, Duplicates: 3, InFlight: 1, RepeatsRetained: 2, UnsupportedRetained: 4, AmbiguousRetained: 5, CapacityRetained: 6, OutsideWindowRetained: 7, Aborted: 8, Entries: 9, Contributors: 10, Bytes: 4096}
	input := &management.StatusResponse{ProcessorStats: &management.ProcessorStats{MediaRules: media, PacketDuplicates: duplicates}}
	encoded, err := proto.Marshal(input)
	require.NoError(t, err)
	var received management.StatusResponse
	require.NoError(t, proto.Unmarshal(encoded, &received))
	for _, pretty := range []bool{false, true} {
		body, err := StatusResponseToJSON(&received, pretty)
		require.NoError(t, err)
		var object map[string]any
		require.NoError(t, json.Unmarshal(body, &object))
		status := object["media_rules"].(map[string]any)
		require.Equal(t, true, status["ready"])
		require.EqualValues(t, 7, status["revision"])
		require.EqualValues(t, 6, status["stale_updates"])
		require.Equal(t, true, status["application_failed"])
		retained := object["packet_duplicates"].(map[string]any)
		for key, want := range map[string]float64{"attempts": 30, "committed": 10, "duplicates": 3, "in_flight": 1, "repeats_retained": 2, "unsupported_retained": 4, "ambiguous_retained": 5, "capacity_retained": 6, "outside_window_retained": 7, "aborted": 8, "entries": 9, "contributors": 10, "bytes": 4096} {
			require.Equal(t, want, retained[key], key)
		}
	}
	hunters, err := HuntersToJSON([]*management.ConnectedHunter{{HunterId: "hunter-a", Stats: &management.HunterStats{MediaRules: media}}}, false)
	require.NoError(t, err)
	var objects []map[string]any
	require.NoError(t, json.Unmarshal(hunters, &objects))
	status := objects[0]["stats"].(map[string]any)["media_rules"].(map[string]any)
	require.Equal(t, true, status["ready"])
	require.EqualValues(t, 7, status["revision"])
}

func TestMediaAndDuplicateStatusUnavailableAndPendingDefaults(t *testing.T) {
	for _, pretty := range []bool{false, true} {
		body, err := StatusResponseToJSON(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{}}, pretty)
		require.NoError(t, err)
		require.NotContains(t, string(body), "media_rules")
		require.NotContains(t, string(body), "packet_duplicates")
	}
	body, err := HuntersToJSON([]*management.ConnectedHunter{{HunterId: "old-peer", Stats: &management.HunterStats{}}}, false)
	require.NoError(t, err)
	require.NotContains(t, string(body), "media_rules")
	body, err = HuntersToJSON([]*management.ConnectedHunter{{HunterId: "pending-peer", Stats: &management.HunterStats{MediaRules: &management.MediaRuleStatus{Enabled: true}}}}, false)
	require.NoError(t, err)
	var pending []map[string]any
	require.NoError(t, json.Unmarshal(body, &pending))
	status := pending[0]["stats"].(map[string]any)["media_rules"].(map[string]any)
	require.Equal(t, true, status["enabled"])
	require.NotContains(t, status, "ready", "a pending application must not claim readiness")
}

func TestMediaAndDuplicateSummariesContainOnlyBoundedCounters(t *testing.T) {
	const secret = "PRIVATE-CALL-SELECTOR-ADDRESS-APPLICATION-ERROR"
	media := &management.MediaRuleStatus{Enabled: true, ApplicationFailed: true}
	// Unknown wire fields survive protobuf transport but must not be promoted to
	// operator JSON as raw source/application diagnostics by compatibility code.
	unknown := protowire.AppendTag(nil, 500, protowire.BytesType)
	unknown = protowire.AppendString(unknown, secret)
	media.ProtoReflect().SetUnknown(unknown)
	duplicates := &management.PacketDuplicateStatus{Duplicates: 1}
	duplicates.ProtoReflect().SetUnknown(unknown)
	for _, message := range []proto.Message{media, duplicates} {
		fields := message.ProtoReflect().Descriptor().Fields()
		for i := 0; i < fields.Len(); i++ {
			field := fields.Get(i)
			require.False(t, field.IsList())
			require.False(t, field.IsMap())
			require.Contains(t, []protoreflect.Kind{protoreflect.BoolKind, protoreflect.Uint64Kind}, field.Kind(), "status must not expose variable-length selectors or raw application errors")
		}
	}
	encoded, err := proto.Marshal(&management.StatusResponse{ProcessorStats: &management.ProcessorStats{MediaRules: media, PacketDuplicates: duplicates}})
	require.NoError(t, err)
	var received management.StatusResponse
	require.NoError(t, proto.Unmarshal(encoded, &received))
	body, err := StatusResponseToJSON(&received, false)
	require.NoError(t, err)
	require.NotContains(t, string(body), secret)
	require.Contains(t, string(body), `"application_failed":true`)
}
