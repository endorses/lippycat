package admissiontelemetry

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestSampledTelemetryProjectionAndCompatibility(t *testing.T) {
	snapshot := mediaadmission.Snapshot{Evidence: mediaadmission.EvidenceStats{SampleEvery: 7, KernelLost: 2, Overwritten: 3, Malformed: 4, ReadErrors: 5}, Shadow: mediaadmission.ShadowStats{Preselection: 6, PublicationWindow: 7, RejectedAfterPublication: 8, Admitted: 9, Incomplete: 10, Ambiguous: 11, TooLarge: 12, Late: 13, TrackingRejected: 14, Pending: 15}, Media: mediaadmission.MediaDiagnostics{UnknownExpectation: 16, InactiveSelected: 17, Alerts: 18}}
	got := ToProto(snapshot)
	require.Equal(t, uint64(7), got.ShadowSampleEvery)
	require.Equal(t, uint64(2), got.EvidenceKernelLost)
	require.Equal(t, uint64(8), got.SampledRejectedAfterPublication)
	require.Equal(t, uint64(10), got.SampledIncomplete)
	require.Equal(t, uint64(16), got.MediaExpectationUnknown)
	require.Equal(t, uint64(17), got.MediaExpectationInactive)
	raw, err := proto.Marshal(got)
	require.NoError(t, err)
	decoded := proto.Clone(got)
	proto.Reset(decoded)
	require.NoError(t, proto.Unmarshal(raw, decoded))
	require.True(t, proto.Equal(got, decoded))
	require.Zero(t, ToProto(mediaadmission.Snapshot{}).SampledRejectedAfterPublication, "older snapshots retain zero-valued additive fields")
}
