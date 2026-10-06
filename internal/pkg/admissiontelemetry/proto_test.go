package admissiontelemetry

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
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

func TestUncertaintyTelemetryProjection(t *testing.T) {
	u := mediaadmission.UncertaintyStats{UnknownCalls: 2, IdenticalDuplicates: 8, ConflictingDuplicates: 3, MalformedRSeq: 4, MalformedRAck: 5, ReplayGuards: 6, ReplayGuardCapacity: 10, ReplayGuardBytes: 768, ReplayGuardByteLimit: 1280, ReplayWindowNanos: 32000000000, ReplayUnrecorded: 7, ReplayDegradedNanos: 8000000000}
	for i := range u.Reasons {
		u.Reasons[i] = uint64(i + 1)
	}
	snapshot := mediaadmission.Snapshot{Scopes: []mediaadmission.ScopeTelemetry{{ScopeStatus: mediaadmission.ScopeStatus{Uncertainty: u, DegradedDuration: 123}}}}
	wire := ToProto(snapshot)
	got := wire.Scopes[0]
	require.Equal(t, uint64(123), got.DegradedDurationNs)
	require.Equal(t, uint64(2), got.Uncertainty.UnknownCalls)
	require.Equal(t, uint64(1), got.Uncertainty.ConflictingHeaders)
	require.Equal(t, uint64(2), got.Uncertainty.FaultyPrack)
	require.Equal(t, uint64(3), got.Uncertainty.PartialSdp)
	require.Equal(t, uint64(4), got.Uncertainty.DelayedOffer)
	require.Equal(t, uint64(5), got.Uncertainty.ForkAmbiguity)
	require.Equal(t, uint64(6), got.Uncertainty.EvidenceLoss)
	require.Equal(t, uint64(8), got.Uncertainty.IdenticalDuplicates)
	require.Equal(t, uint64(3), got.Uncertainty.ConflictingDuplicates)
	require.Equal(t, uint64(4), got.Uncertainty.MalformedRseq)
	require.Equal(t, uint64(5), got.Uncertainty.MalformedRack)
	require.Equal(t, uint64(6), got.Uncertainty.ReplayGuards)
	require.Equal(t, uint64(10), got.Uncertainty.ReplayGuardCapacity)
	require.Equal(t, uint64(768), got.Uncertainty.ReplayGuardBytes)
	require.Equal(t, uint64(1280), got.Uncertainty.ReplayGuardByteLimit)
	require.Equal(t, uint64(32000000000), got.Uncertainty.ReplayWindowNs)
	require.Equal(t, uint64(7), got.Uncertainty.ReplayUnrecorded)
	require.Equal(t, uint64(8000000000), got.Uncertainty.ReplayDegradedNs)
	raw, err := proto.Marshal(wire)
	require.NoError(t, err)
	decoded := proto.Clone(wire)
	proto.Reset(decoded)
	require.NoError(t, proto.Unmarshal(raw, decoded))
	require.True(t, proto.Equal(wire, decoded))
}

func TestReplayDiagnosticsAdditiveWireCompatibility(t *testing.T) {
	// Reconstruct the previously published uncertainty descriptor with fields
	// 1–9 only, so compatibility is checked against an actual older wire reader.
	current := (&management.MediaAdmissionUncertainty{}).ProtoReflect().Descriptor()
	legacyMessage := protodesc.ToDescriptorProto(current)
	legacyMessage.Field = legacyMessage.Field[:9]
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("legacy_admission.proto"), Package: proto.String("legacy"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{legacyMessage},
	}, nil)
	require.NoError(t, err)
	legacy := dynamicpb.NewMessage(file.Messages().Get(0))
	currentMessage := &management.MediaAdmissionUncertainty{UnknownCalls: 2, MalformedRseq: 4, MalformedRack: 5, ReplayGuards: 6, ReplayWindowNs: 32000000000, ReplayDegradedNs: 8000000000}
	raw, err := proto.Marshal(currentMessage)
	require.NoError(t, err)
	require.NoError(t, proto.Unmarshal(raw, legacy))
	require.Equal(t, uint64(2), legacy.Get(legacy.Descriptor().Fields().ByName("unknown_calls")).Uint())
	require.NotEmpty(t, legacy.GetUnknown(), "older peers preserve additive fields without interpreting them")
	forwarded, err := proto.Marshal(legacy)
	require.NoError(t, err)
	var decoded management.MediaAdmissionUncertainty
	require.NoError(t, proto.Unmarshal(forwarded, &decoded))
	require.True(t, proto.Equal(currentMessage, &decoded))

	// A response from the old peer has none of the new fields. Zero and absent
	// values leave replay configuration unknown rather than inventing a bound.
	legacy.Reset()
	legacy.Set(legacy.Descriptor().Fields().ByName("unknown_calls"), protoreflect.ValueOfUint64(2))
	raw, err = proto.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, proto.Unmarshal(raw, &decoded))
	require.Equal(t, uint64(2), decoded.UnknownCalls)
	require.Zero(t, decoded.ReplayWindowNs)
	require.Zero(t, decoded.MalformedRseq)
}
