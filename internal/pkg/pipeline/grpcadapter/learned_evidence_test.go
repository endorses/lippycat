package grpcadapter

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func evidenceFixture() *evidence.LearnedCaptureEvidence {
	return &evidence.LearnedCaptureEvidence{Version: wire.EvidenceVersion, Candidates: []*evidence.LearnedCandidate{
		{BindingId: "diagnostic-binding", BindingRevision: 1, AdapterId: "diagnostic", ContextVersion: 1, SubjectId: "request", SubjectIncarnation: "request-1", AuthorityId: "processor", AuthorityGeneration: 1, AttributionContext: "diagnostic", Proof: &evidence.LearnedCandidate_ReferenceOnly{ReferenceOnly: true}},
		{BindingId: "media-binding", BindingRevision: 2, AdapterId: "voip", ContextVersion: 1, SubjectId: "selected-call", SubjectIncarnation: "call-1", AuthorityId: "processor", AuthorityGeneration: 1, AttributionContext: "media", Proof: &evidence.LearnedCandidate_LegacyMediaRule{LegacyMediaRule: []byte("original-signed-media-rule")}},
	}}
}

func TestLearnedEvidenceRoundtripOwnsCandidatesAndOriginalProof(t *testing.T) {
	original := evidenceFixture()
	in := &data.CapturedPacket{LearnedCaptureEvidence: proto.Clone(original).(*evidence.LearnedCaptureEvidence), DirectMatchedFilterIds: []string{"independent-filter"}}
	env, err := FromCapturedPacket(in, pipeline.SourceProvenance{})
	require.NoError(t, err)
	in.LearnedCaptureEvidence.Candidates[0].SubjectIncarnation = "reused-subject"
	in.LearnedCaptureEvidence.Candidates[1].GetLegacyMediaRule()[0] = 'x'
	in.LearnedCaptureEvidence.Candidates = append(in.LearnedCaptureEvidence.Candidates, nil)
	require.True(t, proto.Equal(original, env.LearnedCaptureEvidence))
	require.Equal(t, []string{"independent-filter"}, env.DirectMatchedFilterIDs)
	env.CurrentCaptureSelection = func() bool { return false }
	out, err := ToCapturedPacket(env)
	require.NoError(t, err)
	env.LearnedCaptureEvidence.Candidates[0].SubjectId = "another-request"
	env.LearnedCaptureEvidence.Candidates[1].GetLegacyMediaRule()[0] = 'y'
	require.True(t, proto.Equal(original, out.LearnedCaptureEvidence))
	encoded, err := proto.Marshal(out)
	require.NoError(t, err)
	decoded := &data.CapturedPacket{}
	require.NoError(t, proto.Unmarshal(encoded, decoded))
	require.True(t, proto.Equal(original, decoded.LearnedCaptureEvidence))
	final, err := FromCapturedPacket(decoded, pipeline.SourceProvenance{})
	require.NoError(t, err)
	require.Nil(t, final.CurrentCaptureSelection, "local callbacks never become transport claims")
	require.Empty(t, final.CaptureSelectionProof)
}

func TestEvidenceRepresentationsAreMutuallyExclusiveAtBothBoundaries(t *testing.T) {
	_, err := FromCapturedPacket(&data.CapturedPacket{CaptureSelectionProof: []byte("legacy"), LearnedCaptureEvidence: evidenceFixture()}, pipeline.SourceProvenance{})
	require.ErrorIs(t, err, pipeline.ErrContradictoryCaptureEvidence)
	_, err = ToCapturedPacket(&pipeline.PacketEnvelope{CaptureSelectionProof: []byte("legacy"), LearnedCaptureEvidence: evidenceFixture()})
	require.ErrorIs(t, err, pipeline.ErrContradictoryCaptureEvidence)
}

func TestLearnedEvidenceRejectsMalformedAndUnsupportedEnvelopes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*evidence.LearnedCaptureEvidence)
		want   error
	}{
		{"version", func(e *evidence.LearnedCaptureEvidence) { e.Version++ }, learnedrules.ErrUnsupported},
		{"missing-proof", func(e *evidence.LearnedCaptureEvidence) { e.Candidates[0].Proof = nil }, learnedrules.ErrUnsupported},
		{"duplicate-binding", func(e *evidence.LearnedCaptureEvidence) {
			e.Candidates = append(e.Candidates, proto.Clone(e.Candidates[0]).(*evidence.LearnedCandidate))
		}, learnedrules.ErrInvalid},
		{"oversized-proof", func(e *evidence.LearnedCaptureEvidence) {
			e.Candidates[1].Proof = &evidence.LearnedCandidate_LegacyMediaRule{LegacyMediaRule: make([]byte, wire.DefaultEvidenceLimits.MaxProofBytes+1)}
		}, learnedrules.ErrCapacity},
		{"unknown-envelope-field", func(e *evidence.LearnedCaptureEvidence) { e.ProtoReflect().SetUnknown([]byte{0x20, 1}) }, learnedrules.ErrUnsupported},
		{"unknown-candidate-field", func(e *evidence.LearnedCaptureEvidence) { e.Candidates[0].ProtoReflect().SetUnknown([]byte{0x60, 1}) }, learnedrules.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ev := evidenceFixture()
			test.mutate(ev)
			_, err := FromCapturedPacket(&data.CapturedPacket{LearnedCaptureEvidence: ev}, pipeline.SourceProvenance{})
			require.ErrorIs(t, err, test.want)
			_, err = ToCapturedPacket(&pipeline.PacketEnvelope{LearnedCaptureEvidence: ev})
			require.ErrorIs(t, err, test.want)
		})
	}
}

func TestLearnedEvidenceOverflowIsRetainedWithoutClaimingUniqueCandidate(t *testing.T) {
	ev := evidenceFixture()
	ev.Overflow = true
	out, err := ToCapturedPacket(&pipeline.PacketEnvelope{LearnedCaptureEvidence: ev})
	require.NoError(t, err)
	env, err := FromCapturedPacket(out, pipeline.SourceProvenance{})
	require.NoError(t, err)
	require.True(t, env.LearnedCaptureEvidence.Overflow)
	require.Len(t, env.LearnedCaptureEvidence.Candidates, 2)
}
