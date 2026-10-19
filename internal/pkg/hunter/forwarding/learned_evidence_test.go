//go:build hunter || all

package forwarding

import (
	"context"
	"testing"

	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func learnedPacket() *pipeline.PacketEnvelope {
	return &pipeline.PacketEnvelope{LearnedCaptureEvidence: &evidence.LearnedCaptureEvidence{Version: wire.EvidenceVersion, Candidates: []*evidence.LearnedCandidate{
		{BindingId: "diagnostic-binding", BindingRevision: 1, AdapterId: "diagnostic", ContextVersion: 1, SubjectId: "request", SubjectIncarnation: "request-1", AuthorityId: "processor", AuthorityGeneration: 1, AttributionContext: "diagnostic", Proof: &evidence.LearnedCandidate_ReferenceOnly{ReferenceOnly: true}},
		{BindingId: "media-binding", BindingRevision: 2, AdapterId: "voip", ContextVersion: 1, SubjectId: "selected-call", SubjectIncarnation: "call-1", AuthorityId: "processor", AuthorityGeneration: 1, AttributionContext: "media", Proof: &evidence.LearnedCandidate_LegacyMediaRule{LegacyMediaRule: []byte("original-signed-media-rule")}},
	}}}
}

func TestLearnedEvidenceRequiresAuthorityAtAdmissionAndSealingWithoutGlobalLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	accepted, checks := 0, 0
	m := New(Config{BatchSize: 10, BatchSink: func(b *pipeline.PacketBatch) error { accepted += len(b.Packets); return nil }}, &flowStats{}, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	_, err := m.AddObservedPacket(learnedPacket())
	require.ErrorIs(t, err, ErrCaptureProvenance, "missing validator denies typed evidence under ordinary owner")
	m.config.ValidateCaptureSelection = func(e *pipeline.PacketEnvelope) bool {
		checks++
		return e.LearnedCaptureEvidence.Candidates[0].SubjectIncarnation == "request-1" && string(e.LearnedCaptureEvidence.Candidates[1].GetLegacyMediaRule()) == "original-signed-media-rule"
	}
	_, err = m.AddObservedPacket(learnedPacket())
	require.NoError(t, err)
	m.SendBatch()
	require.Equal(t, 1, accepted)
	require.Equal(t, 2, checks, "typed evidence is checked at both producer boundaries")
	candidate := learnedPacket()
	_, err = m.AddObservedPacket(candidate)
	require.NoError(t, err)
	candidate.LearnedCaptureEvidence.Candidates[0].SubjectIncarnation = "request-2"
	m.SendBatch()
	require.Equal(t, 1, accepted, "candidate identity mutation must not inherit another subject")
	candidate = learnedPacket()
	_, err = m.AddObservedPacket(candidate)
	require.NoError(t, err)
	candidate.LearnedCaptureEvidence.Candidates[1].GetLegacyMediaRule()[0] = 'x'
	m.SendBatch()
	require.Equal(t, 1, accepted, "original signed proof is revalidated at sealing")
	candidate = learnedPacket()
	_, err = m.AddObservedPacket(candidate)
	require.NoError(t, err)
	m.config.ValidateCaptureSelection = nil
	m.SendBatch()
	require.Equal(t, 1, accepted, "missing authority check at sealing fails closed")
}

func TestLearnedEvidenceSchemaCannotBeBypassedByPermissiveAuthorityCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	accepted := 0
	m := New(Config{BatchSize: 10, ValidateCaptureSelection: func(*pipeline.PacketEnvelope) bool { return true }, BatchSink: func(b *pipeline.PacketBatch) error { accepted += len(b.Packets); return nil }}, &flowStats{}, nil, ctx, nil)
	defer func() { cancel(); m.Wait() }()
	candidate := learnedPacket()
	candidate.CaptureSelectionProof = []byte("contradictory-legacy-proof")
	_, err := m.AddObservedPacket(candidate)
	require.ErrorIs(t, err, ErrCaptureProvenance)
	candidate = learnedPacket()
	candidate.LearnedCaptureEvidence.Version++
	_, err = m.AddObservedPacket(candidate)
	require.ErrorIs(t, err, ErrCaptureProvenance)
	candidate = learnedPacket()
	_, err = m.AddObservedPacket(candidate)
	require.NoError(t, err)
	candidate.LearnedCaptureEvidence.Version++
	m.SendBatch()
	require.Zero(t, accepted, "unknown schema introduced after admission is refused")
	candidate = learnedPacket()
	_, err = m.AddObservedPacket(candidate)
	require.NoError(t, err)
	candidate.CaptureSelectionProof = []byte("contradictory-legacy-proof")
	m.SendBatch()
	require.Zero(t, accepted, "contradictory evidence introduced after admission is refused")
}
