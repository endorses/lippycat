package wire

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/stretchr/testify/require"
)

type packetSink struct {
	data.DataService_StreamPacketsClient
	sent []*data.PacketBatch
}

func (s *packetSink) Send(batch *data.PacketBatch) error { s.sent = append(s.sent, batch); return nil }
func TestEvidenceReadinessPreventsUnknownFieldLoss(t *testing.T) {
	packet := &data.CapturedPacket{Data: []byte("packet"), LearnedCaptureEvidence: &evidence.LearnedCaptureEvidence{Version: 1, Candidates: []*evidence.LearnedCandidate{Candidate(testBinding(0))}}}
	batch := &data.PacketBatch{Packets: []*data.CapturedPacket{packet}}
	sink := &packetSink{}
	legacy := NewPacketStream(sink, nil)
	require.ErrorIs(t, legacy.Send(batch), learnedrules.ErrUnsupported)
	require.Empty(t, sink.sent)
	current := NewPacketStream(sink, []uint32{EvidenceVersion})
	require.NoError(t, current.Send(batch))
	require.Same(t, batch, sink.sent[0])
	require.NotEmpty(t, sink.sent[0].Packets[0].LearnedCaptureEvidence)
	packet.CaptureSelectionProof = []byte("contradictory")
	require.ErrorIs(t, current.Send(batch), learnedrules.ErrInvalid)
	packet.LearnedCaptureEvidence = nil
	require.NoError(t, legacy.Send(batch), "field16 remains available to legacy peers")
	require.Empty(t, AcceptEvidenceVersions([]uint32{2, 3}))
	require.Equal(t, []uint32{1}, AcceptEvidenceVersions([]uint32{2, 1, 1}))
}
