//go:build hunter || all

package packetforwarding

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/packetreceipt"
	"github.com/stretchr/testify/require"
)

func TestReliableEvidenceRequiresDestinationReadinessAndPreservesDigest(t *testing.T) {
	raw := &recordingCaptureSend{}
	id := &data.RawPacketIdentity{SourceId: "hunter", ProducerSessionId: "session", CaptureEpoch: "epoch", DestinationId: "processor", AckScope: "receiver"}
	stream := &Stream{ReliablePacketService_StreamReliablePacketsClient: raw, identity: id}
	batch := &data.PacketBatch{HunterId: id.SourceId, ProducerSessionId: id.ProducerSessionId, CaptureEpoch: id.CaptureEpoch, Sequence: 1, Packets: []*data.CapturedPacket{{Data: []byte{1}, LearnedCaptureEvidence: &evidence.LearnedCaptureEvidence{Version: 1, Overflow: true}}}}
	before, err := packetreceipt.BatchDigest(batch)
	require.NoError(t, err)
	require.ErrorIs(t, stream.Send(batch), learnedrules.ErrUnsupported)
	require.Empty(t, raw.messages)
	stream.evidenceVersions = []uint32{1}
	require.NoError(t, stream.Send(batch))
	require.Same(t, batch, raw.messages[0].Batch)
	after, err := packetreceipt.BatchDigest(batch)
	require.NoError(t, err)
	require.Equal(t, before, after)
	batch.Packets[0].CaptureSelectionProof = []byte("legacy")
	require.ErrorIs(t, stream.Send(batch), learnedrules.ErrInvalid)
	require.Len(t, raw.messages, 1)
	require.NoError(t, stream.Send(&data.PacketBatch{}))
	require.Equal(t, []uint32{1}, raw.messages[1].LearnedEvidenceVersions)
}
