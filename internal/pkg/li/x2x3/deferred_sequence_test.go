package x2x3

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConfiguredProcessorContextSurvivesCaptureSourceChange(t *testing.T) {
	sequencer := NewSequencer(8)
	x2 := NewX2EncoderWithSequencer(sequencer, "domain", "processor")
	x3 := NewX3EncoderWithSequencer(sequencer, "domain", "processor")
	xid := uuid.New()
	for index, node := range []string{"hunter-a", "hunter-b"} {
		packet := &types.PacketDisplay{NodeID: node, Timestamp: time.Now(), RawData: []byte("media"), VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 7, CallID: "same-call"}}
		product, err := x3.EncodeCC(packet, xid)
		require.NoError(t, err)
		data, err := product.MarshalBinary()
		require.NoError(t, err)
		checkpoint, err := ProductSequenceCheckpoint(data)
		require.NoError(t, err)
		require.Equal(t, "processor", checkpoint.Context.IPID)
		require.Equal(t, uint32(index+1), checkpoint.Next)
		require.Equal(t, node, packet.NodeID, "delivery context must not overwrite capture provenance")
		packet.VoIPData.IsRTP = false
		packet.VoIPData.Method = "INVITE"
		packet.VoIPData.RawSIP = []byte("INVITE sip:bob@example.invalid SIP/2.0\r\nCall-ID: same-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
		product, err = x2.EncodeIRI(packet, xid)
		require.NoError(t, err)
		require.NotNil(t, product)
		data, err = product.MarshalBinary()
		require.NoError(t, err)
		checkpoint, err = ProductSequenceCheckpoint(data)
		require.NoError(t, err)
		require.Equal(t, "processor", checkpoint.Context.IPID)
		require.Equal(t, uint32(index+1), checkpoint.Next)
	}
}

func TestDeferredTemplatesAllocateOnlyInChosenOutputOrder(t *testing.T) {
	sequencer := NewSequencer(8)
	encoder := NewX3EncoderWithSequencer(sequencer, "domain", "processor")
	xid := uuid.New()
	packet := &types.PacketDisplay{NodeID: "hunter", Timestamp: time.Now(), RawData: []byte("media"), VoIPData: &types.VoIPMetadata{IsRTP: true, SSRC: 7, CallID: "same-call"}}
	first, one, err := encoder.EncodeCCDeferred(packet, xid, nil)
	require.NoError(t, err)
	second, two, err := encoder.EncodeCCDeferred(packet, xid, nil)
	require.NoError(t, err)
	require.Zero(t, sequencer.Len(), "building/retaining templates must consume no sequence contexts")
	sequence, err := two.Allocate()
	require.NoError(t, err)
	require.Zero(t, sequence)
	data, err := second.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, StampProductSequence(data, two.Context(), sequence))
	sequence, err = one.Allocate()
	require.NoError(t, err)
	require.Equal(t, uint32(1), sequence)
	data, err = first.MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, StampProductSequence(data, one.Context(), sequence))
	checkpoint, err := ProductSequenceCheckpoint(data)
	require.NoError(t, err)
	require.Equal(t, uint32(2), checkpoint.Next)
	_, err = one.Allocate()
	require.Error(t, err)
	wrong := one.Context()
	wrong.XID = uuid.New()
	require.Error(t, StampProductSequence(data, wrong, 17))
	unchanged, err := ProductSequenceCheckpoint(data)
	require.NoError(t, err)
	require.Equal(t, checkpoint, unchanged)
}
