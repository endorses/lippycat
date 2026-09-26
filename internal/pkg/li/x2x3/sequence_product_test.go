package x2x3

import (
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestProductCheckpointX3ContinuityWrapFanoutAndIsolation(t *testing.T) {
	xid := uuid.New()
	context := SequenceContext{PDUType: PDUTypeX3, XID: xid, CorrelationID: 91}
	encode := func(sequence uint32) []byte {
		p := NewPDU(PDUTypeX3, xid, 91)
		p.Header.CorrelationID = 91
		p.AddAttribute((&TLVEncoder{}).EncodeUint32(AttrSequenceNumber, sequence))
		data, err := p.MarshalBinary()
		require.NoError(t, err)
		return data
	}
	s := NewSequencer(10)
	for _, sequence := range []uint32{math.MaxUint32, 0, math.MaxUint32, 0} {
		require.NoError(t, s.RestoreProduct(encode(sequence)))
	}
	next, err := s.Next(context)
	require.NoError(t, err)
	require.Equal(t, uint32(1), next)
	context.PDUType = PDUTypeX2
	next, err = s.Next(context)
	require.NoError(t, err)
	require.Zero(t, next)
	_, err = X2SequenceCheckpoint(encode(1))
	require.Error(t, err, "legacy X2-only caller remains strict")
	_, err = ProductSequenceCheckpoint([]byte("invalid"))
	require.Error(t, err)
}
