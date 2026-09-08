package x2x3

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestRestoreX2SequenceContinuityDuplicatesWrapAndIsolation(t *testing.T) {
	xid := uuid.New()
	ctx := SequenceContext{PDUType: PDUTypeX2, XID: xid, DomainID: "domain", NFID: "nf", IPID: "ip", CorrelationID: 42}
	encoded := func(seq uint32) []byte {
		p := NewPDU(PDUTypeX2, xid, 42)
		p.Header.CorrelationID = 42
		e := &TLVEncoder{}
		p.AddAttribute(e.EncodeString(AttrDomainID, "domain"))
		p.AddAttribute(e.EncodeString(AttrNFID, "nf"))
		p.AddAttribute(e.EncodeString(AttrIPID, "ip"))
		p.AddAttribute(e.EncodeUint32(AttrSequenceNumber, seq))
		b, err := p.MarshalBinary()
		require.NoError(t, err)
		return b
	}
	s := NewSequencer(8)
	require.NoError(t, s.RestoreX2(encoded(math.MaxUint32)))
	require.NoError(t, s.RestoreX2(encoded(0)))
	require.NoError(t, s.RestoreX2(encoded(math.MaxUint32)))
	next, err := s.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(1), next)
	ctx.PDUType = PDUTypeX3
	next, err = s.Next(ctx)
	require.NoError(t, err)
	require.Zero(t, next)
	require.Error(t, s.RestoreX2([]byte("torn")))
}

func TestRestoreCheckpointCapacity(t *testing.T) {
	s := NewSequencer(1)
	cp := SequenceCheckpoint{Context: SequenceContext{PDUType: PDUTypeX2, XID: uuid.New()}, Next: 8}
	require.NoError(t, s.RestoreCheckpoint(cp))
	cp.Context.XID = uuid.New()
	require.ErrorIs(t, s.RestoreCheckpoint(cp), ErrSequenceCapacity)
}

func TestSequenceReactivationRetainsPersistentX2(t *testing.T) {
	s := NewSequencer(8)
	xid := uuid.New()
	x2 := SequenceContext{PDUType: PDUTypeX2, XID: xid}
	x3 := SequenceContext{PDUType: PDUTypeX3, XID: xid}
	n, err := s.Next(x2)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = s.Next(x3)
	require.NoError(t, err)
	require.Zero(t, n)
	s.ClearX3XID(xid)
	n, err = s.Next(x2)
	require.NoError(t, err)
	require.Equal(t, uint32(1), n)
	n, err = s.Next(x3)
	require.NoError(t, err)
	require.Zero(t, n)
}
