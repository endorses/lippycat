package x2x3

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/types"
)

func TestSequencerETSIContext(t *testing.T) {
	sequencer := NewSequencer(100)
	base := SequenceContext{
		PDUType: PDUTypeX2, XID: uuid.New(), DomainID: "domain-a",
		NFID: "nf-a", IPID: "poi-a", CorrelationID: 42,
	}

	sequence, err := sequencer.Next(base)
	require.NoError(t, err)
	require.Equal(t, uint32(0), sequence)
	sequence, err = sequencer.Next(base)
	require.NoError(t, err)
	require.Equal(t, uint32(1), sequence)

	contexts := []SequenceContext{
		withSequenceContext(base, func(c *SequenceContext) { c.PDUType = PDUTypeX3 }),
		withSequenceContext(base, func(c *SequenceContext) { c.XID = uuid.New() }),
		withSequenceContext(base, func(c *SequenceContext) { c.DomainID = "domain-b" }),
		withSequenceContext(base, func(c *SequenceContext) { c.NFID = "nf-b" }),
		withSequenceContext(base, func(c *SequenceContext) { c.IPID = "poi-b" }),
		withSequenceContext(base, func(c *SequenceContext) { c.CorrelationID++ }),
	}
	for _, context := range contexts {
		sequence, err = sequencer.Next(context)
		require.NoError(t, err)
		require.Equal(t, uint32(0), sequence)
	}
}

func TestEncodersUseSharedETSIContextSequencer(t *testing.T) {
	sequencer := NewSequencer(100)
	x2 := NewX2EncoderWithSequencer(sequencer, "domain-a", "nf-a")
	x3 := NewX3EncoderWithSequencer(sequencer, "domain-a", "nf-a")
	xid := uuid.New()
	packet := &types.PacketDisplay{
		Timestamp: time.Now(), NodeID: "poi-a", RawData: []byte("INVITE sip:x SIP/2.0\r\n\r\n"),
		VoIPData: &types.VoIPMetadata{CallID: "call-a", Method: "INVITE"},
	}

	firstX2, err := x2.EncodeIRI(packet, xid)
	require.NoError(t, err)
	secondX2, err := x2.EncodeIRI(packet, xid)
	require.NoError(t, err)
	packet.RawData = []byte{0x80, 0x00}
	packet.VoIPData = &types.VoIPMetadata{IsRTP: true, SSRC: 1, CallID: "call-a"}
	firstX3, err := x3.EncodeCC(packet, xid)
	require.NoError(t, err)

	parser := NewAttributeParser()
	requireSequence := func(want uint32, pdu *PDU) {
		attributes := FindAllAttributes(pdu.Attributes, AttrSequenceNumber)
		require.Len(t, attributes, 1)
		got, parseErr := parser.ParseSequenceNumber(&attributes[0])
		require.NoError(t, parseErr)
		require.Equal(t, want, got)
		require.Len(t, FindAllAttributes(pdu.Attributes, AttrDomainID), 1)
		require.Len(t, FindAllAttributes(pdu.Attributes, AttrNFID), 1)
		require.Len(t, FindAllAttributes(pdu.Attributes, AttrIPID), 1)
	}
	requireSequence(0, firstX2)
	requireSequence(1, secondX2)
	requireSequence(0, firstX3)
}

func TestSequencerWrapClearAndCapacity(t *testing.T) {
	sequencer := NewSequencer(2)
	first := SequenceContext{PDUType: PDUTypeX2, XID: uuid.New(), CorrelationID: 1}
	second := SequenceContext{PDUType: PDUTypeX2, XID: uuid.New(), CorrelationID: 2}
	third := SequenceContext{PDUType: PDUTypeX2, XID: uuid.New(), CorrelationID: 3}
	sequencer.setNextForTest(first, math.MaxUint32)

	sequence, err := sequencer.Next(first)
	require.NoError(t, err)
	require.Equal(t, uint32(math.MaxUint32), sequence)
	sequence, err = sequencer.Next(first)
	require.NoError(t, err)
	require.Equal(t, uint32(0), sequence)
	_, err = sequencer.Next(second)
	require.NoError(t, err)
	_, err = sequencer.Next(third)
	require.ErrorIs(t, err, ErrSequenceCapacity)

	sequencer.ClearXID(first.XID)
	require.Equal(t, 1, sequencer.Len())
	sequence, err = sequencer.Next(third)
	require.NoError(t, err)
	require.Equal(t, uint32(0), sequence)
}

func TestSequencerConcurrentUniqueness(t *testing.T) {
	sequencer := NewSequencer(1)
	context := SequenceContext{PDUType: PDUTypeX3, XID: uuid.New(), CorrelationID: 7}
	const count = 100
	type result struct {
		sequence uint32
		err      error
	}
	results := make(chan result, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sequence, err := sequencer.Next(context)
			results <- result{sequence: sequence, err: err}
		}()
	}
	wg.Wait()
	close(results)
	seen := make(map[uint32]struct{}, count)
	for result := range results {
		require.NoError(t, result.err)
		seen[result.sequence] = struct{}{}
	}
	require.Len(t, seen, count)
	for i := range count {
		_, exists := seen[uint32(i)]
		require.True(t, exists)
	}
}

func withSequenceContext(context SequenceContext, mutate func(*SequenceContext)) SequenceContext {
	mutate(&context)
	return context
}
