package x2x3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

// DeferredSequence owns the single allocation for one immutable, not-yet-
// sequenced product. Template construction consumes no sequence/context slot.
// A shared reorder callback allocates once before identical destination fanout.
type DeferredSequence struct {
	context SequenceContext
	encoder *X3Encoder
	used    atomic.Bool
}

func (s *DeferredSequence) Context() SequenceContext { return s.context }

func (s *DeferredSequence) Allocate() (uint32, error) {
	if s == nil || !s.used.CompareAndSwap(false, true) {
		return 0, errors.New("deferred sequence already consumed")
	}
	sequence, err := s.encoder.sequencer.Next(s.context)
	if err == nil {
		s.encoder.lastSeq.Store(sequence)
	}
	return sequence, err
}

// EncodeCCDeferred builds a template with a fixed-width zero sequence field.
// The template must pass through deferred delivery; it is never final product.
func (e *X3Encoder) EncodeCCDeferred(pkt *types.PacketDisplay, xid uuid.UUID, correlationID *uint64) (*PDU, *DeferredSequence, error) {
	if pkt == nil || pkt.VoIPData == nil || !pkt.VoIPData.IsRTP {
		return nil, nil, ErrNotRTP
	}
	if pkt.VoIPData.SSRC == 0 {
		return nil, nil, ErrNoSSRC
	}
	correlation := e.generateCorrelationID(pkt.VoIPData.SSRC, pkt.VoIPData.CallID)
	if correlationID != nil {
		correlation = *correlationID
	}
	pdu := NewX3RTPPDU(xid, correlation)
	if err := e.addCommonAttributesWithSequence(pdu, pkt, false); err != nil {
		return nil, nil, err
	}
	e.addNetworkAttributes(pdu, pkt)
	if len(pkt.RawData) > 0 {
		pdu.SetPayload(pkt.RawData)
	}
	ipID := e.nfID
	if ipID == "" {
		ipID = pkt.NodeID
	}
	return pdu, &DeferredSequence{encoder: e, context: SequenceContext{PDUType: PDUTypeX3, XID: xid, DomainID: e.domainID, NFID: e.nfID, IPID: ipID, CorrelationID: correlation}}, nil
}

// StampProductSequence changes only the existing fixed-width sequence field,
// after proving the encoded context. Content, identity, lengths and attributes
// remain bound to the exact product accepted by its delivery permit.
func StampProductSequence(data []byte, context SequenceContext, sequence uint32) error {
	checkpoint, err := ProductSequenceCheckpoint(data)
	if err != nil {
		return err
	}
	if checkpoint.Context != context {
		return errors.New("deferred sequence context mismatch")
	}
	var head PDUHeader
	if err := head.UnmarshalBinary(data); err != nil {
		return err
	}
	for offset := HeaderMinSize; offset < int(head.HeaderLength); {
		if int(head.HeaderLength)-offset < 4 {
			return errors.New("invalid deferred product attribute")
		}
		kind := AttributeType(binary.BigEndian.Uint16(data[offset:]))
		length := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4
		if length > int(head.HeaderLength)-offset {
			return errors.New("invalid deferred product attribute size")
		}
		if kind == AttrSequenceNumber {
			if length != 4 {
				return errors.New("invalid deferred product sequence size")
			}
			binary.BigEndian.PutUint32(data[offset:], sequence)
			return nil
		}
		offset += length
	}
	return fmt.Errorf("deferred product has no sequence")
}
