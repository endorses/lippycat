package x2x3

import (
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
	"sync/atomic"
)

// RestoreX2 advances sequence state using an immutable journaled PDU. Call in
// journal FIFO order before enabling live encoding. Fan-out duplicates are safe;
// modulo serial arithmetic preserves the mandated uint32 wrap.
type SequenceCheckpoint struct {
	Context SequenceContext
	Next    uint32
}

func X2SequenceCheckpoint(data []byte) (SequenceCheckpoint, error) {
	var checkpoint SequenceCheckpoint
	var pdu PDU
	if err := pdu.UnmarshalBinary(data); err != nil {
		return checkpoint, fmt.Errorf("restore sequence: %w", err)
	}
	if pdu.Header.Type != PDUTypeX2 {
		return checkpoint, fmt.Errorf("sequence recovery requires X2 product")
	}
	context := SequenceContext{PDUType: pdu.Header.Type, XID: pdu.Header.XID, CorrelationID: pdu.Header.CorrelationID}
	var seq uint32
	found := false
	for _, attr := range pdu.Attributes {
		switch attr.Type {
		case AttrDomainID:
			context.DomainID = string(attr.Value)
		case AttrNFID:
			context.NFID = string(attr.Value)
		case AttrIPID:
			context.IPID = string(attr.Value)
		case AttrSequenceNumber:
			if found || len(attr.Value) != 4 {
				return checkpoint, fmt.Errorf("invalid recovered sequence attribute")
			}
			seq = binary.BigEndian.Uint32(attr.Value)
			found = true
		}
	}
	if !found {
		return checkpoint, fmt.Errorf("recovered X2 missing sequence attribute")
	}
	return SequenceCheckpoint{Context: context, Next: seq + 1}, nil
}

func (s *Sequencer) RestoreX2(data []byte) error {
	checkpoint, err := X2SequenceCheckpoint(data)
	if err != nil {
		return err
	}
	return s.RestoreCheckpoint(checkpoint)
}

// RestoreCheckpoint restores durable sequence state before live encoding.
func (s *Sequencer) RestoreCheckpoint(checkpoint SequenceCheckpoint) error {
	context, next := checkpoint.Context, checkpoint.Next
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if value, ok := s.next.Load(context); ok {
		v := value.(*atomic.Uint32)
		for {
			old := v.Load()
			if int32(next-old) <= 0 {
				return nil
			}
			if v.CompareAndSwap(old, next) {
				return nil
			}
		}
	}
	if s.contexts.Load() >= int64(s.maxContexts) {
		return ErrSequenceCapacity
	}
	v := &atomic.Uint32{}
	v.Store(next)
	s.next.Store(context, v)
	s.contexts.Add(1)
	return nil
}

// ClearX3XID retires volatile CC sequencing while retaining X2 state needed by
// durable product from earlier activations of the same XID.
func (s *Sequencer) ClearX3XID(xid uuid.UUID) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	s.next.Range(func(key, value any) bool {
		context := key.(SequenceContext)
		if context.XID == xid && context.PDUType == PDUTypeX3 && s.next.CompareAndDelete(key, value) {
			s.contexts.Add(-1)
		}
		return true
	})
}
