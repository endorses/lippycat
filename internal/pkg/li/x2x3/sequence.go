package x2x3

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

const DefaultMaxSequenceContexts = 1_000_000

var ErrSequenceCapacity = errors.New("X2/X3 sequence context capacity reached")

// SequenceContext is the complete sequence scope mandated by ETSI
// TS 103 221-2 clause 5.3.9. PDUType keeps X2 and X3 sequences separate.
// DomainID is the X2/X3 Domain ID attribute, not an X1 destination DId.
type SequenceContext struct {
	PDUType       PDUType
	XID           uuid.UUID
	DomainID      string
	NFID          string
	IPID          string
	CorrelationID uint64
}

// Sequencer assigns zero-based sequence numbers to ETSI sequence contexts.
// It fails closed instead of silently resetting a live context when bounded
// storage is exhausted.
type Sequencer struct {
	next        sync.Map // map[SequenceContext]*atomic.Uint32; value is next+1
	createMu    sync.Mutex
	contexts    atomic.Int64
	maxContexts int
}

func NewSequencer(maxContexts int) *Sequencer {
	if maxContexts <= 0 {
		maxContexts = DefaultMaxSequenceContexts
	}
	return &Sequencer{maxContexts: maxContexts}
}

// Next returns zero for a new context, then increments by one. uint32 overflow
// intentionally wraps the next value to zero as required by clause 5.3.9.
func (s *Sequencer) Next(context SequenceContext) (uint32, error) {
	if value, exists := s.next.Load(context); exists {
		return value.(*atomic.Uint32).Add(1) - 1, nil
	}
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if value, exists := s.next.Load(context); exists {
		return value.(*atomic.Uint32).Add(1) - 1, nil
	}
	if s.contexts.Load() >= int64(s.maxContexts) {
		return 0, ErrSequenceCapacity
	}
	state := &atomic.Uint32{}
	state.Store(1)
	s.next.Store(context, state)
	s.contexts.Add(1)
	return 0, nil
}

func (s *Sequencer) ClearXID(xid uuid.UUID) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	s.next.Range(func(key, value any) bool {
		context := key.(SequenceContext)
		if context.XID == xid && s.next.CompareAndDelete(key, value) {
			s.contexts.Add(-1)
		}
		return true
	})
}

func (s *Sequencer) Len() int {
	return int(s.contexts.Load())
}

func (s *Sequencer) setNextForTest(context SequenceContext, next uint32) {
	state := &atomic.Uint32{}
	state.Store(next)
	if _, loaded := s.next.LoadOrStore(context, state); !loaded {
		s.contexts.Add(1)
	}
}
