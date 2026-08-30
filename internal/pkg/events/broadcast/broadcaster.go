// Package broadcast provides non-blocking fanout of normalized protocol events.
package broadcast

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/events"
)

var ErrClosed = errors.New("event broadcaster is closed")

// Projector applies an authorization-sensitive projection before an event is
// placed on a subscriber queue. Returning false omits the event.
type Projector func(events.Event) (projected events.Event, include bool, err error)

type Options struct {
	QueueSize        int
	Kinds            []events.Kind
	NodeIDs          []string
	ProcessorNodeIDs []string
	Project          Projector
}

type SequenceRange struct {
	First uint64
	Last  uint64
}

// Loss describes events omitted because one subscriber's queue was full.
type Loss struct {
	SourceNodeID string
	Count        uint64
	Ranges       []SequenceRange
}

type SubscriberStats struct {
	Enqueued         uint64
	Dropped          uint64
	ProjectionErrors uint64
}

type BroadcasterStats struct {
	Subscribers      int
	Published        uint64
	Enqueued         uint64
	Dropped          uint64
	ProjectionErrors uint64
}

type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[uint64]*Subscription
	nextID      uint64
	closed      bool
	published   atomic.Uint64
	enqueued    atomic.Uint64
	dropped     atomic.Uint64
	projectErrs atomic.Uint64
}

func New() *Broadcaster {
	return &Broadcaster{subscribers: make(map[uint64]*Subscription)}
}

// Subscribe creates an independent bounded queue. QueueSize must be positive.
func (b *Broadcaster) Subscribe(opts Options) (*Subscription, error) {
	if opts.QueueSize <= 0 {
		return nil, fmt.Errorf("subscriber queue size must be positive")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	b.nextID++
	s := &Subscription{
		id:           b.nextID,
		owner:        b,
		events:       make(chan events.Event, opts.QueueSize),
		kinds:        stringSet(opts.Kinds),
		nodeIDs:      stringSet(opts.NodeIDs),
		processorIDs: stringSet(opts.ProcessorNodeIDs),
		project:      opts.Project,
		losses:       make(map[string]*Loss),
	}
	b.subscribers[s.id] = s
	return s, nil
}

// HandleEvent implements events.Sink. Fanout never waits for queue space.
func (b *Broadcaster) HandleEvent(_ context.Context, event events.Event) error {
	if event == nil {
		return nil
	}
	// Content is not part of the event subscription contract, regardless of a
	// caller-supplied kind filter or projector.
	if event.Kind() == events.KindFileContent {
		return nil
	}
	b.published.Add(1)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrClosed
	}
	for _, subscriber := range b.subscribers {
		if !subscriber.matches(event) {
			continue
		}
		projected := event
		if subscriber.project != nil {
			var include bool
			var err error
			projected, include, err = subscriber.project(event)
			if err != nil {
				subscriber.projectErrs.Add(1)
				b.projectErrs.Add(1)
				continue
			}
			if !include || projected == nil || projected.Kind() == events.KindFileContent {
				continue
			}
		}
		select {
		case subscriber.events <- projected:
			subscriber.enqueued.Add(1)
			b.enqueued.Add(1)
		default:
			subscriber.recordDrop(event.Envelope())
			b.dropped.Add(1)
		}
	}
	return nil
}

func (b *Broadcaster) Flush(context.Context) error { return nil }

func (b *Broadcaster) Close(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	for id, subscriber := range b.subscribers {
		delete(b.subscribers, id)
		subscriber.closed.Store(true)
		close(subscriber.events)
	}
	return nil
}

func (b *Broadcaster) Stats() BroadcasterStats {
	b.mu.RLock()
	count := len(b.subscribers)
	b.mu.RUnlock()
	return BroadcasterStats{
		Subscribers: count, Published: b.published.Load(), Enqueued: b.enqueued.Load(),
		Dropped: b.dropped.Load(), ProjectionErrors: b.projectErrs.Load(),
	}
}

type Subscription struct {
	id           uint64
	owner        *Broadcaster
	events       chan events.Event
	kinds        map[events.Kind]struct{}
	nodeIDs      map[string]struct{}
	processorIDs map[string]struct{}
	project      Projector
	closed       atomic.Bool
	enqueued     atomic.Uint64
	dropped      atomic.Uint64
	projectErrs  atomic.Uint64
	lossMu       sync.Mutex
	losses       map[string]*Loss
}

func (s *Subscription) Events() <-chan events.Event { return s.events }

// Close removes the subscription and closes its event channel. It is safe to
// call concurrently with publication and more than once.
func (s *Subscription) Close() {
	b := s.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.closed.Swap(true) {
		return
	}
	delete(b.subscribers, s.id)
	close(s.events)
}

func (s *Subscription) Stats() SubscriberStats {
	return SubscriberStats{Enqueued: s.enqueued.Load(), Dropped: s.dropped.Load(), ProjectionErrors: s.projectErrs.Load()}
}

// ConsumeLosses atomically returns and clears pending overflow information.
func (s *Subscription) ConsumeLosses() []Loss {
	s.lossMu.Lock()
	defer s.lossMu.Unlock()
	result := make([]Loss, 0, len(s.losses))
	for source, loss := range s.losses {
		copyLoss := Loss{SourceNodeID: source, Count: loss.Count, Ranges: append([]SequenceRange(nil), loss.Ranges...)}
		result = append(result, copyLoss)
	}
	s.losses = make(map[string]*Loss)
	return result
}

func (s *Subscription) matches(event events.Event) bool {
	if len(s.kinds) > 0 {
		if _, ok := s.kinds[event.Kind()]; !ok {
			return false
		}
	}
	env := event.Envelope()
	if len(s.nodeIDs) > 0 {
		if _, ok := s.nodeIDs[env.NodeID]; !ok {
			return false
		}
	}
	if len(s.processorIDs) > 0 && !containsAny(env.Provenance.ProcessorNodeIDs, s.processorIDs) {
		return false
	}
	return true
}

func (s *Subscription) recordDrop(env events.Envelope) {
	s.dropped.Add(1)
	s.lossMu.Lock()
	defer s.lossMu.Unlock()
	loss := s.losses[env.NodeID]
	if loss == nil {
		loss = &Loss{SourceNodeID: env.NodeID}
		s.losses[env.NodeID] = loss
	}
	loss.Count++
	if env.EventSequence == 0 {
		return
	}
	last := len(loss.Ranges) - 1
	if last >= 0 && loss.Ranges[last].Last+1 == env.EventSequence {
		loss.Ranges[last].Last = env.EventSequence
		return
	}
	loss.Ranges = append(loss.Ranges, SequenceRange{First: env.EventSequence, Last: env.EventSequence})
}

func stringSet[T ~string](values []T) map[T]struct{} {
	set := make(map[T]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func containsAny(values []string, wanted map[string]struct{}) bool {
	for _, value := range values {
		if _, ok := wanted[value]; ok {
			return true
		}
	}
	return false
}
