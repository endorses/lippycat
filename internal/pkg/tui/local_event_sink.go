//go:build tui || all

package tui

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
)

var errLocalEventSinkClosed = errors.New("local event sink is closed")

// localEventSink bounds normalized-event delivery to Bubble Tea. Live capture
// drops on pressure so rendering can never slow packet analysis; offline replay
// waits for queue capacity to retain deterministic fixture equivalence.
type localEventSink struct {
	queue        chan localEventItem
	preserveAll  bool
	deliver      func(types.EventBatch)
	dropped      atomic.Uint64
	dropBoundary sync.Mutex
	mu           sync.RWMutex
	closed       bool
	closeOnce    sync.Once
	done         chan struct{}
}

type localEventItem struct {
	event   events.Event
	barrier chan struct{}
}

const maxPendingLocalEventBatches = 4096

// pendingLocalEventBuffer gives local events the packet bridge's pull-based
// delivery semantics. Producers never call Program.Send, so restarting from
// Bubble Tea's Update loop cannot deadlock while the pipeline drains.
type pendingLocalEventBuffer struct {
	mu      sync.Mutex
	batches []types.EventBatch
	dropped uint64
}

var pendingLocalEvents = &pendingLocalEventBuffer{
	batches: make([]types.EventBatch, 0, 256),
}

func (b *pendingLocalEventBuffer) addBatch(batch types.EventBatch) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.batches) >= maxPendingLocalEventBatches {
		b.dropped += uint64(len(batch.Events))
		for _, loss := range batch.Losses {
			b.dropped += eventLossCount(loss)
		}
		b.dropped += batch.CompatibilityOmissions
		return
	}
	b.batches = append(b.batches, batch)
}

func (b *pendingLocalEventBuffer) drain(max int) []types.EventBatch {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.batches) == 0 && b.dropped == 0 {
		return nil
	}
	count := len(b.batches)
	if max > 0 && count > max {
		count = max
	}
	result := append([]types.EventBatch(nil), b.batches[:count]...)
	b.batches = append(b.batches[:0], b.batches[count:]...)
	if b.dropped != 0 {
		result = append(result, types.EventBatch{Losses: []types.EventLoss{{
			Kind:  eventsv1.LossKind_LOSS_KIND_BUFFER,
			Count: b.dropped,
		}}})
		b.dropped = 0
	}
	return result
}

func (b *pendingLocalEventBuffer) clear() {
	b.mu.Lock()
	b.batches = b.batches[:0]
	b.dropped = 0
	b.mu.Unlock()
}

func drainPendingLocalEvents(preserveAll bool) []types.EventBatch {
	if preserveAll {
		return pendingLocalEvents.drain(0)
	}
	return pendingLocalEvents.drain(50)
}

func newLocalEventSink(capacity int, preserveAll bool, deliver func(types.EventBatch)) *localEventSink {
	if capacity <= 0 {
		capacity = 1
	}
	s := &localEventSink{
		queue:       make(chan localEventItem, capacity),
		preserveAll: preserveAll,
		deliver:     deliver,
		done:        make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *localEventSink) HandleEvent(ctx context.Context, event events.Event) error {
	if event == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errLocalEventSinkClosed
	}
	item := localEventItem{event: event}
	if s.preserveAll {
		select {
		case s.queue <- item:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case s.queue <- item:
	default:
		s.dropped.Add(1)
	}
	return nil
}

func (s *localEventSink) Flush(ctx context.Context) error {
	barrier := make(chan struct{})
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errLocalEventSinkClosed
	}
	select {
	case s.queue <- localEventItem{barrier: barrier}:
		s.mu.RUnlock()
	case <-ctx.Done():
		s.mu.RUnlock()
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *localEventSink) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *localEventSink) ExcludeFromFlowControl() {}

// These methods let the dispatcher report drops at both its admission queue
// and the per-sink queue. Keeping the boundary locked until the dispatcher has
// decided admission prevents the consumer from attaching a loss count to an
// event that actually preceded that loss.
func (s *localEventSink) LockDropBoundary() { s.dropBoundary.Lock() }
func (s *localEventSink) HandleDroppedEventLocked(_ events.Event, _ time.Time) {
	s.dropped.Add(1)
}
func (s *localEventSink) UnlockDropBoundary() { s.dropBoundary.Unlock() }

func (s *localEventSink) takeDropped() uint64 {
	s.dropBoundary.Lock()
	defer s.dropBoundary.Unlock()
	return s.dropped.Swap(0)
}

func (s *localEventSink) run() {
	defer close(s.done)
	for item := range s.queue {
		if item.barrier != nil {
			close(item.barrier)
			continue
		}
		batch := types.EventBatch{Events: []events.Event{item.event}}
		if dropped := s.takeDropped(); dropped != 0 {
			batch.Losses = []types.EventLoss{{
				Kind:  eventsv1.LossKind_LOSS_KIND_BUFFER,
				Count: dropped,
			}}
		}
		if s.deliver != nil {
			s.deliver(batch)
		}
	}
	// Preserve loss visibility even when pressure occurs immediately before
	// EOF and no later event is available to carry the report.
	if dropped := s.takeDropped(); dropped != 0 && s.deliver != nil {
		s.deliver(types.EventBatch{Losses: []types.EventLoss{{
			Kind:  eventsv1.LossKind_LOSS_KIND_BUFFER,
			Count: dropped,
		}}})
	}
}

var _ events.Sink = (*localEventSink)(nil)
