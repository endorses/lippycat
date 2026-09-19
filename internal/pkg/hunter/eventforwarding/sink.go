package eventforwarding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
)

// Sink connects the shared event dispatcher to the durable forwarding client.
// The dispatcher assigns immutable identity before HandleEvent is called. This
// sink deliberately accepts normalized events only; raw packet bytes have no
// representation on this path.
type Sink struct {
	mu                      sync.Mutex
	client                  *Client
	nextBatchSequence       uint64
	semanticProfileRevision uint32
	pendingLosses           []*eventsv1.EventLoss
	failed                  error
}

type fatalForwardingError struct{ err error }

var errBatchSequenceExhausted = errors.New("event forwarding batch sequence is exhausted; rotate the producer session")

func (e *fatalForwardingError) Error() string {
	return fmt.Sprintf("event forwarding stopped: %v", e.err)
}
func (e *fatalForwardingError) Unwrap() error         { return e.err }
func (*fatalForwardingError) TerminalSinkError() bool { return true }

func NewSink(client *Client, firstBatchSequence uint64, semanticProfileRevision uint32) (*Sink, error) {
	if client == nil {
		return nil, fmt.Errorf("new event forwarding sink: client is required")
	}
	if firstBatchSequence == 0 {
		firstBatchSequence = 1
	}
	return &Sink{client: client, nextBatchSequence: firstBatchSequence, semanticProfileRevision: semanticProfileRevision}, nil
}

func (s *Sink) HandleEvent(_ context.Context, event events.Event) error {
	if event == nil {
		return fmt.Errorf("forward event: nil event")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		s.retainFailedEventLocked(event)
		return &fatalForwardingError{err: s.failed}
	}
	env := event.Envelope()
	if env.NodeID != s.client.config.SourceNodeID || env.ProducerSessionID != s.client.config.ProducerSessionID || env.EventSequence == 0 {
		return fmt.Errorf("forward event: missing or mismatched assigned producer identity")
	}
	// Queue overflow can be observed before older buffered events reach this
	// sink. Keep future omissions out of the current batch: advertising them
	// would advance the receiver past events that are still queued.
	ready, future := splitPendingLosses(s.pendingLosses, env.EventSequence)
	s.pendingLosses = ready
	defer func() { s.appendPendingLossesLocked(future) }()
	if len(s.pendingLosses) > 0 {
		// Local coverage can exceed a wire batch's collection limit. Adopt it
		// durably before encoding the event so the spool can split carriers
		// without misclassifying an otherwise valid event as unsupported.
		retention, retainErr := s.client.retainLosses(s.pendingLosses)
		if retention.Committed {
			s.pendingLosses = nil
		}
		if retainErr = nonCleanupError(retainErr); retainErr != nil {
			s.retainFailedEventLocked(event)
			return s.failLocked(retainErr)
		}
		if !retention.Committed {
			s.retainFailedEventLocked(event)
			return s.failLocked(errors.New("retain queued event losses: spool made no progress"))
		}
	}
	stats := &eventsv1.EventBatchStats{Losses: cloneLosses(s.pendingLosses)}
	batch, err := protoadapter.ToProtoBatch(env.NodeID, env.ProducerSessionID, s.nextBatchSequence, []events.Event{event}, stats, s.semanticProfileRevision)
	if err != nil {
		// Identity was validated above, so any remaining encoding failure means
		// this assigned event cannot be represented by the transport contract.
		// Retain its exact sequence as an omission instead of returning an
		// ordinary sink error that the dispatcher would log and then forget.
		s.client.reportLoss(eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, 1)
		loss := &eventsv1.EventLoss{
			Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 1,
			SourceNodeId: env.NodeID, ProducerSessionId: env.ProducerSessionID,
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: env.EventSequence, Last: env.EventSequence}},
		}
		retention, retainErr := s.client.retainLosses(append(cloneLosses(s.pendingLosses), loss))
		if retention.Committed {
			s.pendingLosses = nil
			if retainErr = nonCleanupError(retainErr); retainErr != nil {
				return s.failLocked(retainErr)
			}
			if retainErr = s.flushRequiredPendingLossesLocked(); retainErr != nil {
				return s.failLocked(retainErr)
			}
			return nil
		}
		s.pendingLosses = append(s.pendingLosses, loss)
		if retainErr != nil {
			return s.failLocked(retainErr)
		}
		return nil
	}
	for {
		result, enqueueErr := s.client.Enqueue(batch)
		if result.Rejection == eventspool.RejectionPendingLossFlush {
			flushResult, flushErr := s.client.flushPendingLosses(s.nextBatchSequence, s.semanticProfileRevision)
			if flushResult.Stored {
				flushErr = s.applyCarrierResult(flushResult, flushErr)
				if flushErr != nil {
					s.retainFailedEventLocked(event)
					return s.failLocked(flushErr)
				}
				if s.failed != nil {
					s.retainFailedEventLocked(event)
					return &fatalForwardingError{err: s.failed}
				}
				batch.BatchSequence = s.nextBatchSequence
				continue
			}
			s.retainFailedEventLocked(event)
			if flushErr == nil {
				flushErr = errors.New("flush pending event losses: spool made no progress")
			}
			return s.failLocked(flushErr)
		}
		err = s.applyEnqueueResult(result, enqueueErr)
		if err != nil {
			if !result.Stored && result.Rejection == eventspool.RejectionNone {
				s.retainFailedEventLocked(event)
			}
			return s.failLocked(err)
		}
		if s.failed != nil {
			// The current event is durably stored in the final usable batch. Stop
			// future admission without reporting this event as lost.
			return nil
		}
		if err = s.flushRequiredPendingLossesLocked(); err != nil {
			return s.failLocked(err)
		}
		return nil
	}
}

func (s *Sink) flushRequiredPendingLossesLocked() error {
	if s.failed != nil {
		return s.failed
	}
	for {
		required, err := s.client.pendingLossesRequireFlush(s.nextBatchSequence, s.semanticProfileRevision)
		if err != nil || !required {
			return err
		}
		result, flushErr := s.client.flushPendingLosses(s.nextBatchSequence, s.semanticProfileRevision)
		if result.Stored {
			if flushErr = s.applyCarrierResult(result, flushErr); flushErr != nil {
				return flushErr
			}
			if s.failed != nil {
				return nil
			}
			continue
		}
		if flushErr != nil {
			return flushErr
		}
		return errors.New("flush pending event losses: spool made no progress")
	}
}

func (s *Sink) failLocked(err error) error {
	if s.failed == nil {
		s.failed = err
	}
	return &fatalForwardingError{err: err}
}

func (s *Sink) retainFailedEventLocked(event events.Event) {
	if event == nil {
		return
	}
	env := event.Envelope()
	if env.NodeID != s.client.config.SourceNodeID || env.ProducerSessionID != s.client.config.ProducerSessionID || env.EventSequence == 0 {
		return
	}
	s.client.reportLoss(eventsv1.LossKind_LOSS_KIND_TRANSPORT, 1)
	s.appendPendingLossLocked(&eventsv1.EventLoss{
		Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
		SourceNodeId: env.NodeID, ProducerSessionId: env.ProducerSessionID,
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: env.EventSequence, Last: env.EventSequence}},
	})
}

// splitPendingLosses returns independent coverage before and after the event
// currently being handled. A dropped event cannot be that current event.
func splitPendingLosses(losses []*eventsv1.EventLoss, sequence uint64) (ready, future []*eventsv1.EventLoss) {
	for _, loss := range cloneLosses(losses) {
		for _, r := range loss.GetEventSequenceRanges() {
			appendRange := func(target *[]*eventsv1.EventLoss, first, last uint64) {
				*target = append(*target, &eventsv1.EventLoss{
					Kind: loss.Kind, SourceNodeId: loss.SourceNodeId, ProducerSessionId: loss.ProducerSessionId,
					Count: last - first + 1, EventSequenceRanges: []*eventsv1.SequenceRange{{First: first, Last: last}},
				})
			}
			if r.GetFirst() < sequence {
				appendRange(&ready, r.GetFirst(), min(r.GetLast(), sequence-1))
			}
			if r.GetLast() >= sequence {
				appendRange(&future, max(r.GetFirst(), sequence), r.GetLast())
			}
		}
	}
	return ready, future
}

func (s *Sink) appendPendingLossLocked(loss *eventsv1.EventLoss) {
	s.appendPendingLossesLocked([]*eventsv1.EventLoss{loss})
}

func (s *Sink) appendPendingLossesLocked(losses []*eventsv1.EventLoss) {
	if len(losses) == 0 {
		return
	}
	// Dispatcher admission and per-sink queue drops may arrive in different
	// sequence order. Sort before merging so earlier, disjoint ranges are never
	// mistaken for overlap, and preserve both ends of overlapping coverage.
	for _, loss := range losses {
		for _, r := range loss.GetEventSequenceRanges() {
			s.pendingLosses = append(s.pendingLosses, &eventsv1.EventLoss{
				Kind: loss.Kind, SourceNodeId: loss.SourceNodeId, ProducerSessionId: loss.ProducerSessionId,
				Count:               r.GetLast() - r.GetFirst() + 1,
				EventSequenceRanges: []*eventsv1.SequenceRange{{First: r.GetFirst(), Last: r.GetLast()}},
			})
		}
	}
	sort.Slice(s.pendingLosses, func(i, j int) bool {
		a, b := s.pendingLosses[i], s.pendingLosses[j]
		if a.SourceNodeId != b.SourceNodeId {
			return a.SourceNodeId < b.SourceNodeId
		}
		if a.ProducerSessionId != b.ProducerSessionId {
			return a.ProducerSessionId < b.ProducerSessionId
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.EventSequenceRanges[0].First < b.EventSequenceRanges[0].First
	})
	merged := s.pendingLosses[:0]
	for _, next := range s.pendingLosses {
		if len(merged) > 0 {
			previous := merged[len(merged)-1]
			a, b := previous.EventSequenceRanges[0], next.EventSequenceRanges[0]
			if previous.Kind == next.Kind && previous.SourceNodeId == next.SourceNodeId && previous.ProducerSessionId == next.ProducerSessionId &&
				(b.First <= a.Last || (a.Last != ^uint64(0) && b.First == a.Last+1)) {
				a.Last = max(a.Last, b.Last)
				previous.Count = a.Last - a.First + 1
				continue
			}
		}
		merged = append(merged, next)
	}
	clear(s.pendingLosses[len(merged):])
	s.pendingLosses = merged
}

func (s *Sink) LockDropBoundary()   { s.mu.Lock() }
func (s *Sink) UnlockDropBoundary() { s.mu.Unlock() }
func (s *Sink) HandleDroppedEventLocked(event events.Event, _ time.Time) {
	s.retainFailedEventLocked(event)
}
func (s *Sink) HandleFailedEvent(event events.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retainFailedEventLocked(event)
}

func (s *Sink) applyEnqueueResult(result eventspool.EnqueueResult, err error) error {
	if result.Stored {
		if s.nextBatchSequence == ^uint64(0) {
			s.failed = errBatchSequenceExhausted
		} else {
			s.nextBatchSequence++
		}
		// Drop-oldest losses are attached to the newly stored batch by the
		// spool, so they must not be deferred to a later batch.
		s.pendingLosses = nil
		return nonCleanupError(err)
	}
	if result.Rejection != eventspool.RejectionNone {
		// Rejected batches retain their exact event and inherited loss coverage
		// durably in the spool. The next admitted batch keeps this sequence and
		// receives that coverage exactly once.
		s.pendingLosses = nil
		return handledRejectionError(err)
	}
	return err
}

// A loss carrier adopts only durable spool coverage. Local queue omissions
// remain owned by the sink until their own batch or retention commit succeeds.
func (s *Sink) applyCarrierResult(result eventspool.EnqueueResult, err error) error {
	pending := s.pendingLosses
	err = s.applyEnqueueResult(result, err)
	s.pendingLosses = pending
	return err
}

func (s *Sink) Flush(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return &fatalForwardingError{err: s.failed}
	}
	if len(s.pendingLosses) > 0 {
		// Persist local omissions before splitting them into bounded carriers.
		// Enqueue may request a pending-loss flush without adopting these local
		// ranges, so its rejection path must not be used to clear them.
		result, err := s.client.retainLosses(s.pendingLosses)
		if result.Committed {
			s.pendingLosses = nil
		}
		if err = nonCleanupError(err); err != nil {
			return err
		}
		if !result.Committed {
			return fmt.Errorf("flush event loss reports: spool made no progress")
		}
	}
	for s.client.spool.HasPendingLosses() {
		if s.failed != nil {
			return &fatalForwardingError{err: s.failed}
		}
		result, err := s.client.flushPendingLosses(s.nextBatchSequence, s.semanticProfileRevision)
		if result.Stored {
			if err = s.applyCarrierResult(result, err); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("flush event loss reports: spool made no progress")
	}
	return nil
}
func (s *Sink) Close(ctx context.Context) error { return s.Flush(ctx) }

func nonCleanupError(err error) error {
	if errors.Is(err, eventspool.ErrDurabilityUncertain) || errors.Is(err, eventspool.ErrCheckpointRequired) {
		return err
	}
	var cleanupErr *eventspool.CleanupError
	if errors.As(err, &cleanupErr) {
		return nil
	}
	return err
}

func handledRejectionError(err error) error {
	if errors.Is(err, eventspool.ErrDurabilityUncertain) || errors.Is(err, eventspool.ErrCheckpointRequired) {
		return err
	}
	if errors.Is(err, eventspool.ErrRecordTooLarge) {
		return nil
	}
	return nonCleanupError(err)
}

func cloneLosses(input []*eventsv1.EventLoss) []*eventsv1.EventLoss {
	out := make([]*eventsv1.EventLoss, len(input))
	for i, loss := range input {
		if loss != nil {
			out[i] = &eventsv1.EventLoss{Kind: loss.Kind, Count: loss.Count, SourceNodeId: loss.SourceNodeId, ProducerSessionId: loss.ProducerSessionId}
			for _, r := range loss.EventSequenceRanges {
				if r != nil {
					out[i].EventSequenceRanges = append(out[i].EventSequenceRanges, &eventsv1.SequenceRange{First: r.First, Last: r.Last})
				}
			}
		}
	}
	return out
}

var _ events.Sink = (*Sink)(nil)
