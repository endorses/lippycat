package eventforwarding

import (
	"context"
	"errors"
	"fmt"
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
	stats := &eventsv1.EventBatchStats{Losses: cloneLosses(s.pendingLosses)}
	batch, err := protoadapter.ToProtoBatch(env.NodeID, env.ProducerSessionID, s.nextBatchSequence, []events.Event{event}, stats, s.semanticProfileRevision)
	if err != nil {
		if !errors.Is(err, protoadapter.ErrFileContentDisallowed) {
			return fmt.Errorf("forward event: encode batch: %w", err)
		}
		s.client.reportLoss(eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, 1)
		loss := &eventsv1.EventLoss{
			Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 1,
			SourceNodeId: env.NodeID, ProducerSessionId: env.ProducerSessionID,
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: env.EventSequence, Last: env.EventSequence}},
		}
		retention, retainErr := s.client.retainLosses([]*eventsv1.EventLoss{loss})
		if retention.Committed {
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
				if flushErr = s.applyEnqueueResult(flushResult, flushErr); flushErr != nil {
					s.retainFailedEventLocked(event)
					return s.failLocked(flushErr)
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
		if err = s.flushRequiredPendingLossesLocked(); err != nil {
			return s.failLocked(err)
		}
		return nil
	}
}

func (s *Sink) flushRequiredPendingLossesLocked() error {
	for {
		required, err := s.client.pendingLossesRequireFlush(s.nextBatchSequence, s.semanticProfileRevision)
		if err != nil || !required {
			return err
		}
		result, flushErr := s.client.flushPendingLosses(s.nextBatchSequence, s.semanticProfileRevision)
		if result.Stored {
			if flushErr = s.applyEnqueueResult(result, flushErr); flushErr != nil {
				return flushErr
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

func (s *Sink) appendPendingLossLocked(loss *eventsv1.EventLoss) {
	if loss == nil || len(loss.GetEventSequenceRanges()) != 1 {
		s.pendingLosses = append(s.pendingLosses, loss)
		return
	}
	if len(s.pendingLosses) != 0 {
		previous := s.pendingLosses[len(s.pendingLosses)-1]
		previousRanges := previous.GetEventSequenceRanges()
		next := loss.GetEventSequenceRanges()[0]
		adjacent := false
		if len(previousRanges) == 1 {
			adjacent = next.GetFirst() <= previousRanges[0].GetLast() || (previousRanges[0].GetLast() != ^uint64(0) && next.GetFirst() == previousRanges[0].GetLast()+1)
		}
		if previous.GetKind() == loss.GetKind() && previous.GetSourceNodeId() == loss.GetSourceNodeId() && previous.GetProducerSessionId() == loss.GetProducerSessionId() && adjacent {
			if next.GetLast() > previousRanges[0].GetLast() {
				previousRanges[0].Last = next.GetLast()
			}
			previous.Count = previousRanges[0].GetLast() - previousRanges[0].GetFirst() + 1
			return
		}
	}
	s.pendingLosses = append(s.pendingLosses, loss)
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
		s.nextBatchSequence++
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

func (s *Sink) Flush(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingLosses) > 0 {
		batch := &eventsv1.ProtocolEventBatch{
			SourceNodeId: s.client.config.SourceNodeID, ProducerSessionId: s.client.config.ProducerSessionID,
			BatchSequence: s.nextBatchSequence, SemanticProfileRevision: s.semanticProfileRevision,
			Stats: &eventsv1.EventBatchStats{Losses: cloneLosses(s.pendingLosses)},
		}
		result, err := s.client.Enqueue(batch)
		if err = s.applyEnqueueResult(result, err); err != nil {
			return err
		}
		if !result.Stored && result.Rejection == eventspool.RejectionNone {
			return fmt.Errorf("flush event loss reports: spool made no progress")
		}
	}
	for s.client.spool.HasPendingLosses() {
		result, err := s.client.flushPendingLosses(s.nextBatchSequence, s.semanticProfileRevision)
		if result.Stored {
			if err = s.applyEnqueueResult(result, err); err != nil {
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
	var cleanupErr *eventspool.CleanupError
	if errors.As(err, &cleanupErr) {
		return nil
	}
	return err
}

func handledRejectionError(err error) error {
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
