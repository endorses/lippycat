package eventforwarding

import (
	"context"
	"fmt"
	"sync"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
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
}

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
	env := event.Envelope()
	if env.NodeID != s.client.config.SourceNodeID || env.ProducerSessionID != s.client.config.ProducerSessionID || env.EventSequence == 0 {
		return fmt.Errorf("forward event: missing or mismatched assigned producer identity")
	}
	stats := &eventsv1.EventBatchStats{Losses: cloneLosses(s.pendingLosses)}
	batch, err := protoadapter.ToProtoBatch(env.NodeID, env.ProducerSessionID, s.nextBatchSequence, []events.Event{event}, stats, s.semanticProfileRevision)
	if err != nil {
		return fmt.Errorf("forward event: encode batch: %w", err)
	}
	result, err := s.client.Enqueue(batch)
	if err != nil {
		return err
	}
	if result.Stored {
		s.nextBatchSequence++
		// Drop-oldest losses are attached to the newly stored batch by the
		// spool, so they must not be deferred to a later batch.
		s.pendingLosses = nil
	} else {
		// drop_new loses this event; preserve both earlier and current exact
		// ranges for the next successfully admitted batch.
		s.pendingLosses = append(s.pendingLosses, cloneLosses(result.Losses)...)
	}
	return nil
}

func (s *Sink) Flush(context.Context) error { return nil }
func (s *Sink) Close(context.Context) error { return nil }

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
