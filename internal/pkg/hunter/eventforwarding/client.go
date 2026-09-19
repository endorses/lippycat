// Package eventforwarding implements the hunter side of normalized event ingestion.
package eventforwarding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

type Stream interface {
	Send(*eventsv1.EventIngressMessage) error
	Recv() (*eventsv1.EventIngressControl, error)
}

type Config struct {
	SourceNodeID            string
	ProducerSessionID       string
	EventAPIMajor           uint32
	SemanticProfileRevision uint32
	EventKinds              []eventsv1.EventKind
	Profile                 eventsv1.IngressProfile
	SlowInterval            time.Duration
	OnLoss                  func(eventsv1.LossKind, uint64)
	RelayNodeID             string
}

// Client persists before sending and deletes only after a cumulative ACK.
// Re-running Serve with a replacement stream retransmits every unacknowledged
// batch with its original identity for processor-side deduplication.
type Client struct {
	config Config
	spool  *eventspool.Spool
	wake   chan struct{}

	batchFetches atomic.Uint64
	// controlReceived is a deterministic test seam invoked after a received
	// control is queued for Serve. Production clients leave it nil.
	controlReceived func()
}

const batchFetchLimit = 128

func (c *Client) ProducerSessionID() string { return c.config.ProducerSessionID }

// HasPending reports whether the durable spool contains unacknowledged event
// batches or loss coverage awaiting a bounded loss-only batch. A forwarding-
// mode fallback must not strand either form of durable state.
func (c *Client) HasPending() bool { return c.spool.HasPending() }

func New(config Config, spool *eventspool.Spool) (*Client, error) {
	if spool == nil {
		return nil, errors.New("new event forwarding client: spool is required")
	}
	if config.SourceNodeID == "" || config.ProducerSessionID == "" {
		return nil, errors.New("new event forwarding client: source node and producer session are required")
	}
	if config.EventAPIMajor == 0 {
		config.EventAPIMajor = 1
	}
	if config.Profile == eventsv1.IngressProfile_INGRESS_PROFILE_UNSPECIFIED {
		config.Profile = eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
	}
	if config.SlowInterval <= 0 {
		config.SlowInterval = 25 * time.Millisecond
	}
	return &Client{config: config, spool: spool, wake: make(chan struct{}, 1)}, nil
}

func (c *Client) Enqueue(batch *eventsv1.ProtocolEventBatch) (eventspool.EnqueueResult, error) {
	if batch == nil {
		return eventspool.EnqueueResult{}, errors.New("enqueue forwarded event batch: nil batch")
	}
	if batch.GetSourceNodeId() != c.config.SourceNodeID || batch.GetProducerSessionId() != c.config.ProducerSessionID {
		return eventspool.EnqueueResult{}, errors.New("enqueue forwarded event batch: producer identity does not match fixed session")
	}
	result, err := c.spool.Enqueue(batch)
	c.afterEnqueue(result, err)
	return result, err
}

func (c *Client) flushPendingLosses(batchSequence uint64, semanticProfileRevision uint32) (eventspool.EnqueueResult, error) {
	result, err := c.spool.FlushPendingLosses(c.config.SourceNodeID, c.config.ProducerSessionID, batchSequence, semanticProfileRevision)
	c.afterEnqueue(result, err)
	return result, err
}

// FlushPendingLosses publishes one bounded durable loss carrier and wakes an
// active forwarding stream when the carrier commits. Terminal-sequence
// recovery uses this after older records drain enough capacity from the spool.
func (c *Client) FlushPendingLosses(batchSequence uint64, semanticProfileRevision uint32) (eventspool.EnqueueResult, error) {
	return c.flushPendingLosses(batchSequence, semanticProfileRevision)
}

func (c *Client) retainLosses(losses []*eventsv1.EventLoss) (eventspool.RetentionResult, error) {
	result, err := c.spool.RetainLosses(losses)
	if result.Committed {
		logCommittedCleanup(err)
	}
	return result, err
}

func (c *Client) pendingLossesRequireFlush(batchSequence uint64, semanticProfileRevision uint32) (bool, error) {
	return c.spool.PendingLossesRequireFlush(c.config.SourceNodeID, c.config.ProducerSessionID, batchSequence, semanticProfileRevision)
}

func (c *Client) afterEnqueue(result eventspool.EnqueueResult, err error) {
	if (result.Stored || result.Rejection != eventspool.RejectionNone || err == nil || errors.Is(err, eventspool.ErrRecordTooLarge)) && c.config.OnLoss != nil {
		for _, loss := range result.Losses {
			if loss != nil {
				c.config.OnLoss(loss.GetKind(), loss.GetCount())
			}
		}
	}
	if result.Stored {
		c.notify()
	}
	if result.Stored {
		logCommittedCleanup(err)
	}
}

func logCommittedCleanup(err error) {
	var cleanupErr *eventspool.CleanupError
	if errors.As(err, &cleanupErr) {
		logger.Warn("Event spool cleanup deferred after committed enqueue",
			"operation", cleanupErr.Operation,
			"path", cleanupErr.Path,
			"error", cleanupErr.Err,
			"logical_commit", true,
		)
	}
}

func (c *Client) Serve(ctx context.Context, stream Stream) error {
	if stream == nil {
		return errors.New("serve event forwarding: stream is required")
	}
	open := &eventsv1.EventIngressOpen{SourceNodeId: c.config.SourceNodeID, ProducerSessionId: c.config.ProducerSessionID, EventApiMajor: c.config.EventAPIMajor, SemanticProfileRevision: c.config.SemanticProfileRevision, EventKinds: append([]eventsv1.EventKind(nil), c.config.EventKinds...), Profile: c.config.Profile, RelayNodeId: c.config.RelayNodeID}
	if err := stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Open{Open: open}}); err != nil {
		return fmt.Errorf("serve event forwarding: send open: %w", err)
	}
	accepted, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("serve event forwarding: receive acceptance: %w", err)
	}
	if accepted.GetKind() != eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED {
		return fmt.Errorf("serve event forwarding: profile rejected: %s", accepted.GetError())
	}
	if accepted.GetAcceptedProfile() != c.config.Profile {
		return fmt.Errorf("serve event forwarding: processor accepted profile %s, requested %s", accepted.GetAcceptedProfile(), c.config.Profile)
	}

	controls := make(chan controlResult, 1)
	go receiveControls(ctx, stream, controls, c.controlReceived)
	// The initial retrieval observes everything committed before Serve starts;
	// discard the coalesced historical wake so an empty suffix does not cause a
	// redundant fetch. A concurrent enqueue is still visible in that retrieval.
	select {
	case <-c.wake:
	default:
	}
	highestSent := uint64(0)
	paused := false
	var cached []*eventsv1.ProtocolEventBatch
	needFetch := true
serveLoop:
	for {
		// Give ACK/NACK and flow-control messages priority between batches. This
		// bounds overshoot to one batch when the processor asks us to pause.
		select {
		case result := <-controls:
			var handleErr error
			var rewind bool
			paused, highestSent, rewind, handleErr = c.handleControl(ctx, result, paused, highestSent)
			if handleErr != nil {
				return handleErr
			}
			if rewind {
				cached = nil
				needFetch = true
			}
			continue
		default:
		}
		if !paused {
			if len(cached) == 0 && needFetch {
				var err error
				cached, err = c.spool.BatchesAfter(c.config.SourceNodeID, c.config.ProducerSessionID, highestSent, batchFetchLimit)
				c.batchFetches.Add(1)
				if err != nil {
					return fmt.Errorf("serve event forwarding: retrieve batches after %d: %w", highestSent, err)
				}
				needFetch = len(cached) == batchFetchLimit
			}
			for len(cached) > 0 {
				next := cached[0]
				cached[0] = nil
				cached = cached[1:]
				sequence := next.GetBatchSequence()
				if sequence <= highestSent || !c.spool.Contains(c.config.SourceNodeID, c.config.ProducerSessionID, sequence) {
					continue
				}
				if err := stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Batch{Batch: next}}); err != nil {
					return fmt.Errorf("serve event forwarding: send batch %d: %w", sequence, err)
				}
				highestSent = sequence
				continue serveLoop
			}
			// Removal may consume the entire cached suffix without sending a
			// batch. Fetch the next window before waiting: the enqueue wake may
			// already have been consumed while paused, and older ACK retirement
			// does not produce a wake at all.
			if needFetch {
				continue serveLoop
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
			needFetch = true
		case result := <-controls:
			var handleErr error
			var rewind bool
			paused, highestSent, rewind, handleErr = c.handleControl(ctx, result, paused, highestSent)
			if handleErr != nil {
				return handleErr
			}
			if rewind {
				cached = nil
				needFetch = true
			}
		}
	}
}

func (c *Client) handleControl(ctx context.Context, result controlResult, paused bool, highestSent uint64) (bool, uint64, bool, error) {
	if result.err != nil {
		if errors.Is(result.err, io.EOF) && ctx.Err() != nil {
			return paused, highestSent, false, ctx.Err()
		}
		return paused, highestSent, false, fmt.Errorf("serve event forwarding: receive control: %w", result.err)
	}
	ctrl := result.control
	switch ctrl.GetFlowControl() {
	case int32(data.FlowControl_FLOW_PAUSE):
		paused = true
	case int32(data.FlowControl_FLOW_RESUME), int32(data.FlowControl_FLOW_CONTINUE):
		paused = false
	case int32(data.FlowControl_FLOW_SLOW):
		timer := time.NewTimer(c.config.SlowInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return paused, highestSent, false, ctx.Err()
		case <-timer.C:
		}
	}
	switch ctrl.GetKind() {
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK:
		if err := c.spool.Ack(c.config.SourceNodeID, c.config.ProducerSessionID, ctrl.GetCumulativeAckSequence()); err != nil {
			return paused, highestSent, false, err
		}
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK:
		rewind := false
		for _, r := range ctrl.GetNackBatchRanges() {
			if r.GetFirst() > 0 && r.GetFirst() <= highestSent {
				highestSent = r.GetFirst() - 1
				rewind = true
			}
		}
		return paused, highestSent, rewind, nil
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW:
		// Flow state is handled above because processors may attach it to ACKs.
	}
	return paused, highestSent, false, nil
}

type controlResult struct {
	control *eventsv1.EventIngressControl
	err     error
}

func receiveControls(ctx context.Context, stream Stream, output chan<- controlResult, received func()) {
	for {
		ctrl, err := stream.Recv()
		select {
		case output <- controlResult{control: ctrl, err: err}:
			if received != nil {
				received()
			}
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *Client) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) reportLoss(kind eventsv1.LossKind, count uint64) {
	if count > 0 && c.config.OnLoss != nil {
		c.config.OnLoss(kind, count)
	}
}
