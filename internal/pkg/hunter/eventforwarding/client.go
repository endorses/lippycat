// Package eventforwarding implements the hunter side of normalized event ingestion.
package eventforwarding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
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
}

func (c *Client) ProducerSessionID() string { return c.config.ProducerSessionID }

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
	if err == nil && c.config.OnLoss != nil {
		for _, loss := range result.Losses {
			if loss != nil {
				c.config.OnLoss(loss.GetKind(), loss.GetCount())
			}
		}
	}
	if err == nil && result.Stored {
		c.notify()
	}
	return result, err
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
	go receiveControls(ctx, stream, controls)
	highestSent := uint64(0)
	paused := false
	for {
		// Give ACK/NACK and flow-control messages priority between batches. This
		// bounds overshoot to one batch when the processor asks us to pause.
		select {
		case result := <-controls:
			var handleErr error
			paused, highestSent, handleErr = c.handleControl(ctx, result, paused, highestSent)
			if handleErr != nil {
				return handleErr
			}
			continue
		default:
		}
		if !paused {
			var next *eventsv1.ProtocolEventBatch
			for _, b := range c.spool.Batches() {
				if b.GetBatchSequence() > highestSent {
					next = b
					break
				}
			}
			if next != nil {
				if err := stream.Send(&eventsv1.EventIngressMessage{Message: &eventsv1.EventIngressMessage_Batch{Batch: next}}); err != nil {
					return fmt.Errorf("serve event forwarding: send batch %d: %w", next.GetBatchSequence(), err)
				}
				highestSent = next.GetBatchSequence()
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
		case result := <-controls:
			var handleErr error
			paused, highestSent, handleErr = c.handleControl(ctx, result, paused, highestSent)
			if handleErr != nil {
				return handleErr
			}
		}
	}
}

func (c *Client) handleControl(ctx context.Context, result controlResult, paused bool, highestSent uint64) (bool, uint64, error) {
	if result.err != nil {
		if errors.Is(result.err, io.EOF) && ctx.Err() != nil {
			return paused, highestSent, ctx.Err()
		}
		return paused, highestSent, fmt.Errorf("serve event forwarding: receive control: %w", result.err)
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
			return paused, highestSent, ctx.Err()
		case <-timer.C:
		}
	}
	switch ctrl.GetKind() {
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK:
		if err := c.spool.Ack(c.config.SourceNodeID, c.config.ProducerSessionID, ctrl.GetCumulativeAckSequence()); err != nil {
			return paused, highestSent, err
		}
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK:
		for _, r := range ctrl.GetNackBatchRanges() {
			if r.GetFirst() > 0 && r.GetFirst() <= highestSent {
				highestSent = r.GetFirst() - 1
			}
		}
	case eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW:
		// Flow state is handled above because processors may attach it to ACKs.
	}
	return paused, highestSent, nil
}

type controlResult struct {
	control *eventsv1.EventIngressControl
	err     error
}

func receiveControls(ctx context.Context, stream Stream, output chan<- controlResult) {
	for {
		ctrl, err := stream.Recv()
		select {
		case output <- controlResult{control: ctrl, err: err}:
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
