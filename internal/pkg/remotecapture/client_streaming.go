// File: client_streaming.go - Packet streaming and hot-swapping
//
// Handles the main packet streaming loop, dynamic EventHandler swapping,
// batch processing, and flow control coordination with the processor.

package remotecapture

import (
	"context"
	"fmt"
	"io"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StreamPackets starts receiving packet stream from remote node
func (c *Client) StreamPackets() error {
	return c.StreamPacketsWithFilter(nil)
}

// StreamPacketsWithFilter starts receiving packet stream from remote node with hunter filter
func (c *Client) StreamPacketsWithFilter(hunterIDs []string) error {
	// Cancel any existing stream before starting a new one
	c.streamMu.Lock()
	if c.streamCancel != nil {
		c.streamCancel()
	}

	// Create a new context for this stream
	streamCtx, streamCancel := context.WithCancel(c.ctx)
	c.streamCancel = streamCancel
	c.currentHunters = hunterIDs
	c.streamMu.Unlock()

	// Subscribe to packet stream using the new SubscribePackets RPC
	// ClientId is omitted - processor will auto-generate a unique ID
	req := &data.SubscribeRequest{
		HunterIds:       hunterIDs,        // Filter by specific hunters
		HasHunterFilter: hunterIDs != nil, // Set flag to distinguish nil from []
	}

	stream, err := c.dataClient.SubscribePackets(streamCtx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to packets: %w", err)
	}

	// Event delivery is an independent, best-effort side stream. Older nodes do
	// not implement EventService; that must never prevent packet monitoring.
	go c.startEventStream(streamCtx, hunterIDs)

	// Start goroutine to receive packets
	// Note: gRPC keepalive (30s ping + 20s timeout) detects dead connections
	// No additional health monitoring needed
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Notify handler of disconnection after panic
				if c.handler != nil {
					c.handler.OnDisconnect(c.addr, fmt.Errorf("panic in packet receiver: %v", r))
				}
			}
		}()

		for {
			select {
			case <-streamCtx.Done():
				// Stream context cancelled (hot-swap or shutdown)
				return
			case <-c.ctx.Done():
				// Client context cancelled, normal shutdown
				return
			default:
				batch, err := stream.Recv()
				if err != nil {
					// Don't report error if context was cancelled (normal shutdown or hot-swap)
					if streamCtx.Err() != nil || c.ctx.Err() != nil {
						// Shutdown or hot-swap in progress, exit gracefully
						return
					}
					if c.handler != nil {
						// Notify handler of disconnection
						c.handler.OnDisconnect(c.addr, fmt.Errorf("stream error: %w", err))
					}
					return
				}

				// Convert entire batch to PacketDisplay and send to handler
				if c.handler != nil && len(batch.Packets) > 0 {
					displays := make([]types.PacketDisplay, 0, len(batch.Packets))
					callEnded := false
					for _, pkt := range batch.Packets {
						display := c.convertToPacketDisplay(pkt, batch.HunterId)
						displays = append(displays, display)

						// Update call state from VoIP metadata
						if pkt.Metadata != nil {
							if pkt.Metadata.Sip != nil {
								if c.updateCallState(pkt, batch.HunterId) {
									callEnded = true
								}
							}
							// Update RTP quality metrics
							if pkt.Metadata.Rtp != nil {
								c.updateRTPQuality(pkt)
							}
						}
					}
					// Send entire batch to handler
					c.handler.OnPacketBatch(displays)

					// Notify handler of call updates. Force the notification when
					// a call just ended so the terminal state isn't lost to the
					// throttle if this batch is the call's last traffic.
					c.maybeNotifyCallUpdates(callEnded)
				}
			}
		}
	}()

	return nil
}

func (c *Client) startEventStream(ctx context.Context, nodeIDs []string) {
	if nodeIDs != nil && len(nodeIDs) == 0 {
		return
	}
	c.eventCursorMu.Lock()
	previousStreamID := c.eventStreamID
	previousDeliverySequence := c.eventDeliverySequence
	c.eventCursorMu.Unlock()

	stream, err := c.eventClient.SubscribeEvents(ctx, &eventsv1.EventSubscribeRequest{
		SubscriptionVersion:      1,
		NodeIds:                  nodeIDs,
		MaxBatchEvents:           128,
		MaxMessageBytes:          4 << 20,
		PreviousStreamId:         previousStreamID,
		PreviousDeliverySequence: previousDeliverySequence,
	})
	if err != nil {
		// SubscribeEvents may return Unimplemented immediately on legacy servers.
		return
	}

	go c.receiveEvents(ctx, stream)
}

func (c *Client) receiveEvents(ctx context.Context, stream eventsv1.EventService_SubscribeEventsClient) {
	var streamID string
	var deliverySequence uint64
	started := false
	for {
		message, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil || c.ctx.Err() != nil || err == io.EOF || status.Code(err) == codes.Unimplemented {
				return
			}
			// The packet subscription remains authoritative for connection health.
			// Surface an event-only transport gap without triggering reconnect.
			c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
			return
		}
		if message == nil || message.DeliverySequence == 0 || message.DeliverySequence != deliverySequence+1 {
			c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
			return
		}
		deliverySequence = message.DeliverySequence

		switch payload := message.Message.(type) {
		case *eventsv1.EventSubscriptionMessage_Control:
			control := payload.Control
			if control == nil || control.DeliverySequence != deliverySequence || control.StreamId == "" || (streamID != "" && control.StreamId != streamID) {
				c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
				return
			}
			if (!started && control.Kind != eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED) || (started && control.Kind == eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED) || control.Kind == eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_UNSPECIFIED {
				c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
				return
			}
			streamID = control.StreamId
			batch := types.EventBatch{Losses: convertEventLosses(control.Losses), StreamID: streamID, DeliverySequence: deliverySequence}
			if control.Kind == eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED {
				started = true
				batch.CompatibilityOmissions = unsupportedEventKindCount(control.SupportedEventKinds)
			}
			if len(batch.Losses) > 0 || batch.CompatibilityOmissions > 0 {
				c.deliverEventBatch(batch)
			}
		case *eventsv1.EventSubscriptionMessage_Batch:
			if streamID == "" {
				c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, DeliverySequence: deliverySequence})
				return
			}
			events, omissions, decodeErr := protoadapter.DecodeBatch(payload.Batch)
			if decodeErr != nil {
				c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
				return
			}
			c.deliverEventBatch(types.EventBatch{Events: events, Losses: convertEventLosses(payload.Batch.GetStats().GetLosses()), CompatibilityOmissions: uint64(len(omissions)), StreamID: streamID, DeliverySequence: deliverySequence})
		default:
			c.deliverEventBatch(types.EventBatch{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 1}}, StreamID: streamID, DeliverySequence: deliverySequence})
		}

		c.eventCursorMu.Lock()
		c.eventStreamID = streamID
		c.eventDeliverySequence = deliverySequence
		c.eventCursorMu.Unlock()
	}
}

func (c *Client) deliverEventBatch(batch types.EventBatch) {
	if c.handler != nil {
		c.handler.OnEventBatch(batch)
	}
}

func convertEventLosses(losses []*eventsv1.EventLoss) []types.EventLoss {
	out := make([]types.EventLoss, 0, len(losses))
	for _, loss := range losses {
		if loss == nil {
			continue
		}
		converted := types.EventLoss{Kind: loss.Kind, Count: loss.Count, SourceNodeID: loss.SourceNodeId, ProducerSessionID: loss.ProducerSessionId, SequenceRanges: make([]types.EventSequenceRange, 0, len(loss.EventSequenceRanges))}
		// Reconnect boundaries can have no measurable event count but still
		// represent one observable transport-loss incident to the consumer.
		if converted.Count == 0 && converted.Kind == eventsv1.LossKind_LOSS_KIND_RECONNECT {
			converted.Count = 1
		}
		for _, sequenceRange := range loss.EventSequenceRanges {
			if sequenceRange != nil {
				converted.SequenceRanges = append(converted.SequenceRanges, types.EventSequenceRange{First: sequenceRange.First, Last: sequenceRange.Last})
			}
		}
		out = append(out, converted)
	}
	return out
}

func unsupportedEventKindCount(supported []eventsv1.EventKind) uint64 {
	available := make(map[eventsv1.EventKind]struct{}, len(supported))
	for _, kind := range supported {
		available[kind] = struct{}{}
	}
	wanted := [...]eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_CONN, eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_TLS, eventsv1.EventKind_EVENT_KIND_HTTP, eventsv1.EventKind_EVENT_KIND_SMTP}
	var missing uint64
	for _, kind := range wanted {
		if _, ok := available[kind]; !ok {
			missing++
		}
	}
	return missing
}

// UpdateSubscription hot-swaps the hunter subscription without reconnecting
// This enables seamless subscription changes with zero packet loss
func (c *Client) UpdateSubscription(hunterIDs []string) error {
	c.streamMu.RLock()
	// Check if subscription is already the same
	if slicesEqual(c.currentHunters, hunterIDs) {
		c.streamMu.RUnlock()
		return nil // No change needed
	}
	c.streamMu.RUnlock()

	// Start new subscription (this will cancel the old stream automatically)
	return c.StreamPacketsWithFilter(hunterIDs)
}
