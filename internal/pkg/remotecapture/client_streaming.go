// File: client_streaming.go - Packet streaming and hot-swapping
//
// Handles the main packet streaming loop, dynamic EventHandler swapping,
// batch processing, and flow control coordination with the processor.

package remotecapture

import (
	"context"
	"fmt"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/types"
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
					for _, pkt := range batch.Packets {
						display := c.convertToPacketDisplay(pkt, batch.HunterId)
						displays = append(displays, display)

						// Update call state from VoIP metadata
						if pkt.Metadata != nil {
							if pkt.Metadata.Sip != nil {
								c.updateCallState(pkt, batch.HunterId)
							}
							// Update RTP quality metrics
							if pkt.Metadata.Rtp != nil {
								c.updateRTPQuality(pkt)
							}
						}
					}
					// Send entire batch to handler
					c.handler.OnPacketBatch(displays)

					// Periodically notify handler of call updates
					c.maybeNotifyCallUpdates()
				}
			}
		}
	}()

	return nil
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
