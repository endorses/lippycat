// File: client_subscriptions.go - Hunter status, topology, and call subscriptions
//
// Manages subscriptions to hunter status updates, topology changes, and
// active call information from the remote processor.

package remotecapture

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// SubscribeTopology subscribes to real-time topology updates from a processor
func (c *Client) SubscribeTopology() error {
	// Only works for processors
	if c.nodeType == NodeTypeHunter {
		return fmt.Errorf("topology subscription is only available from processor nodes")
	}

	// Create subscription request
	req := &management.TopologySubscribeRequest{}

	// Start topology stream
	stream, err := c.mgmtClient.SubscribeTopology(c.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to subscribe to topology: %w", err)
	}

	// Start goroutine to receive topology updates
	go func() {
		for {
			update, err := stream.Recv()
			if err != nil {
				// Don't report error if context was cancelled (normal shutdown)
				if c.ctx.Err() == nil && c.handler != nil {
					// Notify handler of disconnection
					c.handler.OnDisconnect(c.addr, fmt.Errorf("topology stream error: %w", err))
				}
				return
			}

			// Send topology update to handler
			if c.handler != nil {
				c.handler.OnTopologyUpdate(update, c.addr)
			}
		}
	}()

	return nil
}

// SubscribeHunterStatus subscribes to hunter status updates
func (c *Client) SubscribeHunterStatus() error {
	// Only works for processors - hunters don't have GetHunterStatus
	if c.nodeType == NodeTypeHunter {
		// For direct hunter connection, create a single HunterInfo entry
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-c.ctx.Done():
					return
				case <-ticker.C:
					// Create hunter info for this direct connection
					hunters := []types.HunterInfo{
						{
							ID:            c.nodeID,
							Hostname:      c.addr,
							RemoteAddr:    c.addr,
							Status:        management.HunterStatus_STATUS_HEALTHY,
							ProcessorAddr: "Direct", // Direct hunter connection (no processor)
							// Stats will be inferred from packet stream
						},
					}
					if c.handler != nil {
						// Direct hunter: no processor ID or upstream
						c.handler.OnHunterStatus(hunters, "", management.ProcessorStatus_PROCESSOR_HEALTHY, c.addr, "")
					}
				}
			}
		}()
		return nil
	}

	// For processors, poll GetHunterStatus
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				resp, err := c.mgmtClient.GetHunterStatus(c.ctx, &management.StatusRequest{})
				if err != nil {
					// Don't report error if context was cancelled (normal shutdown)
					if c.ctx.Err() == nil && c.handler != nil {
						// Notify handler of disconnection
						c.handler.OnDisconnect(c.addr, fmt.Errorf("hunter status error: %w", err))
					}
					return
				}

				// Update interface mapping
				c.interfacesMu.Lock()
				for _, h := range resp.Hunters {
					if len(h.Interfaces) > 0 {
						c.interfaces[h.HunterId] = h.Interfaces
					}
				}
				c.interfacesMu.Unlock()

				// Convert to HunterInfo list
				hunters := make([]types.HunterInfo, len(resp.Hunters))
				for i, h := range resp.Hunters {
					hunters[i] = c.convertToHunterInfo(h)
				}

				// Get processor ID, status, and upstream from stats
				processorID := ""
				processorStatus := management.ProcessorStatus_PROCESSOR_HEALTHY
				upstreamProcessor := ""
				if resp.ProcessorStats != nil {
					processorID = resp.ProcessorStats.ProcessorId
					processorStatus = resp.ProcessorStats.Status
					upstreamProcessor = resp.ProcessorStats.UpstreamProcessor
				}

				// Send to handler with processor address and upstream info
				if c.handler != nil {
					c.handler.OnHunterStatus(hunters, processorID, processorStatus, c.addr, upstreamProcessor)
				}
			}
		}
	}()

	return nil
}

// SubscribeCorrelatedCalls subscribes to correlated call updates from processor
func (c *Client) SubscribeCorrelatedCalls() error {
	// Only works for processors
	if c.nodeType == NodeTypeHunter {
		return fmt.Errorf("correlated calls are only available from processor nodes")
	}

	go func() {
		// Subscribe to correlated calls stream
		stream, err := c.dataClient.SubscribeCorrelatedCalls(c.ctx, &data.SubscribeRequest{})
		if err != nil {
			if c.handler != nil {
				c.handler.OnDisconnect(c.addr, fmt.Errorf("failed to subscribe to correlated calls: %w", err))
			}
			return
		}

		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				update, err := stream.Recv()
				if err != nil {
					if c.ctx.Err() == nil {
						if c.handler != nil {
							c.handler.OnDisconnect(c.addr, fmt.Errorf("correlated calls stream error: %w", err))
						}
					}
					return
				}

				// Convert protobuf to types.CorrelatedCallInfo
				correlatedCall := types.CorrelatedCallInfo{
					CorrelationID: update.CorrelationId,
					TagPair:       [2]string{update.TagPair[0], update.TagPair[1]},
					FromUser:      update.FromUser,
					ToUser:        update.ToUser,
					StartTime:     time.Unix(0, update.StartTimeNs),
					LastSeen:      time.Unix(0, update.LastSeenNs),
					State:         update.State,
				}

				// Convert legs
				correlatedCall.Legs = make([]types.CallLegInfo, len(update.Legs))
				for i, leg := range update.Legs {
					correlatedCall.Legs[i] = types.CallLegInfo{
						CallID:       leg.CallId,
						HunterID:     leg.HunterId,
						SrcIP:        leg.SrcIp,
						DstIP:        leg.DstIp,
						Method:       leg.Method,
						ResponseCode: leg.ResponseCode,
						PacketCount:  int(leg.PacketCount),
						StartTime:    time.Unix(0, leg.StartTimeNs),
						LastSeen:     time.Unix(0, leg.LastSeenNs),
					}
				}

				// Notify handler
				if c.handler != nil {
					c.handler.OnCorrelatedCallUpdate([]types.CorrelatedCallInfo{correlatedCall})
				}
			}
		}
	}()

	return nil
}
