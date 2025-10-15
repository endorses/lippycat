package flow

import (
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Controller manages flow control signals to hunters
type Controller struct {
	// PCAP writer queue metrics (if enabled)
	pcapQueueDepth    func() int
	pcapQueueCapacity func() int

	// Upstream forwarding metrics (if enabled)
	packetsReceived  *atomic.Uint64
	packetsForwarded *atomic.Uint64
	hasUpstream      bool
}

// NewController creates a new flow controller
func NewController(packetsReceived, packetsForwarded *atomic.Uint64, hasUpstream bool) *Controller {
	return &Controller{
		packetsReceived:  packetsReceived,
		packetsForwarded: packetsForwarded,
		hasUpstream:      hasUpstream,
	}
}

// SetPCAPQueue sets the PCAP queue metrics functions
func (c *Controller) SetPCAPQueue(depthFn func() int, capacityFn func() int) {
	c.pcapQueueDepth = depthFn
	c.pcapQueueCapacity = capacityFn
}

// Determine determines appropriate flow control signal based on processor load
// Checks all pressure sources and returns the most severe signal (PAUSE > SLOW > RESUME > CONTINUE)
func (c *Controller) Determine() data.FlowControl {
	mostSevere := data.FlowControl_FLOW_CONTINUE

	// Check PCAP write queue depth if configured
	if c.pcapQueueDepth != nil && c.pcapQueueCapacity != nil {
		queueDepth := c.pcapQueueDepth()
		queueCapacity := c.pcapQueueCapacity()

		if queueCapacity > 0 {
			utilizationPct := float64(queueDepth) / float64(queueCapacity) * 100

			// Pause if queue is critically full (>90%)
			if utilizationPct > 90 {
				logger.Warn("PCAP write queue critically full - requesting pause",
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				mostSevere = data.FlowControl_FLOW_PAUSE
			} else if utilizationPct > 70 {
				// Slow down if queue is getting full (>70%)
				logger.Debug("PCAP write queue filling - requesting slowdown",
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				if mostSevere < data.FlowControl_FLOW_SLOW {
					mostSevere = data.FlowControl_FLOW_SLOW
				}
			} else if utilizationPct < 30 {
				// Resume if queue has drained (< 30%)
				if mostSevere < data.FlowControl_FLOW_RESUME {
					mostSevere = data.FlowControl_FLOW_RESUME
				}
			}
		}
	}

	// NOTE: We do NOT check subscriber backpressure here!
	// TUI client drops should NOT pause hunters because:
	// 1. Hunters serve multiple consumers (other TUI clients, file writes, upstream processors)
	// 2. TUI disconnects/reconnects cause temporary drops that shouldn't affect hunters
	// 3. Slow TUI clients are already handled by per-subscriber channel buffering & drops
	// Hunters should only pause for processor-level overload (PCAP write queue, upstream backlog)

	// Check overall packet processing load (only if upstream forwarding is configured)
	// If no upstream processor, packets are only consumed by TUI subscribers, not forwarded
	if c.hasUpstream && c.packetsReceived != nil && c.packetsForwarded != nil {
		packetsReceived := c.packetsReceived.Load()
		packetsForwarded := c.packetsForwarded.Load()

		// If we're significantly behind in forwarding, slow down
		if packetsReceived > packetsForwarded {
			backlog := packetsReceived - packetsForwarded
			if backlog > 10000 {
				logger.Warn("Large packet backlog detected - requesting slowdown",
					"backlog", backlog)
				if mostSevere < data.FlowControl_FLOW_SLOW {
					mostSevere = data.FlowControl_FLOW_SLOW
				}
			}
		}
	}

	return mostSevere
}
