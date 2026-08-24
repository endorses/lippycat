package flow

import (
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Controller manages flow control signals to hunters
type Controller struct {
	mu      sync.RWMutex
	sources map[string]QueuePressureSource

	// Upstream forwarding metrics (if enabled)
	packetsReceived  *atomic.Uint64
	packetsForwarded *atomic.Uint64
	hasUpstream      bool
}

// QueuePressureSource describes a processor-level bounded queue.
type QueuePressureSource struct {
	Name     string
	Depth    func() int
	Capacity func() int
}

// NewController creates a new flow controller
func NewController(packetsReceived, packetsForwarded *atomic.Uint64, hasUpstream bool) *Controller {
	return &Controller{
		sources:          make(map[string]QueuePressureSource),
		packetsReceived:  packetsReceived,
		packetsForwarded: packetsForwarded,
		hasUpstream:      hasUpstream,
	}
}

// SetPCAPQueue sets the PCAP queue metrics functions
func (c *Controller) SetPCAPQueue(depthFn func() int, capacityFn func() int) {
	c.SetQueueSource(QueuePressureSource{Name: "pcap", Depth: depthFn, Capacity: capacityFn})
}

// SetQueueSource adds or replaces a named processor-level pressure source.
func (c *Controller) SetQueueSource(source QueuePressureSource) {
	if source.Name == "" || source.Depth == nil || source.Capacity == nil {
		return
	}
	c.mu.Lock()
	c.sources[source.Name] = source
	c.mu.Unlock()
}

// Determine determines appropriate flow control signal based on processor load
// Checks all pressure sources and returns the most severe signal (PAUSE > SLOW > RESUME > CONTINUE)
func (c *Controller) Determine() data.FlowControl {
	mostSevere := data.FlowControl_FLOW_CONTINUE

	c.mu.RLock()
	sources := make([]QueuePressureSource, 0, len(c.sources))
	for _, source := range c.sources {
		sources = append(sources, source)
	}
	c.mu.RUnlock()
	if len(sources) > 0 {
		mostSevere = data.FlowControl_FLOW_RESUME
	}
	for _, source := range sources {
		queueDepth := source.Depth()
		queueCapacity := source.Capacity()

		if queueCapacity > 0 {
			utilization := float64(queueDepth) / float64(queueCapacity)
			utilizationPct := utilization * 100

			// Pause if queue is critically full (>90%)
			if utilization > constants.FlowControlPauseThreshold {
				logger.Warn("Processor queue critically full - requesting pause",
					"queue", source.Name,
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_PAUSE)
			} else if utilization > constants.FlowControlSlowThreshold {
				// Slow down if queue is getting full (>70%)
				logger.Debug("Processor queue filling - requesting slowdown",
					"queue", source.Name,
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_SLOW)
			} else if utilization < constants.FlowControlResumeThreshold {
				// Resume if queue has drained (< 30%)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_RESUME)
			} else {
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_CONTINUE)
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
			if backlog > constants.FlowControlUpstreamBacklogThreshold {
				logger.Warn("Large packet backlog detected - requesting slowdown",
					"backlog", backlog)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_SLOW)
			}
		}
	}

	return mostSevere
}

func moreSevere(current, candidate data.FlowControl) data.FlowControl {
	rank := func(value data.FlowControl) int {
		switch value {
		case data.FlowControl_FLOW_PAUSE:
			return 3
		case data.FlowControl_FLOW_SLOW:
			return 2
		case data.FlowControl_FLOW_CONTINUE:
			return 1
		default:
			return 0
		}
	}
	if rank(candidate) > rank(current) {
		return candidate
	}
	return current
}
