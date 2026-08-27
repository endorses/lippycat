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
	hasUpstream           bool
	upstreamQueueDepth    func() int
	upstreamQueueCapacity func() int
	state                 atomic.Int32
}

// QueuePressureSource describes a processor-level bounded queue.
type QueuePressureSource struct {
	Name     string
	Depth    func() int
	Capacity func() int
}

// SetUpstreamQueue sets the real outstanding upstream queue metrics. These
// supersede lifetime received/forwarded counter subtraction when configured.
func (c *Controller) SetUpstreamQueue(depthFn func() int, capacityFn func() int) {
	c.upstreamQueueDepth = depthFn
	c.upstreamQueueCapacity = capacityFn
}

func severity(control data.FlowControl) int {
	switch control {
	case data.FlowControl_FLOW_PAUSE:
		return 3
	case data.FlowControl_FLOW_SLOW:
		return 2
	case data.FlowControl_FLOW_RESUME:
		return 1
	default:
		return 0
	}
}

func moreSevere(current, candidate data.FlowControl) data.FlowControl {
	if severity(candidate) > severity(current) {
		return candidate
	}
	return current
}

// NewController creates a new flow controller
func NewController(hasUpstream bool) *Controller {
	c := &Controller{
		hasUpstream: hasUpstream,
		sources:     make(map[string]QueuePressureSource),
	}
	c.state.Store(int32(data.FlowControl_FLOW_CONTINUE))
	return c
}

// transition applies queue hysteresis. Escalation is immediate, while SLOW and
// PAUSE are held until every pressure source drains below the resume threshold.
// RESUME is an observable release signal; the next neutral sample becomes
// CONTINUE.
func transition(previous, pressure data.FlowControl) data.FlowControl {
	if pressure == data.FlowControl_FLOW_PAUSE {
		return pressure
	}
	if previous == data.FlowControl_FLOW_PAUSE {
		if pressure == data.FlowControl_FLOW_RESUME {
			return pressure
		}
		return previous
	}
	if pressure == data.FlowControl_FLOW_SLOW {
		return pressure
	}
	if previous == data.FlowControl_FLOW_SLOW {
		if pressure == data.FlowControl_FLOW_RESUME {
			return pressure
		}
		return previous
	}
	return pressure
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
	pressureSources := 0
	allSourcesBelowResume := true

	c.mu.RLock()
	sources := make([]QueuePressureSource, 0, len(c.sources))
	for _, source := range c.sources {
		sources = append(sources, source)
	}
	c.mu.RUnlock()

	for _, source := range sources {
		queueDepth := source.Depth()
		queueCapacity := source.Capacity()

		if queueCapacity > 0 {
			pressureSources++
			utilization := float64(queueDepth) / float64(queueCapacity)
			allSourcesBelowResume = allSourcesBelowResume && utilization < constants.FlowControlResumeThreshold
			utilizationPct := utilization * 100

			// Pause if queue is critically full (>90%)
			if utilization > constants.FlowControlPauseThreshold {
				logger.Warn("Processor queue critically full - requesting pause",
					"queue", source.Name,
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				mostSevere = data.FlowControl_FLOW_PAUSE
			} else if utilization > constants.FlowControlSlowThreshold {
				// Slow down if queue is getting full (>70%)
				logger.Debug("Processor queue filling - requesting slowdown",
					"queue", source.Name,
					"queue_depth", queueDepth,
					"capacity", queueCapacity,
					"utilization", utilizationPct)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_SLOW)
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
	if c.hasUpstream && c.upstreamQueueDepth != nil && c.upstreamQueueCapacity != nil {
		depth, capacity := c.upstreamQueueDepth(), c.upstreamQueueCapacity()
		if capacity > 0 {
			pressureSources++
			utilization := float64(depth) / float64(capacity)
			allSourcesBelowResume = allSourcesBelowResume && utilization < constants.FlowControlResumeThreshold
			if utilization > constants.FlowControlSlowThreshold {
				logger.Warn("Upstream queue filling - requesting slowdown",
					"queue_depth", depth, "capacity", capacity)
				mostSevere = moreSevere(mostSevere, data.FlowControl_FLOW_SLOW)
			}
		}
	}

	// RESUME is a release signal, not a pressure level. Emitting it when only
	// one queue has drained can prematurely release hysteresis while another
	// queue remains above the low watermark. Require every configured, valid
	// pressure source to be below the resume threshold.
	if mostSevere == data.FlowControl_FLOW_CONTINUE && pressureSources > 0 && allSourcesBelowResume {
		mostSevere = data.FlowControl_FLOW_RESUME
	}

	for {
		previousRaw := c.state.Load()
		next := transition(data.FlowControl(previousRaw), mostSevere)
		if c.state.CompareAndSwap(previousRaw, int32(next)) {
			return next
		}
	}
}
