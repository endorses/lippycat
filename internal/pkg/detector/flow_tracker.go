package detector

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/viper"
)

// FlowTracker manages flow contexts for stateful protocol detection
type FlowTracker struct {
	flows      map[string]*signatures.FlowContext
	ttl        time.Duration
	maxEntries int
	capWarned  bool
	mu         sync.RWMutex
	done       chan struct{}
}

// NewFlowTracker creates a new flow tracker
func NewFlowTracker(ttl time.Duration) *FlowTracker {
	return NewFlowTrackerWithMaxEntries(ttl, viper.GetInt("detector.max_flows"))
}

// NewFlowTrackerWithMaxEntries creates a new flow tracker with a hard entry cap.
// A maxEntries value of zero or less disables cap-based eviction.
func NewFlowTrackerWithMaxEntries(ttl time.Duration, maxEntries int) *FlowTracker {
	tracker := &FlowTracker{
		flows:      make(map[string]*signatures.FlowContext),
		ttl:        ttl,
		maxEntries: maxEntries,
		done:       make(chan struct{}),
	}

	// Start cleanup goroutine
	go tracker.cleanup()

	return tracker
}

// GetOrCreate retrieves an existing flow or creates a new one
func (f *FlowTracker) GetOrCreate(flowID string) *signatures.FlowContext {
	f.mu.Lock()
	defer f.mu.Unlock()

	flow, ok := f.flows[flowID]
	if !ok {
		f.evictOldestLocked()
		flow = &signatures.FlowContext{
			FlowID:    flowID,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Protocols: make([]string, 0),
			Metadata:  make(map[string]interface{}),
		}
		f.flows[flowID] = flow
	}

	return flow
}

func (f *FlowTracker) evictOldestLocked() {
	if f.maxEntries <= 0 || len(f.flows) < f.maxEntries {
		return
	}

	var oldestFlowID string
	var oldestLastSeen time.Time
	for flowID, flow := range f.flows {
		if oldestFlowID == "" || flow.LastSeen.Before(oldestLastSeen) {
			oldestFlowID = flowID
			oldestLastSeen = flow.LastSeen
		}
	}
	if oldestFlowID == "" {
		return
	}

	delete(f.flows, oldestFlowID)
	if !f.capWarned {
		logger.Warn("Detector flow cap reached, evicting oldest flow",
			"max_entries", f.maxEntries)
		f.capWarned = true
	}
}

// Get retrieves a flow context
func (f *FlowTracker) Get(flowID string) *signatures.FlowContext {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.flows[flowID]
}

// Delete removes a flow from tracking
func (f *FlowTracker) Delete(flowID string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.flows, flowID)
}

// Clear removes all flows
func (f *FlowTracker) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.flows = make(map[string]*signatures.FlowContext)
}

// Size returns the number of tracked flows
func (f *FlowTracker) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return len(f.flows)
}

// cleanup periodically removes expired flows
func (f *FlowTracker) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.mu.Lock()
			now := time.Now()
			for flowID, flow := range f.flows {
				if now.Sub(flow.LastSeen) > f.ttl {
					delete(f.flows, flowID)
				}
			}
			f.mu.Unlock()
		case <-f.done:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (f *FlowTracker) Close() {
	select {
	case <-f.done:
		// Already closed
		return
	default:
		close(f.done)
	}
}
