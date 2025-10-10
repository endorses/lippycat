package detector

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// FlowTracker manages flow contexts for stateful protocol detection
type FlowTracker struct {
	flows map[string]*signatures.FlowContext
	ttl   time.Duration
	mu    sync.RWMutex
	done  chan struct{}
}

// NewFlowTracker creates a new flow tracker
func NewFlowTracker(ttl time.Duration) *FlowTracker {
	tracker := &FlowTracker{
		flows: make(map[string]*signatures.FlowContext),
		ttl:   ttl,
		done:  make(chan struct{}),
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
