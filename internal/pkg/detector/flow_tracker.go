package detector

import (
	"container/heap"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/viper"
)

const flowCapWarningInterval = time.Minute

// FlowTracker manages flow contexts for stateful protocol detection
type FlowTracker struct {
	flows           map[string]*signatures.FlowContext
	ttl             time.Duration
	maxEntries      int
	lastCapWarning  time.Time
	evictionScratch []flowEvictionCandidate
	mu              sync.RWMutex
	done            chan struct{}
}

type flowEvictionCandidate struct {
	flowID   string
	lastSeen time.Time
}

// flowEvictionHeap is a max-heap: the newest retained candidate is at the root
// and can be replaced whenever the scan encounters an older flow.
type flowEvictionHeap []flowEvictionCandidate

func (h flowEvictionHeap) Len() int { return len(h) }
func (h flowEvictionHeap) Less(i, j int) bool {
	return flowCandidateOlder(h[j], h[i])
}
func (h flowEvictionHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *flowEvictionHeap) Push(value any) {
	*h = append(*h, value.(flowEvictionCandidate))
}
func (h *flowEvictionHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = flowEvictionCandidate{}
	*h = old[:last]
	return value
}

func flowCandidateOlder(a, b flowEvictionCandidate) bool {
	if a.lastSeen.Equal(b.lastSeen) {
		return a.flowID < b.flowID
	}
	return a.lastSeen.Before(b.lastSeen)
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
		f.evictOldestBatchLocked()
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

func (f *FlowTracker) evictOldestBatchLocked() {
	if f.maxEntries <= 0 || len(f.flows) < f.maxEntries {
		return
	}

	batchSize := f.maxEntries / 10
	if batchSize < 1 {
		batchSize = 1
	}
	// Recover safely if the map is already oversized (for example after a
	// configuration change): leave enough room for the pending insertion.
	if required := len(f.flows) - f.maxEntries + 1; required > batchSize {
		batchSize = required
	}
	// The scratch slice belongs to FlowTracker and may only be accessed while
	// f.mu is write-locked. Clear it before reuse and after selection so flow
	// IDs from removed entries are not retained between pressure episodes.
	f.evictionScratch = f.evictionScratch[:0]
	for flowID, flow := range f.flows {
		candidate := flowEvictionCandidate{
			flowID:   flowID,
			lastSeen: flow.LastSeen,
		}
		if len(f.evictionScratch) < batchSize {
			f.evictionScratch = append(f.evictionScratch, candidate)
			if len(f.evictionScratch) == batchSize {
				heap.Init((*flowEvictionHeap)(&f.evictionScratch))
			}
			continue
		}
		if flowCandidateOlder(candidate, f.evictionScratch[0]) {
			f.evictionScratch[0] = candidate
			heap.Fix((*flowEvictionHeap)(&f.evictionScratch), 0)
		}
	}
	if batchSize > len(f.evictionScratch) {
		batchSize = len(f.evictionScratch)
	}
	for i := 0; i < batchSize; i++ {
		delete(f.flows, f.evictionScratch[i].flowID)
	}
	if now := time.Now(); f.capWarningEligibleLocked(now) {
		logger.Warn("Detector flow cap reached, evicting oldest flow batch",
			"max_entries", f.maxEntries,
			"evicted", batchSize)
		f.lastCapWarning = now
	}
	clear(f.evictionScratch[:cap(f.evictionScratch)])
	f.evictionScratch = f.evictionScratch[:0]
}

// capWarningEligibleLocked reports whether cap pressure may be logged now.
// Callers must hold f.mu for writing. The interval keeps sustained pressure
// observable without emitting a warning for every eviction batch.
func (f *FlowTracker) capWarningEligibleLocked(now time.Time) bool {
	return f.lastCapWarning.IsZero() || now.Sub(f.lastCapWarning) >= flowCapWarningInterval
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
