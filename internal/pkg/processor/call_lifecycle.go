//go:build processor || tap || all

package processor

import (
	"container/heap"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// ErrCallLifecycleShutdown is returned when admission is attempted after the
// registry has begun process shutdown.
var ErrCallLifecycleShutdown = errors.New("call lifecycle registry is shut down")

// CallLifecycleConfig controls retention of terminal call state.
type CallLifecycleConfig struct {
	TombstoneTTL   time.Duration
	TombstoneLimit int
}

// CallFinalizationEvent is delivered once for each successful semantic call
// finalization. Shutdown deliberately does not produce these events.
type CallFinalizationEvent struct {
	CallID      string
	Generation  uint64
	Reason      CallFinalizationReason
	FinalizedAt time.Time
}

// CallLifecycleTelemetry is a snapshot of shared lifecycle state.
type CallLifecycleTelemetry struct {
	ActiveCalls                uint64
	Tombstones                 uint64
	TombstoneCapacityEvictions uint64
}

type lifecycleCall struct {
	callID     string
	generation uint64
	inflight   uint64
	closed     bool
	drained    chan struct{}
}

type lifecycleTombstone struct {
	callID      string
	generation  uint64
	finalizedAt time.Time
	index       int
}

type lifecycleTombstoneHeap []*lifecycleTombstone

func (h lifecycleTombstoneHeap) Len() int { return len(h) }
func (h lifecycleTombstoneHeap) Less(i, j int) bool {
	return h[i].finalizedAt.Before(h[j].finalizedAt)
}
func (h lifecycleTombstoneHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *lifecycleTombstoneHeap) Push(value any) {
	entry := value.(*lifecycleTombstone)
	entry.index = len(*h)
	*h = append(*h, entry)
}
func (h *lifecycleTombstoneHeap) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	*h = old[:last]
	entry.index = -1
	return entry
}

// CallLifecycleRegistry is the processor-owned terminal-state authority. An
// admission and finalization have a single winner under mu. Slow admitted work,
// cleanup, and callbacks never run while mu is held.
type CallLifecycleRegistry struct {
	mu sync.Mutex

	active         map[string]*lifecycleCall
	finalizing     map[string]*lifecycleTombstone
	tombstones     map[string]*lifecycleTombstone
	tombstoneQueue lifecycleTombstoneHeap
	tombstoneTTL   time.Duration
	tombstoneLimit int
	nextGeneration uint64
	subscribers    []func(CallFinalizationEvent)

	shutdown           bool
	totalInflight      uint64
	totalFinalizing    uint64
	shutdownDrain      chan struct{}
	shutdownClosed     bool
	tombstoneEvictions atomic.Uint64
}

// CallAdmission represents one accepted critical section. Release must be
// called when the irreversible sink-acceptance step has completed.
type CallAdmission struct {
	registry    *CallLifecycleRegistry
	call        *lifecycleCall
	releaseOnce sync.Once
}

func NewCallLifecycleRegistry(config CallLifecycleConfig) *CallLifecycleRegistry {
	if config.TombstoneTTL <= 0 {
		config.TombstoneTTL = completedCallTombstoneTTL
	}
	if config.TombstoneLimit <= 0 {
		config.TombstoneLimit = completedCallTombstoneLimit
	}
	return &CallLifecycleRegistry{
		active:         make(map[string]*lifecycleCall),
		finalizing:     make(map[string]*lifecycleTombstone),
		tombstones:     make(map[string]*lifecycleTombstone),
		tombstoneTTL:   config.TombstoneTTL,
		tombstoneLimit: config.TombstoneLimit,
		shutdownDrain:  make(chan struct{}),
	}
}

// Generation identifies the admitted incarnation of a reused Call-ID.
func (a *CallAdmission) Generation() uint64 {
	if a == nil || a.call == nil {
		return 0
	}
	return a.call.generation
}

// Release completes the admitted critical section. It is idempotent.
func (a *CallAdmission) Release() {
	if a == nil || a.registry == nil || a.call == nil {
		return
	}
	a.releaseOnce.Do(func() { a.registry.release(a.call) })
}

// Admit atomically accepts work for the current call generation.
func (r *CallLifecycleRegistry) Admit(callID string) (*CallAdmission, error) {
	if r == nil {
		return nil, ErrCallLifecycleShutdown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutdown {
		return nil, ErrCallLifecycleShutdown
	}
	now := time.Now()
	if terminal := r.finalizing[callID]; terminal != nil {
		return nil, &FinalizedCallError{CallID: callID, FinalizedAt: terminal.finalizedAt}
	}
	if terminal := r.tombstones[callID]; terminal != nil {
		if r.tombstoneTTL <= 0 || now.Sub(terminal.finalizedAt) < r.tombstoneTTL {
			return nil, &FinalizedCallError{CallID: callID, FinalizedAt: terminal.finalizedAt}
		}
		r.removeTombstoneLocked(callID)
	}
	call := r.active[callID]
	if call == nil {
		r.nextGeneration++
		call = &lifecycleCall{callID: callID, generation: r.nextGeneration, drained: make(chan struct{})}
		r.active[callID] = call
	}
	call.inflight++
	r.totalInflight++
	return &CallAdmission{registry: r, call: call}, nil
}

func (r *CallLifecycleRegistry) release(call *lifecycleCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call.inflight--
	r.totalInflight--
	if call.closed && call.inflight == 0 {
		close(call.drained)
	}
	r.closeShutdownDrainLocked()
}

// Subscribe adds a finalization observer. Observers run in registration order,
// outside registry locks, and may safely re-enter the registry.
func (r *CallLifecycleRegistry) Subscribe(callback func(CallFinalizationEvent)) {
	if r == nil || callback == nil {
		return
	}
	r.mu.Lock()
	r.subscribers = append(r.subscribers, callback)
	r.mu.Unlock()
}

// Finalize closes the currently active generation, or creates terminal state
// when completion arrives before the first packet.
func (r *CallLifecycleRegistry) Finalize(callID string, reason CallFinalizationReason) CallFinalizationResult {
	return r.finalize(callID, 0, reason)
}

// FinalizeGeneration finalizes only generation. It prevents stale idle sweeps
// or delayed callbacks from terminating a later reuse of the same Call-ID.
func (r *CallLifecycleRegistry) FinalizeGeneration(callID string, generation uint64, reason CallFinalizationReason) CallFinalizationResult {
	return r.finalize(callID, generation, reason)
}

func (r *CallLifecycleRegistry) finalize(callID string, requiredGeneration uint64, reason CallFinalizationReason) CallFinalizationResult {
	result := CallFinalizationResult{CallID: callID, Reason: reason}
	if r == nil || callID == "" || reason == CallFinalizationShutdown {
		return result
	}
	r.mu.Lock()
	if r.shutdown {
		r.mu.Unlock()
		return result
	}
	now := time.Now()
	if terminal := r.finalizing[callID]; terminal != nil {
		result.FinalizedAt = terminal.finalizedAt
		r.mu.Unlock()
		return result
	}
	if old := r.tombstones[callID]; old != nil {
		if r.tombstoneTTL <= 0 || now.Sub(old.finalizedAt) < r.tombstoneTTL {
			result.FinalizedAt = old.finalizedAt
			r.mu.Unlock()
			return result
		}
		r.removeTombstoneLocked(callID)
	}
	call := r.active[callID]
	if requiredGeneration != 0 && (call == nil || call.generation != requiredGeneration) {
		r.mu.Unlock()
		return result
	}
	if call == nil {
		r.nextGeneration++
		call = &lifecycleCall{callID: callID, generation: r.nextGeneration, drained: make(chan struct{})}
	}
	delete(r.active, callID)
	call.closed = true
	if call.inflight == 0 {
		close(call.drained)
	}
	r.addTombstoneLocked(callID, call.generation, now)
	r.finalizing[callID] = &lifecycleTombstone{callID: callID, generation: call.generation, finalizedAt: now, index: -1}
	r.totalFinalizing++
	subscribers := append([]func(CallFinalizationEvent){}, r.subscribers...)
	event := CallFinalizationEvent{CallID: callID, Generation: call.generation, Reason: reason, FinalizedAt: now}
	result.Finalized = true
	result.FinalizedAt = now
	r.mu.Unlock()

	<-call.drained
	for index, subscriber := range subscribers {
		invokeLifecycleSubscriber(subscriber, event, index)
	}
	r.mu.Lock()
	if current := r.finalizing[callID]; current != nil && current.generation == call.generation {
		delete(r.finalizing, callID)
	}
	r.totalFinalizing--
	r.closeShutdownDrainLocked()
	r.mu.Unlock()
	return result
}

// IsFinalized reports whether callID has an unexpired terminal tombstone.
func (r *CallLifecycleRegistry) IsFinalized(callID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.tombstones[callID]
	if finalizing := r.finalizing[callID]; finalizing != nil {
		return true
	}
	if entry != nil && r.tombstoneTTL > 0 && time.Since(entry.finalizedAt) >= r.tombstoneTTL {
		r.removeTombstoneLocked(callID)
		return false
	}
	return entry != nil
}

// Telemetry returns current lifecycle gauges and monotonic counters.
func (r *CallLifecycleRegistry) Telemetry() CallLifecycleTelemetry {
	if r == nil {
		return CallLifecycleTelemetry{}
	}
	r.mu.Lock()
	activeCalls := len(r.active)
	tombstones := len(r.tombstones)
	r.mu.Unlock()
	return CallLifecycleTelemetry{
		ActiveCalls:                uint64(activeCalls), // #nosec G115 -- map sizes cannot be negative
		Tombstones:                 uint64(tombstones),  // #nosec G115 -- map sizes cannot be negative
		TombstoneCapacityEvictions: r.tombstoneEvictions.Load(),
	}
}

// Shutdown rejects new work and waits for admitted work. It is process
// lifecycle only: it creates no tombstones and emits no finalization events.
func (r *CallLifecycleRegistry) Shutdown() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.shutdown {
		r.shutdown = true
		for callID, call := range r.active {
			delete(r.active, callID)
			call.closed = true
			if call.inflight == 0 {
				close(call.drained)
			}
		}
		r.closeShutdownDrainLocked()
	}
	drain := r.shutdownDrain
	r.mu.Unlock()
	<-drain
}

func (r *CallLifecycleRegistry) closeShutdownDrainLocked() {
	if r.shutdown && r.totalInflight == 0 && r.totalFinalizing == 0 && !r.shutdownClosed {
		close(r.shutdownDrain)
		r.shutdownClosed = true
	}
}

func invokeLifecycleSubscriber(subscriber func(CallFinalizationEvent), event CallFinalizationEvent, index int) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("Call lifecycle subscriber panicked",
				"generation", event.Generation,
				"reason", event.Reason,
				"subscriber_index", index,
				"panic", recovered)
		}
	}()
	subscriber(event)
}

func (r *CallLifecycleRegistry) addTombstoneLocked(callID string, generation uint64, finalizedAt time.Time) {
	r.pruneExpiredLocked(finalizedAt)
	if len(r.tombstones) >= r.tombstoneLimit {
		r.removeTombstoneLocked(r.tombstoneQueue[0].callID)
		r.tombstoneEvictions.Add(1)
	}
	entry := &lifecycleTombstone{callID: callID, generation: generation, finalizedAt: finalizedAt}
	r.tombstones[callID] = entry
	heap.Push(&r.tombstoneQueue, entry)
}

func (r *CallLifecycleRegistry) pruneExpiredLocked(now time.Time) {
	for len(r.tombstoneQueue) > 0 {
		oldest := r.tombstoneQueue[0]
		if r.tombstoneTTL <= 0 || now.Sub(oldest.finalizedAt) < r.tombstoneTTL {
			return
		}
		r.removeTombstoneLocked(oldest.callID)
	}
}

func (r *CallLifecycleRegistry) removeTombstoneLocked(callID string) {
	entry := r.tombstones[callID]
	if entry == nil {
		return
	}
	delete(r.tombstones, callID)
	heap.Remove(&r.tombstoneQueue, entry.index)
}
