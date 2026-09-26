//go:build processor || tap || all

package processor

import (
	"container/heap"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

// ErrCallLifecycleShutdown is returned when admission is attempted after the
// registry has begun process shutdown.
var ErrCallLifecycleShutdown = errors.New("call lifecycle registry is shut down")

// ErrCallLifecycleIdentity blocks admission after a new call identity could not
// be allocated. Existing incarnations can still finalize and drain on shutdown.
var ErrCallLifecycleIdentity = errors.New("call lifecycle identity unavailable")

// CallLifecycleConfig controls retention of terminal call state.
type CallLifecycleConfig struct {
	TombstoneTTL   time.Duration
	TombstoneLimit int
}

// CallFinalizationEvent is delivered once for each successful semantic call
// finalization. Shutdown deliberately does not produce these events.
type CallFinalizationEvent struct {
	CallID          string
	Generation      uint64
	CallIncarnation uuid.UUID
	Reason          CallFinalizationReason
	FinalizedAt     time.Time
}

// CallLifecycleTelemetry is a snapshot of shared lifecycle state.
type CallLifecycleTelemetry struct {
	ActiveCalls                uint64
	Tombstones                 uint64
	TombstoneCapacityEvictions uint64
}

type lifecycleCall struct {
	callID      string
	generation  uint64
	incarnation uuid.UUID
	inflight    uint64
	closed      bool
	drained     chan struct{}
}

type lifecycleTombstone struct {
	callID      string
	generation  uint64
	incarnation uuid.UUID
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
	entropy        io.Reader // crypto/rand.Reader; replaced only by fault-injection tests
	identityErr    error
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
	admittedAt  time.Time
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
		entropy:        rand.Reader,
	}
}

// Generation is the process-local guard against stale callbacks for a reused
// Call-ID. It is not a durable incarnation identity.
func (a *CallAdmission) Generation() uint64 {
	if a == nil || a.call == nil {
		return 0
	}
	return a.call.generation
}

// Incarnation identifies exactly one call lifecycle, independently of Call-ID
// reuse and process-local generation numbering. The returned UUID is a value.
func (a *CallAdmission) Incarnation() uuid.UUID {
	if a == nil || a.call == nil {
		return uuid.Nil
	}
	return a.call.incarnation
}

// Err reports a latched identity-allocation failure. It does not prevent
// finalization of previously allocated calls or shutdown reference draining.
func (r *CallLifecycleRegistry) Err() error {
	if r == nil {
		return ErrCallLifecycleShutdown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.identityErr
}

// newCallLocked allocates only when a new generation is needed. Failure leaves
// generation and lifecycle maps unchanged and permanently closes new admission.
func (r *CallLifecycleRegistry) newCallLocked(callID string) (*lifecycleCall, error) {
	if r.identityErr != nil {
		return nil, r.identityErr
	}
	if r.nextGeneration == ^uint64(0) {
		r.identityErr = fmt.Errorf("%w: generation exhausted", ErrCallLifecycleIdentity)
		return nil, r.identityErr
	}
	incarnation, err := uuid.NewRandomFromReader(r.entropy)
	if err != nil {
		r.identityErr = fmt.Errorf("%w: %w", ErrCallLifecycleIdentity, err)
		return nil, r.identityErr
	}
	r.nextGeneration++
	return &lifecycleCall{callID: callID, generation: r.nextGeneration, incarnation: incarnation, drained: make(chan struct{})}, nil
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
	return r.admit(callID, 0)
}

// AdmitGeneration atomically accepts work only when generation is still the
// current live incarnation of callID. Delayed sink callbacks use this to avoid
// attaching old work to a reused Call-ID.
func (r *CallLifecycleRegistry) AdmitGeneration(callID string, generation uint64) (*CallAdmission, error) {
	if generation == 0 {
		return nil, &FinalizedCallError{CallID: callID}
	}
	return r.admit(callID, generation)
}

// RestartInvite replaces a completed call's tombstone only after the caller
// has verified a distinct INVITE transaction. It never reuses a generation and
// cannot race a still-running finalization callback.
func (r *CallLifecycleRegistry) RestartInvite(callID string) (*CallAdmission, error) {
	if r == nil {
		return nil, ErrCallLifecycleShutdown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutdown {
		return nil, ErrCallLifecycleShutdown
	}
	if r.identityErr != nil {
		return nil, r.identityErr
	}
	if _, busy := r.finalizing[callID]; busy {
		return nil, &FinalizedCallError{CallID: callID}
	}
	if r.tombstones[callID] == nil {
		return nil, &FinalizedCallError{CallID: callID}
	}
	call, err := r.newCallLocked(callID)
	if err != nil {
		return nil, err
	}
	r.removeTombstoneLocked(callID)
	call.inflight = 1
	r.active[callID] = call
	r.totalInflight++
	return &CallAdmission{registry: r, call: call, admittedAt: time.Now()}, nil
}

// StartInviteAfterExpiry creates a new generation only after the old
// tombstone has been evicted or expired and no live generation exists.
// The caller must have verified a distinct INVITE against retained call state.
func (r *CallLifecycleRegistry) StartInviteAfterExpiry(callID string) (*CallAdmission, error) {
	if r == nil {
		return nil, ErrCallLifecycleShutdown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutdown {
		return nil, ErrCallLifecycleShutdown
	}
	if r.identityErr != nil {
		return nil, r.identityErr
	}
	if r.active[callID] != nil || r.finalizing[callID] != nil || r.tombstones[callID] != nil {
		return nil, &FinalizedCallError{CallID: callID}
	}
	call, err := r.newCallLocked(callID)
	if err != nil {
		return nil, err
	}
	call.inflight = 1
	r.active[callID] = call
	r.totalInflight++
	return &CallAdmission{registry: r, call: call, admittedAt: time.Now()}, nil
}

func (r *CallLifecycleRegistry) admit(callID string, requiredGeneration uint64) (*CallAdmission, error) {
	if r == nil {
		return nil, ErrCallLifecycleShutdown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.shutdown {
		return nil, ErrCallLifecycleShutdown
	}
	if r.identityErr != nil {
		return nil, r.identityErr
	}
	now := time.Now()
	if terminal := r.finalizing[callID]; terminal != nil {
		return nil, &FinalizedCallError{CallID: callID, FinalizedAt: terminal.finalizedAt}
	}
	if terminal := r.tombstones[callID]; terminal != nil {
		if r.tombstoneTTL <= 0 || now.Sub(terminal.finalizedAt) < r.tombstoneTTL {
			return nil, &FinalizedCallError{CallID: callID, FinalizedAt: terminal.finalizedAt}
		}
	}
	call := r.active[callID]
	if requiredGeneration != 0 && (call == nil || call.generation != requiredGeneration) {
		return nil, &FinalizedCallError{CallID: callID}
	}
	if call == nil {
		var err error
		call, err = r.newCallLocked(callID)
		if err != nil {
			return nil, err
		}
		r.removeTombstoneLocked(callID)
		r.active[callID] = call
	}
	call.inflight++
	r.totalInflight++
	return &CallAdmission{registry: r, call: call, admittedAt: now}, nil
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
	}
	call := r.active[callID]
	if requiredGeneration != 0 && (call == nil || call.generation != requiredGeneration) {
		r.mu.Unlock()
		return result
	}
	if call == nil {
		var err error
		call, err = r.newCallLocked(callID)
		if err != nil {
			result.Err = err
			r.mu.Unlock()
			return result
		}
	}
	r.removeTombstoneLocked(callID)
	delete(r.active, callID)
	call.closed = true
	if call.inflight == 0 {
		close(call.drained)
	}
	r.addTombstoneLocked(callID, call.generation, call.incarnation, now)
	r.finalizing[callID] = &lifecycleTombstone{callID: callID, generation: call.generation, incarnation: call.incarnation, finalizedAt: now, index: -1}
	r.totalFinalizing++
	subscribers := append([]func(CallFinalizationEvent){}, r.subscribers...)
	event := CallFinalizationEvent{CallID: callID, Generation: call.generation, CallIncarnation: call.incarnation, Reason: reason, FinalizedAt: now}
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

// HasCompletedCall reports a retained completion even when its suppression
// TTL has elapsed. A verified new INVITE may replace that record explicitly.
func (r *CallLifecycleRegistry) HasCompletedCall(callID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalizing[callID] != nil || r.tombstones[callID] != nil
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

// Shutdown begins process shutdown and rejects new work. It is safe to call
// from a finalization subscriber because it does not wait for that subscriber
// to return. Shutdown creates no tombstones and emits no finalization events.
func (r *CallLifecycleRegistry) Shutdown() {
	if r == nil {
		return
	}
	r.beginShutdown()
}

// ShutdownAndWait begins process shutdown and waits for admitted work and all
// committed finalization subscribers to drain. Finalization subscribers must
// use Shutdown instead: waiting for the subscriber currently on the stack would
// be self-dependent.
func (r *CallLifecycleRegistry) ShutdownAndWait() {
	if r == nil {
		return
	}
	drain := r.beginShutdown()
	<-drain
}

func (r *CallLifecycleRegistry) beginShutdown() <-chan struct{} {
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
	return drain
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

func (r *CallLifecycleRegistry) addTombstoneLocked(callID string, generation uint64, incarnation uuid.UUID, finalizedAt time.Time) {
	r.pruneExpiredLocked(finalizedAt)
	if len(r.tombstones) >= r.tombstoneLimit {
		r.removeTombstoneLocked(r.tombstoneQueue[0].callID)
		r.tombstoneEvictions.Add(1)
	}
	entry := &lifecycleTombstone{callID: callID, generation: generation, incarnation: incarnation, finalizedAt: finalizedAt}
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
