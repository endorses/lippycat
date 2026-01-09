//go:build tui || all

package store

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// CallStore manages call storage with a ring buffer (similar to PacketStore)
type CallStore struct {
	mu         sync.RWMutex
	calls      map[string]*components.Call // callID -> call (for quick updates)
	callRing   []string                    // Ring buffer of CallIDs in chronological order
	ringHead   int                         // Head index for circular buffer
	ringCount  int                         // Current number of calls in buffer
	maxCalls   int                         // Maximum calls to keep in memory
	totalCalls int                         // Total calls seen (ever)
}

// NewCallStore creates a new call store with the given buffer size
func NewCallStore(bufferSize int) *CallStore {
	return &CallStore{
		calls:    make(map[string]*components.Call),
		callRing: make([]string, bufferSize),
		maxCalls: bufferSize,
	}
}

// AddOrUpdateCall adds or updates a call in the store
func (cs *CallStore) AddOrUpdateCall(call components.Call) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	_, exists := cs.calls[call.CallID]

	if !exists {
		// New call - add to ring buffer
		if cs.ringCount >= cs.maxCalls {
			// Ring buffer is full, remove oldest call
			oldestCallID := cs.callRing[cs.ringHead]
			delete(cs.calls, oldestCallID)
		} else {
			cs.ringCount++
		}

		// Add new call to ring buffer
		cs.callRing[cs.ringHead] = call.CallID
		cs.ringHead = (cs.ringHead + 1) % cs.maxCalls
		cs.totalCalls++
	}

	// Store/update the call
	cs.calls[call.CallID] = &call
}

// AddOrUpdateCalls adds or updates multiple calls
func (cs *CallStore) AddOrUpdateCalls(calls []components.Call) {
	for _, call := range calls {
		cs.AddOrUpdateCall(call)
	}
}

// GetCallsInOrder returns calls from the ring buffer in chronological order
func (cs *CallStore) GetCallsInOrder() []components.Call {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.ringCount == 0 {
		return nil
	}

	result := make([]components.Call, 0, cs.ringCount)

	if cs.ringCount < cs.maxCalls {
		// Buffer not full yet, calls are in order from ring start
		for i := range cs.ringCount {
			callID := cs.callRing[i]
			if call, exists := cs.calls[callID]; exists {
				result = append(result, *call)
			}
		}
	} else {
		// Buffer is full, need to wrap around from ringHead
		for i := range cs.maxCalls {
			idx := (cs.ringHead + i) % cs.maxCalls
			callID := cs.callRing[idx]
			if call, exists := cs.calls[callID]; exists {
				result = append(result, *call)
			}
		}
	}

	return result
}

// GetCall returns a specific call by ID
func (cs *CallStore) GetCall(callID string) (*components.Call, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	call, exists := cs.calls[callID]
	if !exists {
		return nil, false
	}
	return call, true
}

// GetCallCount returns the current number of calls in the store
func (cs *CallStore) GetCallCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.ringCount
}

// GetTotalCalls returns the total number of calls ever seen
func (cs *CallStore) GetTotalCalls() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.totalCalls
}

// Clear removes all calls from the store
func (cs *CallStore) Clear() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.calls = make(map[string]*components.Call)
	cs.callRing = make([]string, cs.maxCalls)
	cs.ringHead = 0
	cs.ringCount = 0
}
