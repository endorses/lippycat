//go:build tui || all

package store

import (
	"sync"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// CallStore manages call storage with a ring buffer (similar to PacketStore)
type CallStore struct {
	mu            sync.RWMutex
	calls         map[string]*components.Call // callID -> call (for quick updates)
	callRing      []string                    // Ring buffer of CallIDs in chronological order
	ringHead      int                         // Head index for circular buffer
	ringCount     int                         // Current number of calls in buffer
	maxCalls      int                         // Maximum calls to keep in memory
	totalCalls    int                         // Total calls seen (ever)
	FilterChain   *filters.FilterChain        // Active filters
	filteredCalls []components.Call           // Filtered calls for display
	matchedCalls  int64                       // Calls matching filter
}

// NewCallStore creates a new call store with the given buffer size
func NewCallStore(bufferSize int) *CallStore {
	return &CallStore{
		calls:         make(map[string]*components.Call),
		callRing:      make([]string, bufferSize),
		maxCalls:      bufferSize,
		FilterChain:   filters.NewFilterChain(),
		filteredCalls: []components.Call{},
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
			// Remove from filtered calls if present
			cs.removeFromFilteredLocked(oldestCallID)
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

	// Apply filter and update filtered calls
	cs.updateFilteredCallLocked(call)
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
	cs.filteredCalls = []components.Call{}
	cs.matchedCalls = 0
}

// AddFilter adds a filter to the chain and reapplies to existing calls
func (cs *CallStore) AddFilter(filter filters.Filter) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.FilterChain.Add(filter)
	cs.reapplyFiltersLocked()
}

// RemoveLastFilter removes the last filter from the chain
// Returns true if a filter was removed, false if the chain was empty
func (cs *CallStore) RemoveLastFilter() bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.FilterChain.RemoveLast() {
		cs.reapplyFiltersLocked()
		return true
	}
	return false
}

// ClearFilter removes all filters and shows all calls
func (cs *CallStore) ClearFilter() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.FilterChain.Clear()
	cs.reapplyFiltersLocked()
}

// HasFilter returns true if any filters are active
func (cs *CallStore) HasFilter() bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return !cs.FilterChain.IsEmpty()
}

// GetFilteredCalls returns filtered calls for display
func (cs *CallStore) GetFilteredCalls() []components.Call {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	result := make([]components.Call, len(cs.filteredCalls))
	copy(result, cs.filteredCalls)
	return result
}

// GetFilteredCallCount returns the number of calls matching the filter
func (cs *CallStore) GetFilteredCallCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.filteredCalls)
}

// GetMatchedCalls returns the total number of calls that have ever matched the filter
func (cs *CallStore) GetMatchedCalls() int64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.matchedCalls
}

// removeFromFilteredLocked removes a call from filtered calls by ID (must hold lock)
func (cs *CallStore) removeFromFilteredLocked(callID string) {
	for i, call := range cs.filteredCalls {
		if call.CallID == callID {
			cs.filteredCalls = append(cs.filteredCalls[:i], cs.filteredCalls[i+1:]...)
			return
		}
	}
}

// updateFilteredCallLocked applies filter to a call and updates filtered list (must hold lock)
func (cs *CallStore) updateFilteredCallLocked(call components.Call) {
	// Check if call matches filter
	matches := cs.FilterChain.Match(call)

	// Find if call already exists in filtered list
	existingIdx := -1
	for i, fc := range cs.filteredCalls {
		if fc.CallID == call.CallID {
			existingIdx = i
			break
		}
	}

	if matches {
		if existingIdx >= 0 {
			// Update existing entry
			cs.filteredCalls[existingIdx] = call
		} else {
			// Add new matching call
			cs.filteredCalls = append(cs.filteredCalls, call)
			cs.matchedCalls++
		}
	} else {
		if existingIdx >= 0 {
			// Call no longer matches, remove it
			cs.filteredCalls = append(cs.filteredCalls[:existingIdx], cs.filteredCalls[existingIdx+1:]...)
		}
	}
}

// reapplyFiltersLocked re-evaluates all calls against current filter (must hold lock)
func (cs *CallStore) reapplyFiltersLocked() {
	cs.filteredCalls = []components.Call{}
	cs.matchedCalls = 0

	// Iterate through calls in chronological order
	if cs.ringCount == 0 {
		return
	}

	if cs.ringCount < cs.maxCalls {
		// Buffer not full yet, calls are in order from ring start
		for i := range cs.ringCount {
			callID := cs.callRing[i]
			if call, exists := cs.calls[callID]; exists {
				if cs.FilterChain.Match(*call) {
					cs.filteredCalls = append(cs.filteredCalls, *call)
					cs.matchedCalls++
				}
			}
		}
	} else {
		// Buffer is full, need to wrap around from ringHead
		for i := range cs.maxCalls {
			idx := (cs.ringHead + i) % cs.maxCalls
			callID := cs.callRing[idx]
			if call, exists := cs.calls[callID]; exists {
				if cs.FilterChain.Match(*call) {
					cs.filteredCalls = append(cs.filteredCalls, *call)
					cs.matchedCalls++
				}
			}
		}
	}
}
