//go:build tui || all

package store

import (
	"container/list"
	"sort"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// CallStore manages call storage with LRU eviction
type CallStore struct {
	mu            sync.RWMutex
	calls         map[string]*components.Call // callID -> call (for quick updates)
	lruList       *list.List                  // LRU list (front = most recently used)
	lruIndex      map[string]*list.Element    // callID -> list element for O(1) lookup
	maxCalls      int                         // Maximum calls to keep in memory
	totalCalls    int                         // Total calls seen (ever)
	FilterChain   *filters.FilterChain        // Active filters
	filteredCalls []components.Call           // Filtered calls for display
	filteredIndex map[string]int              // callID -> index in filteredCalls for O(1) lookup
	matchedCalls  int64                       // Calls matching filter
	cachedCalls   []components.Call           // Cached sorted copy of all calls
	callsDirty    bool                        // True if cache needs rebuild
}

// NewCallStore creates a new call store with the given buffer size
func NewCallStore(bufferSize int) *CallStore {
	return &CallStore{
		calls:         make(map[string]*components.Call),
		lruList:       list.New(),
		lruIndex:      make(map[string]*list.Element),
		maxCalls:      bufferSize,
		FilterChain:   filters.NewFilterChain(),
		filteredCalls: []components.Call{},
		filteredIndex: make(map[string]int),
		callsDirty:    true, // Start dirty so first GetCallsInOrder builds cache
	}
}

// AddOrUpdateCall adds or updates a call in the store
func (cs *CallStore) AddOrUpdateCall(call components.Call) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.addOrUpdateCallLocked(call)
}

// addOrUpdateCallLocked is the internal implementation (must hold lock)
func (cs *CallStore) addOrUpdateCallLocked(call components.Call) {
	cs.callsDirty = true // Invalidate cache on mutation

	_, exists := cs.calls[call.CallID]

	if !exists {
		// Evict LRU (least recently used) if at capacity
		if cs.lruList.Len() >= cs.maxCalls {
			// Remove from back (least recently used)
			oldest := cs.lruList.Back()
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				cs.lruList.Remove(oldest)
				delete(cs.lruIndex, oldestCallID)
				delete(cs.calls, oldestCallID)
				// Remove from filtered calls if present
				cs.removeFromFilteredLocked(oldestCallID)
			}
		}

		// Add new call to front (most recently used)
		elem := cs.lruList.PushFront(call.CallID)
		cs.lruIndex[call.CallID] = elem
		cs.totalCalls++
	} else {
		// Move existing call to front (most recently used)
		if elem, ok := cs.lruIndex[call.CallID]; ok {
			cs.lruList.MoveToFront(elem)
		}
	}

	// Store/update the call
	cs.calls[call.CallID] = &call

	// Apply filter and update filtered calls
	cs.updateFilteredCallLocked(call)
}

// AddOrUpdateCalls adds or updates multiple calls with a single lock acquisition
func (cs *CallStore) AddOrUpdateCalls(calls []components.Call) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	for _, call := range calls {
		cs.addOrUpdateCallLocked(call)
	}
}

// GetCallsInOrder returns calls sorted by StartTime (chronological order).
// LRU is the eviction policy only; display order is always chronological.
// Uses caching to avoid repeated copy and sort operations.
func (cs *CallStore) GetCallsInOrder() []components.Call {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.lruList.Len() == 0 {
		return nil
	}

	// Rebuild cache if dirty
	if cs.callsDirty {
		cs.cachedCalls = make([]components.Call, 0, cs.lruList.Len())
		for _, call := range cs.calls {
			cs.cachedCalls = append(cs.cachedCalls, *call)
		}

		// Sort by StartTime for chronological display order, then by CallID as tiebreaker
		sort.Slice(cs.cachedCalls, func(i, j int) bool {
			if cs.cachedCalls[i].StartTime.Equal(cs.cachedCalls[j].StartTime) {
				return cs.cachedCalls[i].CallID < cs.cachedCalls[j].CallID
			}
			return cs.cachedCalls[i].StartTime.Before(cs.cachedCalls[j].StartTime)
		})

		cs.callsDirty = false
	}

	// Return a copy of the cached slice
	result := make([]components.Call, len(cs.cachedCalls))
	copy(result, cs.cachedCalls)

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
	return cs.lruList.Len()
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
	cs.lruList = list.New()
	cs.lruIndex = make(map[string]*list.Element)
	cs.filteredCalls = []components.Call{}
	cs.filteredIndex = make(map[string]int)
	cs.matchedCalls = 0
	cs.cachedCalls = nil
	cs.callsDirty = true
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
// Uses swap-with-last technique for O(1) removal
func (cs *CallStore) removeFromFilteredLocked(callID string) {
	idx, exists := cs.filteredIndex[callID]
	if !exists {
		return
	}

	lastIdx := len(cs.filteredCalls) - 1
	if idx != lastIdx {
		// Swap with last element
		cs.filteredCalls[idx] = cs.filteredCalls[lastIdx]
		// Update the swapped element's index
		cs.filteredIndex[cs.filteredCalls[idx].CallID] = idx
	}

	// Truncate slice and remove from index
	cs.filteredCalls = cs.filteredCalls[:lastIdx]
	delete(cs.filteredIndex, callID)
}

// updateFilteredCallLocked applies filter to a call and updates filtered list (must hold lock)
// Uses index for O(1) lookup
func (cs *CallStore) updateFilteredCallLocked(call components.Call) {
	// Check if call matches filter
	matches := cs.FilterChain.Match(call)

	// O(1) lookup to find if call already exists in filtered list
	existingIdx, exists := cs.filteredIndex[call.CallID]

	if matches {
		if exists {
			// Update existing entry in place
			cs.filteredCalls[existingIdx] = call
		} else {
			// Add new matching call
			cs.filteredIndex[call.CallID] = len(cs.filteredCalls)
			cs.filteredCalls = append(cs.filteredCalls, call)
			cs.matchedCalls++
		}
	} else {
		if exists {
			// Call no longer matches, remove it using O(1) swap-with-last
			cs.removeFromFilteredLocked(call.CallID)
		}
	}
}

// reapplyFiltersLocked re-evaluates all calls against current filter (must hold lock)
func (cs *CallStore) reapplyFiltersLocked() {
	cs.filteredCalls = []components.Call{}
	cs.filteredIndex = make(map[string]int)
	cs.matchedCalls = 0

	if cs.lruList.Len() == 0 {
		return
	}

	// Collect all matching calls
	for _, call := range cs.calls {
		if cs.FilterChain.Match(*call) {
			cs.filteredCalls = append(cs.filteredCalls, *call)
			cs.matchedCalls++
		}
	}

	// Sort by StartTime for chronological display order, then by CallID as tiebreaker
	sort.Slice(cs.filteredCalls, func(i, j int) bool {
		if cs.filteredCalls[i].StartTime.Equal(cs.filteredCalls[j].StartTime) {
			return cs.filteredCalls[i].CallID < cs.filteredCalls[j].CallID
		}
		return cs.filteredCalls[i].StartTime.Before(cs.filteredCalls[j].StartTime)
	})

	// Rebuild index after sorting
	for i, call := range cs.filteredCalls {
		cs.filteredIndex[call.CallID] = i
	}
}
