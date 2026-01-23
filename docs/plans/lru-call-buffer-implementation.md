# LRU Call Buffer Implementation Plan

**Research:** [../research/lru-call-buffer-conversion.md](../research/lru-call-buffer-conversion.md)

## Overview

Convert call tracking from FIFO ring buffers to LRU to keep active calls in buffer while evicting idle ones.

**Design decisions:**
- Pure LRU (no state-based priority)
- No grace period for ended calls
- Keep chronological display order (LRU is eviction policy only)
- Keep 1000 call limit
- Only packet processing updates LRU position (not reads)

## Implementation

### Phase 1: CallAggregator (processor-side)

File: `internal/pkg/voip/call_aggregator.go`

- [x] Replace ring buffer fields with LRU structure:
  ```go
  lruList  *list.List                  // container/list
  lruIndex map[string]*list.Element    // callID -> element
  ```
- [x] Update `NewCallAggregatorWithCapacity()` to initialize LRU
- [x] Update `processSIPPacket()`:
  - New call: push to front, add to lruIndex
  - Existing call: move element to front
  - Evict from back when full
- [x] Update `processRTPPacketInternal()` with same logic
- [x] Keep `GetCalls()` returning chronological order (sort by StartTime)
- [x] Update tests in `call_aggregator_test.go`:
  - [x] Change `TestCallAggregator_EvictionOrder` to verify LRU
  - [x] Update `TestCallAggregator_RingBufferEvictionRace` for LRU (renamed to `TestCallAggregator_LRUEvictionRace`)
  - [x] Add `TestCallAggregator_LRUActiveCallSurvival` to verify active calls survive

### Phase 2: CallStore (TUI-side)

File: `internal/pkg/tui/store/call_store.go`

- [x] Replace ring buffer fields with LRU structure (same as Phase 1)
- [x] Update `NewCallStore()` to initialize LRU
- [x] Update `AddOrUpdateCall()`:
  - New call: push to front, evict from back if full
  - Existing call: move to front
- [x] Keep `GetCallsInOrder()` returning chronological order (sort by StartTime)
- [x] Update `reapplyFiltersLocked()` to sort filtered calls by StartTime
- [x] Verify filter chain integration still works (TUI tests pass)

### Phase 3: CallTracker (sniff/tap/hunt)

File: `internal/pkg/voip/calltracker.go`

- [x] Replace ring buffer fields with LRU structure
- [x] Update `NewCallTracker()` to initialize LRU
- [x] Update `GetOrCreateCall()`:
  - New call: push to front, evict from back if full
  - Existing call: move to front
- [x] Ensure PCAP file cleanup on eviction still works
- [x] Update tests in `calltracker_test.go`:
  - [x] Add `TestCallTrackerLRUEviction` to verify LRU eviction order
  - [x] Add `TestCallTrackerLRUActiveCallSurvival` to verify active calls survive

## Testing

- [x] Verify active calls survive when buffer is full
- [x] Verify idle calls are evicted first
- [x] Verify chronological display order preserved
- [x] Run full test suite
- [ ] Manual test with live VoIP traffic

## Helper Function

Consider extracting shared LRU logic:

```go
// internal/pkg/lru/lru.go
type LRU[V any] struct {
    list     *list.List
    index    map[string]*list.Element
    maxSize  int
}

func (l *LRU[V]) Add(key string, value V) (evictedKey string, evicted bool)
func (l *LRU[V]) Get(key string) (V, bool)
func (l *LRU[V]) Touch(key string)  // Move to front
func (l *LRU[V]) Remove(key string)
func (l *LRU[V]) Len() int
```

This avoids duplicating LRU logic across three files. Optional - can inline if preferred.
