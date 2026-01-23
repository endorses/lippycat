# TUI Calls Performance Optimization Plan

## Overview

Performance improvements for the TUI calls view and RTP-only call detection, addressing bottlenecks introduced in recent changes (commits 85d574f through 1d1913c).

**Key issues identified:**
- O(n²) complexity in RTP packet lookup (IP fallback matching)
- O(n) linear scans in filtered calls management
- Excessive memory allocations on every update cycle
- Redundant sorting operations
- String operations in hot paths

## Design Decisions

- Maintain backward compatibility with existing APIs
- Prefer O(1) lookups over O(n) scans using index maps
- Cache computed values that don't change frequently
- Batch operations to reduce lock contention
- Use enums/flags instead of string prefix checks

---

## Phase 1: Fix O(n²) RTP Packet Lookup (Critical)

**File:** `internal/pkg/tui/call_tracker.go`

The `GetCallIDForRTPPacket()` method iterates the entire `rtpEndpointToCallID` map twice when direct endpoint lookup fails - once to find matches by IP and again to verify uniqueness.

### Changes

- [x] Add IP-based index for faster fallback lookup:
  ```go
  type CallTracker struct {
      // existing fields...
      rtpEndpointToCallID map[string]string           // "ip:port" -> callID
      callIDToEndpoints   map[string][]string         // callID -> endpoints

      // NEW: IP-based index for fallback matching
      ipToCallIDs         map[string]map[string]struct{}  // ip -> set of callIDs
  }
  ```

- [x] Update `RegisterMediaPorts()` to maintain IP index:
  - Extract IP from endpoint once, add callID to `ipToCallIDs[ip]`
  - Remove from old IP entry on re-registration

- [x] Refactor `GetCallIDForRTPPacket()`:
  - Direct endpoint lookup first (O(1)) - unchanged
  - IP fallback: lookup `ipToCallIDs[srcIP]` (O(1))
  - If single callID in set, return it
  - If multiple, return empty (ambiguous)
  - Eliminate double iteration entirely

- [x] Update `evictCallLocked()` to clean up IP index

- [x] Add tests for new IP index behavior (`call_tracker_test.go`)

**Benchmark results (5000 calls):**
- DirectMatch: ~182ns/op
- IPFallback: ~185ns/op (was O(n²), now O(1))
- NoMatch: ~192ns/op

**Expected improvement:** O(n²) → O(1) for RTP packet lookup ✅

---

## Phase 2: Index Filtered Calls for O(1) Lookup

**File:** `internal/pkg/tui/store/call_store.go`

Currently `removeFromFilteredLocked()` and `updateFilteredCallLocked()` perform O(n) linear scans.

### Changes

- [x] Add position index for filtered calls:
  ```go
  type CallStore struct {
      // existing fields...
      filteredCalls    []components.Call

      // NEW: O(1) position lookup
      filteredIndex    map[string]int    // callID -> index in filteredCalls
  }
  ```

- [x] Refactor `removeFromFilteredLocked()`:
  - Lookup index in map (O(1))
  - Swap with last element (O(1))
  - Truncate slice (O(1))
  - Update swapped element's index in map

- [x] Refactor `updateFilteredCallLocked()`:
  - Lookup existing index in map (O(1))
  - Update in place or append + add to map

- [x] Update `reapplyFiltersLocked()` to rebuild index after re-filtering

- [x] Add tests for index consistency (`call_store_test.go`)

**Benchmark results (5000 calls):**
- AddOrUpdateCall: ~241ns/op
- FilteredRemoval: ~752ns/op (was O(n), now O(1))

**Expected improvement:** O(n) → O(1) for filtered call operations ✅

---

## Phase 3: Batch CallStore Updates

**File:** `internal/pkg/tui/store/call_store.go`

Currently `AddOrUpdateCalls()` acquires lock N times for N calls.

### Changes

- [x] Refactor `AddOrUpdateCalls()` to batch operations:
  ```go
  func (cs *CallStore) AddOrUpdateCalls(calls []components.Call) {
      cs.mu.Lock()
      defer cs.mu.Unlock()

      for _, call := range calls {
          cs.addOrUpdateCallLocked(call)  // No lock acquisition
      }
  }
  ```

- [x] Extract `addOrUpdateCallLocked()` from `AddOrUpdateCall()` (internal, no lock)

- [x] Keep `AddOrUpdateCall()` for single-call updates (backward compat)

**Benchmark results:**
- Batch of 100 calls: ~14.2μs/op (single lock acquisition)

**Expected improvement:** N lock acquisitions → 1 lock acquisition ✅

---

## Phase 4: Cache Sorted Call Lists

**Files:**
- `internal/pkg/voip/call_aggregator.go`
- `internal/pkg/tui/store/call_store.go`

Currently `GetCalls()` and `GetCallsInOrder()` deep-copy and sort on every call.

### Changes

#### CallAggregator

- [x] Add dirty flag and cached result:
  ```go
  type CallAggregator struct {
      // existing fields...
      callsDirty     bool
      cachedCalls    []AggregatedCall
  }
  ```

- [x] Set `callsDirty = true` on any call mutation (processSIPPacket, processRTPPacketInternal, mergeRTPOnlyCall)

- [x] Refactor `GetCalls()`:
  - If not dirty, return copy of cached slice
  - If dirty, rebuild cache (deep copy + sort), clear flag
  - Return shallow copy of cached slice

#### CallStore

- [x] Add similar dirty flag and cached result

- [x] Refactor `GetCallsInOrder()` with same pattern

- [x] Add tests for caching behavior (`call_store_test.go`)

**Benchmark results (5000 calls):**
- Cached: ~139μs/op (8.4x faster)
- Uncached: ~1174μs/op

**Expected improvement:** O(n log n) on every call → O(n log n) only when data changes ✅

---

## Phase 5: Eliminate Redundant Sorting in CallsView

**File:** `internal/pkg/tui/components/callsview.go`

`SetCalls()` re-sorts calls that are already sorted by upstream.

### Changes

- [x] Update upstream sorts to include CallID tiebreaker (matching CallsView criteria):
  - `call_store.go`: GetCallsInOrder cache and reapplyFiltersLocked
  - `call_aggregator.go`: GetCalls cache

- [x] Remove redundant sort in `SetCalls()`:
  ```go
  // Calls are pre-sorted by upstream (CallStore/CallAggregator) by StartTime then CallID
  cv.calls = calls
  ```

- [x] Add comment documenting that callers provide pre-sorted calls

**Expected improvement:** O(n log n) → O(1) per SetCalls ✅

---

## Phase 6: Use CallState Enum for RTP-Only Detection

**Files:**
- `internal/pkg/tui/local_call_aggregator.go`

Currently uses `strings.HasPrefix(callID, "rtp-")` in hot paths.

### Changes

- [x] `CallStateRTPOnly` is already set properly during call creation in `call_aggregator.go`

- [x] Replace string prefix check with state comparison in `convertToTUICall()`:
  ```go
  // BEFORE:
  if strings.HasPrefix(call.CallID, "rtp-") { ... }

  // AFTER:
  if call.State == voip.CallStateRTPOnly { ... }
  ```

- [x] Remove unused `strings` import from `local_call_aggregator.go`

**Note:** Other uses of `strings.HasPrefix` in `call_tracker.go` and `call_aggregator.go` are still needed:
- `call_tracker.go`: Format validation for synthetic CallIDs
- `call_aggregator.go`: Initial state determination when creating RTP-only calls

**Expected improvement:** O(k) string comparison → O(1) enum comparison ✅

---

## Phase 7: Pre-Parse and Cache URIs

**Files:**
- `internal/pkg/tui/components/callsview.go`
- `internal/pkg/tui/capture_events.go`

`extractSIPURI()` was called on every render for every visible row.

### Changes

- [x] Add parsed URI fields to Call struct:
  ```go
  type Call struct {
      // existing fields...
      From       string
      To         string

      // NEW: Pre-parsed for display
      FromURI    string    // Cached result of ExtractSIPURI(From)
      ToURI      string    // Cached result of ExtractSIPURI(To)
  }
  ```

- [x] Export `ExtractSIPURI()` function for use in conversion code

- [x] Parse URIs when creating/updating Call (in `capture_events.go` during types.CallInfo → components.Call conversion)

- [x] Update `renderTableWithSize()` to use cached `FromURI`/`ToURI` (fallback to parsing if empty)

- [x] Update `renderCallDetails()` to use cached URIs

- [x] Update `GetStringField()` to use cached URIs for filtering

**Expected improvement:** O(k) parsing per render → O(1) field access ✅

---

## Phase 8: Optimize Selected Call Lookup

**File:** `internal/pkg/tui/components/callsview.go`

`SetCalls()` was performing O(n) linear search to find selected call index.

### Changes

- [x] Add `callIndex map[string]int` field to `CallsView` struct

- [x] Initialize map in `NewCallsView()`

- [x] Build index during `SetCalls()`:
  ```go
  cv.callIndex = make(map[string]int, len(calls))
  for i, call := range calls {
      cv.callIndex[call.CallID] = i
  }
  ```

- [x] Replace linear search with O(1) map lookup:
  ```go
  if idx, ok := cv.callIndex[selectedCallID]; ok {
      newIndex = idx
  }
  ```

**Expected improvement:** O(n) → O(1) for selected call lookup ✅

---

## Phase 9: Reduce Allocation Frequency in Update Cycle

**File:** `internal/pkg/tui/local_call_aggregator.go`

`notifyCallUpdates()` allocates new slices on every cycle (500ms-1s).

### Changes

- [ ] Add reusable buffer:
  ```go
  type LocalCallAggregator struct {
      // existing fields...
      callInfoBuffer []types.CallInfo    // Reusable slice
  }
  ```

- [ ] Refactor `notifyCallUpdates()`:
  - Reuse buffer slice (reset length, keep capacity)
  - Only reallocate if capacity insufficient

- [ ] Consider: object pool for CallInfo if still allocating heavily

**Expected improvement:** O(n) allocations per cycle → amortized O(1)

---

## Testing

- [x] Add benchmarks for critical paths:
  - [x] `BenchmarkGetCallIDForRTPPacket` with varying call counts (Phase 1)
  - [x] `BenchmarkCallStore_*` benchmarks for store operations (Phases 2 & 3)
  - [ ] `BenchmarkCallsViewSetCalls` with large call lists

- [x] Run existing tests after each phase

- [ ] Manual testing with live VoIP traffic (high call volume)

- [ ] Profile before/after with `go tool pprof`

---

## Implementation Order

Recommended order by impact:

1. **Phase 1** - RTP lookup O(n²) is the most critical bottleneck
2. **Phase 2** - Filtered calls indexing (high frequency operation)
3. **Phase 3** - Batch updates (quick win, low risk)
4. **Phase 4** - Caching sorted lists (significant memory/CPU savings)
5. **Phase 5** - Remove redundant sort (trivial, safe)
6. **Phase 6** - CallState enum (cleanup, small improvement)
7. **Phase 7** - Cache URIs (moderate improvement)
8. **Phase 8** - Selected call index (moderate improvement)
9. **Phase 9** - Reduce allocations (polish)

---

## Success Metrics

- RTP packet processing: < 1μs per packet (currently ~100μs with 5000 calls)
- Call update cycle: < 10ms for 5000 calls (currently ~50ms)
- Memory allocations: < 10KB per update cycle (currently ~250KB)
- No visible TUI lag with 5000 active calls
