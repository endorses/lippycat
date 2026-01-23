# LRU Call Buffer Conversion Research

## Problem Statement

The current FIFO (ring buffer) eviction strategy for call tracking causes long-running active calls to be evicted in favor of newer short-duration calls. This results in:

1. Long-running calls (>30 minutes) disappearing from the TUI
2. Active calls being evicted while receiving packets, then re-added as "new" calls
3. Unstable call list display in high-volume environments

An LRU (Least Recently Used) strategy would keep active calls (those receiving packets) in the buffer while evicting idle/ended calls.

## Current Architecture

### Components Using Ring Buffers for Calls

| Component | File | Max Size | Purpose |
|-----------|------|----------|---------|
| **CallTracker** | `internal/pkg/voip/calltracker.go` | 5000 | VoIP sniff/tap/hunt per-call PCAP |
| **CallAggregator** | `internal/pkg/voip/call_aggregator.go` | 1000 | Processor-side call state aggregation |
| **CallStore** | `internal/pkg/tui/store/call_store.go` | 1000 | TUI display buffer |

### Ring Buffer Data Structure (Current)

All three implementations use the same pattern:

```go
type CallAggregator struct {
    calls     map[string]*AggregatedCall  // callID -> call data
    callRing  []string                    // Ring buffer of CallIDs
    ringHead  int                         // Next write position
    ringCount int                         // Number of calls in buffer
    maxCalls  int                         // Maximum capacity
    mu        sync.RWMutex
}
```

**Eviction Logic (FIFO):**
```go
if ringCount >= maxCalls {
    oldestCallID := callRing[ringHead]
    delete(calls, oldestCallID)
}
callRing[ringHead] = newCallID
ringHead = (ringHead + 1) % maxCalls
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Live/Tap VoIP Capture                    │
│ cmd/sniff/voip, cmd/tap/voip, cmd/hunt/voip                 │
│    ↓                                                        │
│ voip/CallTracker (FIFO)                                     │
│    - Manages per-call PCAP files                            │
│    - Evicts oldest call when full                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│           Processor-Side (Distributed Mode)                 │
│ Hunter → Processor (gRPC)                                   │
│    ↓                                                        │
│ voip/CallAggregator (FIFO)                                  │
│    - Aggregates call state from hunters                     │
│    - Evicts oldest call when full                           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│              TUI Display (All Modes)                        │
│ LocalCallAggregator → CallAggregator                        │
│    ↓                                                        │
│ tui/store/CallStore (FIFO)                                  │
│    - Mirrors CallAggregator state                           │
│    - Applies user filters                                   │
└─────────────────────────────────────────────────────────────┘
```

## Components NOT Using Ring Buffers

These do NOT need LRU conversion:

| Component | File | Storage | Cleanup Strategy |
|-----------|------|---------|------------------|
| **TimeRingBuffer** | `tui/bridge.go` | timestamps | Rolling window (not calls) |
| **CallBuffer** | `voip/callbuffer.go` | per-call packets | Lifecycle-based |
| **TUI CallTracker** | `tui/call_tracker.go` | RTP→CallID map | Unbounded |
| **CallCorrelator** | `processor/call_correlator.go` | correlation map | Time-based (5 min ticker) |

## LRU Data Structure Proposal

### Option 1: Standard LRU (container/list + map)

```go
import "container/list"

type CallAggregator struct {
    calls    map[string]*AggregatedCall  // callID -> call data
    lruList  *list.List                  // Doubly-linked list for LRU ordering
    lruIndex map[string]*list.Element    // callID -> list element (for O(1) access)
    maxCalls int
    mu       sync.RWMutex
}
```

**Operations:**
- **Add new call:** Push to front of list, add to both maps
- **Update existing call:** Move element to front of list (O(1) via lruIndex)
- **Evict:** Remove from back of list (least recently used)
- **Lookup:** O(1) via calls map

**Pros:**
- Standard pattern, well-understood
- O(1) for all operations
- `container/list` is in stdlib

**Cons:**
- More memory overhead (~48 bytes per entry for list element + map entry)
- Two maps to maintain

### Option 2: Intrusive List (embed list pointers in call struct)

```go
type lruEntry struct {
    callID string
    prev   *lruEntry
    next   *lruEntry
}

type CallAggregator struct {
    calls    map[string]*AggregatedCall
    lruHead  *lruEntry  // Most recently used
    lruTail  *lruEntry  // Least recently used
    lruIndex map[string]*lruEntry
    maxCalls int
    mu       sync.RWMutex
}
```

**Pros:**
- Slightly less memory (no list.Element wrapper)
- More control over implementation

**Cons:**
- More code to maintain
- No significant benefit over Option 1

### Option 3: External LRU Library

Use `github.com/hashicorp/golang-lru` or similar.

**Pros:**
- Battle-tested implementation
- May have additional features (thread-safety options, metrics)

**Cons:**
- External dependency
- May not fit exact use case (e.g., custom eviction callbacks)

### Recommendation: Option 1

Use `container/list` + map. It's:
- Standard Go pattern
- No external dependencies
- Easy to understand and maintain
- Proven correct by stdlib

## Files Requiring Changes

### 1. `internal/pkg/voip/call_aggregator.go`

**Current lines affected:**
- 68-75: Struct definition (replace ring buffer fields)
- 84-94: Constructor (initialize LRU structures)
- 224-237: SIP path eviction (change to LRU)
- 369-382: RTP path eviction (change to LRU)
- 519-531: `GetCalls()` (may need adjustment for ordering)

**New behavior:**
- On new call: add to front of LRU list
- On update (SIP/RTP packet): move to front of LRU list
- On eviction: remove from back of LRU list

### 2. `internal/pkg/tui/store/call_store.go`

**Current lines affected:**
- 12-24: Struct definition
- 38-67: `AddOrUpdateCall()` eviction logic
- 76-107: `GetCallsInOrder()` iteration

**New behavior:**
- Same LRU pattern as CallAggregator
- `GetCallsInOrder()` returns MRU→LRU order (or configurable)

### 3. `internal/pkg/voip/calltracker.go`

**Current lines affected:**
- 96-148: Struct definition and ring buffer fields
- 238-293: `GetOrCreateCall()` eviction logic

**Question:** Does CallTracker need LRU?
- CallTracker is used for per-call PCAP file management
- Calls that are actively receiving packets should stay
- **Yes, it should also use LRU** to prevent active calls from being evicted

### 4. Test Files

**Files to update:**
- `internal/pkg/voip/call_aggregator_test.go`
  - `TestCallAggregator_RingBufferEvictionRace` (lines 720-874)
  - `TestCallAggregator_EvictionOrder` (lines 941-1009) - change to verify LRU order
- `internal/pkg/voip/calltracker_test.go`
  - Any eviction order tests
- `internal/pkg/tui/store/call_store_test.go` (if exists)

## Behavioral Changes

### Current (FIFO)

```
Time 0: Add Call A (oldest)
Time 1: Add Call B
Time 2: Add Call C
...
Time 1000: Buffer full, add Call X
  → Evicts Call A (oldest by insertion time)
  → Even if Call A just received a packet at Time 999
```

### Proposed (LRU)

```
Time 0: Add Call A
Time 1: Add Call B
Time 2: Add Call C
...
Time 999: Call A receives packet → moves to front
Time 1000: Buffer full, add Call X
  → Evicts Call B (least recently accessed)
  → Call A stays because it was recently active
```

### Edge Cases to Consider

1. **Ended calls:** Should ended calls be deprioritized?
   - Option A: Treat all calls equally (pure LRU)
   - Option B: Prefer evicting ended calls first (LRU within category)

2. **Read vs Write access:** Should reads (GetCall, GetCalls) update LRU?
   - For CallAggregator: No (reads are for display, not activity)
   - For CallStore: No (reads are view rendering)
   - Only packet processing should update LRU

3. **Ordering in GetCalls():**
   - Current: Chronological (oldest first)
   - LRU: Most recently used first, or least recently used first?
   - Recommendation: Keep chronological by StartTime for display consistency

## Performance Considerations

| Operation | Ring Buffer | LRU (container/list) |
|-----------|-------------|---------------------|
| Add new | O(1) | O(1) |
| Update existing | O(1) | O(1) |
| Evict | O(1) | O(1) |
| Lookup by ID | O(1) | O(1) |
| Iterate all | O(n) | O(n) |
| Memory per call | ~8 bytes (string in slice) | ~56 bytes (list element + map entry) |

For 1000-5000 calls, the memory difference is negligible (8KB vs 56KB per 1000 calls).

## Migration Strategy

1. **Phase 1:** Update CallAggregator (processor-side)
   - Most impact on user-reported issue
   - Has comprehensive test coverage

2. **Phase 2:** Update CallStore (TUI-side)
   - Must stay in sync with CallAggregator behavior
   - Filter chain integration needs verification

3. **Phase 3:** Update CallTracker (sniff/tap/hunt)
   - Lower priority (different use case)
   - Per-call PCAP files add complexity

## Design Decisions

1. **Pure LRU** - All calls treated equally regardless of state (active/ended/failed). Evict least recently accessed.
2. **No grace period** - Ended calls follow normal LRU eviction, no special retention.
3. **Keep chronological display** - LRU is for eviction policy only. Display remains sorted by StartTime.
4. **Keep 1000 call limit** - LRU makes the limit more effective; no need to increase.

## Related Code

- `internal/pkg/processor/call_correlator.go` - Uses time-based cleanup (5 min), not LRU
- `internal/pkg/tui/call_tracker.go` - Unbounded map, no eviction
- `internal/pkg/voip/callbuffer.go` - Per-call packet buffer, lifecycle-based

## References

- Go `container/list` package: https://pkg.go.dev/container/list
- LRU Cache pattern: https://en.wikipedia.org/wiki/Cache_replacement_policies#LRU
