# TUI Generic Filtering System

Research document for abstracting the TUI filter system to support multiple record types (packets, calls, and future protocols).

## Current Architecture

### Filter Interface (Packet-Specific)

**File:** `internal/pkg/tui/filters/filters.go`

```go
type Filter interface {
    Match(packet components.PacketDisplay) bool
    String() string
    Type() string
    Selectivity() float64
}
```

The current `Filter` interface is tightly coupled to `PacketDisplay`. All filter implementations (`TextFilter`, `VoIPFilter`, `BPFFilter`, `MetadataFilter`, `NodeFilter`, `BooleanFilter`) operate exclusively on packets.

### FilterChain

**File:** `internal/pkg/tui/filters/filters.go`

```go
type FilterChain struct {
    filters        []filterWithOrder
    nextOrderIndex int
}

func (fc *FilterChain) Match(packet components.PacketDisplay) bool { ... }
```

The chain also operates on `PacketDisplay`, making it unusable for calls or other record types.

### PacketStore (Storage + Filtering)

**File:** `internal/pkg/tui/store/packet_store.go`

PacketStore combines storage and filtering:
- Ring buffer for all packets
- `FilteredPackets` slice for matching packets
- `FilterChain` for active filters
- `AddPacketBatch()` applies filters inline

### CallStore (Storage Only)

**File:** `internal/pkg/tui/store/call_store.go`

CallStore has no filtering:
- Ring buffer with O(1) lookup by CallID
- No `FilterChain` integration
- No `FilteredCalls` tracking

### Parser Integration

**File:** `internal/pkg/tui/filter_helpers.go`

The parser (`parseSimpleFilter`) detects filter types and creates packet-specific filters:
- `sip.user:alicent` → `VoIPFilter`
- `has:voip` → `MetadataFilter`
- `node:hunter-1` → `NodeFilter`
- `port 5060` → `BPFFilter`
- Bare text → `TextFilter`

---

## Proposed Design

### Option 1: Filterable Interface (Recommended)

Define a common interface that both packets and calls implement:

```go
// internal/pkg/tui/filters/filterable.go

// Filterable represents any record that can be filtered
type Filterable interface {
    // GetStringField returns a string field value by name
    // Returns empty string if field doesn't exist
    GetStringField(name string) string

    // GetNumericField returns a numeric field value by name
    // Returns 0 if field doesn't exist or isn't numeric
    GetNumericField(name string) float64

    // HasField returns true if the record has the named field
    HasField(name string) bool

    // RecordType returns the type identifier ("packet", "call", "email", etc.)
    RecordType() string
}
```

**PacketDisplay implementation:**

```go
func (p PacketDisplay) GetStringField(name string) string {
    switch name {
    case "src", "srcip":
        return p.SrcIP
    case "dst", "dstip":
        return p.DstIP
    case "srcport":
        return p.SrcPort
    case "dstport":
        return p.DstPort
    case "protocol":
        return p.Protocol
    case "info":
        return p.Info
    case "node", "nodeid":
        return p.NodeID
    // VoIP fields (from VoIPData)
    case "sip.user", "sip.from":
        if p.VoIPData != nil { return p.VoIPData.User }
    case "sip.to":
        if p.VoIPData != nil { return p.VoIPData.To }
    case "sip.callid":
        if p.VoIPData != nil { return p.VoIPData.CallID }
    case "sip.method":
        if p.VoIPData != nil { return p.VoIPData.Method }
    }
    return ""
}

func (p PacketDisplay) RecordType() string { return "packet" }
```

**Call implementation:**

```go
func (c Call) GetStringField(name string) string {
    switch name {
    case "callid":
        return c.CallID
    case "from", "user":
        return extractUser(c.From)
    case "to":
        return extractUser(c.To)
    case "state":
        return c.State.String()
    case "codec":
        return c.Codec
    case "node", "nodeid":
        return c.NodeID
    }
    return ""
}

func (c Call) GetNumericField(name string) float64 {
    switch name {
    case "duration":
        return c.Duration.Seconds()
    case "mos":
        return c.MOS
    case "jitter":
        return c.Jitter
    case "loss", "packetloss":
        return c.PacketLoss
    case "packets", "packetcount":
        return float64(c.PacketCount)
    }
    return 0
}

func (c Call) RecordType() string { return "call" }
```

### Generic Filter Interface

```go
// internal/pkg/tui/filters/filter.go

// Filter represents a filter that operates on any Filterable record
type Filter interface {
    Match(record Filterable) bool
    String() string
    Type() string
    Selectivity() float64

    // SupportedRecordTypes returns which record types this filter supports
    // Empty slice means all types (generic filter)
    SupportedRecordTypes() []string
}
```

### Generic FilterChain

```go
// FilterChain[T] would be ideal but Go generics have limitations
// Instead, use Filterable interface

type FilterChain struct {
    filters        []filterWithOrder
    nextOrderIndex int
    recordType     string  // Optional: restrict to specific record type
}

func (fc *FilterChain) Match(record Filterable) bool {
    if len(fc.filters) == 0 {
        return true
    }
    for _, fwo := range fc.filters {
        if !fwo.filter.Match(record) {
            return false
        }
    }
    return true
}
```

### Refactored Filter Types

**TextFilter (Generic):**

```go
type TextFilter struct {
    searchText string
    fields     []string  // "all" searches all string fields
    searchAll  bool
}

func (f *TextFilter) Match(record Filterable) bool {
    if f.searchAll {
        // Search common fields based on record type
        commonFields := getCommonFields(record.RecordType())
        for _, field := range commonFields {
            if strings.Contains(
                strings.ToLower(record.GetStringField(field)),
                f.searchText,
            ) {
                return true
            }
        }
        return false
    }
    // Search specific fields
    for _, field := range f.fields {
        if strings.Contains(
            strings.ToLower(record.GetStringField(field)),
            f.searchText,
        ) {
            return true
        }
    }
    return false
}

func (f *TextFilter) SupportedRecordTypes() []string {
    return nil  // All types
}
```

**CallStateFilter (Call-Specific):**

```go
type CallStateFilter struct {
    states []CallState  // Match any of these states
}

func (f *CallStateFilter) Match(record Filterable) bool {
    if record.RecordType() != "call" {
        return false
    }
    stateStr := record.GetStringField("state")
    for _, s := range f.states {
        if strings.EqualFold(stateStr, s.String()) {
            return true
        }
    }
    return false
}

func (f *CallStateFilter) SupportedRecordTypes() []string {
    return []string{"call"}
}
```

**NumericComparisonFilter (Generic):**

```go
type NumericComparisonFilter struct {
    field    string
    operator string  // ">", "<", ">=", "<=", "="
    value    float64
}

func (f *NumericComparisonFilter) Match(record Filterable) bool {
    fieldValue := record.GetNumericField(f.field)
    switch f.operator {
    case ">":
        return fieldValue > f.value
    case "<":
        return fieldValue < f.value
    case ">=":
        return fieldValue >= f.value
    case "<=":
        return fieldValue <= f.value
    case "=", "==":
        return fieldValue == f.value
    }
    return false
}
```

---

## Filter Syntax by Record Type

### Packet Filters (Existing)

| Syntax | Filter Type | Example |
|--------|-------------|---------|
| `sip.user:alicent` | VoIPFilter | Match SIP user |
| `sip.from:555*` | VoIPFilter | Wildcard match |
| `has:voip` | MetadataFilter | Has VoIP metadata |
| `node:hunter-1` | NodeFilter | Match node ID |
| `port 5060` | BPFFilter | BPF expression |
| `protocol:UDP` | TextFilter | Field-specific |
| `192.168` | TextFilter | Search all fields |

### Call Filters (New)

| Syntax | Filter Type | Example |
|--------|-------------|---------|
| `state:active` | CallStateFilter | Call state |
| `state:ringing,ended` | CallStateFilter | Multiple states |
| `from:alicent` | TextFilter | From field |
| `to:robb` | TextFilter | To field |
| `user:alicent` | TextFilter | From or To |
| `callid:abc123` | TextFilter | Call ID |
| `codec:g711` | TextFilter | Codec match |
| `duration:>30s` | NumericComparisonFilter | Duration > 30s |
| `duration:<5m` | NumericComparisonFilter | Duration < 5min |
| `mos:>3.5` | NumericComparisonFilter | Quality threshold |
| `jitter:<50` | NumericComparisonFilter | Jitter < 50ms |
| `loss:>5` | NumericComparisonFilter | Packet loss > 5% |
| `node:hunter-1` | NodeFilter | Origin node |
| `alicent` | TextFilter | Search all fields |

### Duration Parsing

Support common duration formats:
- `30s` → 30 seconds
- `5m` → 5 minutes
- `1h` → 1 hour
- `1h30m` → 1 hour 30 minutes

---

## Refactoring Assessment

### Files Requiring Changes

#### High Impact (Core Filter System)

| File | Change Required | Effort |
|------|-----------------|--------|
| `filters/filters.go` | Change `Filter` interface to use `Filterable` | Medium |
| `filters/text.go` | Refactor to use `GetStringField()` | Medium |
| `filters/voip.go` | Refactor to use `GetStringField()` for packet fields | Medium |
| `filters/boolean.go` | Update `Match()` signature | Low |
| `filters/metadata.go` | Update to use `Filterable` | Low |
| `filters/node.go` | Update to use `Filterable` | Low |
| `filters/bpf.go` | Keep packet-specific, add `SupportedRecordTypes()` | Low |

#### Medium Impact (Store Layer)

| File | Change Required | Effort |
|------|-----------------|--------|
| `store/packet_store.go` | Update `Match()` calls to pass `Filterable` | Low |
| `store/call_store.go` | Add `FilterChain`, `FilteredCalls`, filter methods | High |

#### Low Impact (UI/Integration)

| File | Change Required | Effort |
|------|-----------------|--------|
| `filter_helpers.go` | Add call-specific filter parsing | Medium |
| `filter_operations.go` | Generalize or duplicate for calls view | Medium |
| `components/callsview.go` | Add filter mode, display filtered calls | Medium |
| `keyboard_handler.go` | Add `/` handler for calls tab | Low |
| `components/filterinput.go` | No changes needed (already generic) | None |

#### New Files Required

| File | Purpose |
|------|---------|
| `filters/filterable.go` | `Filterable` interface definition |
| `filters/call_state.go` | `CallStateFilter` implementation |
| `filters/numeric.go` | `NumericComparisonFilter` implementation |
| `filters/duration.go` | Duration parsing utilities |

### Type Changes Required

**PacketDisplay** (`components/packetlist.go` or `types/packet.go`):
- Add `GetStringField(name string) string`
- Add `GetNumericField(name string) float64`
- Add `HasField(name string) bool`
- Add `RecordType() string`

**Call** (`components/callsview.go`):
- Add `GetStringField(name string) string`
- Add `GetNumericField(name string) float64`
- Add `HasField(name string) bool`
- Add `RecordType() string`

---

## CallStore Filtering Integration

### Required Additions to CallStore

```go
type CallStore struct {
    mu            sync.RWMutex
    calls         map[string]*components.Call
    callRing      []string
    ringHead      int
    ringCount     int
    maxCalls      int
    totalCalls    int

    // New: filtering support
    FilterChain     *filters.FilterChain
    filteredCalls   []components.Call
    matchedCalls    int64
}

// AddOrUpdateCall with filtering
func (cs *CallStore) AddOrUpdateCall(call components.Call) {
    cs.mu.Lock()
    defer cs.mu.Unlock()

    // ... existing ring buffer logic ...

    // Apply filter if active
    if cs.FilterChain != nil && !cs.FilterChain.IsEmpty() {
        if cs.FilterChain.Match(&call) {
            cs.updateFilteredCall(call)
            cs.matchedCalls++
        }
    }
}

// Filter management methods
func (cs *CallStore) AddFilter(filter filters.Filter)
func (cs *CallStore) RemoveLastFilter() bool
func (cs *CallStore) ClearFilter()
func (cs *CallStore) HasFilter() bool
func (cs *CallStore) GetFilteredCalls() []components.Call
```

### Performance Consideration

Unlike packets (which arrive at high rates and refill buffers quickly), calls are relatively rare events. Re-applying filters to existing calls on filter change is acceptable:

```go
func (cs *CallStore) reapplyFilters() {
    cs.filteredCalls = make([]components.Call, 0)
    for _, call := range cs.calls {
        if cs.FilterChain.Match(call) {
            cs.filteredCalls = append(cs.filteredCalls, *call)
        }
    }
}
```

---

## UI Integration

### CallsView Filter Mode

Add filter state and input handling to CallsView:

```go
type CallsView struct {
    // ... existing fields ...
    filterMode   bool
    filterInput  *FilterInput  // Reuse existing component
}

func (cv *CallsView) Update(msg tea.Msg) tea.Cmd {
    if cv.filterMode {
        return cv.handleFilterInput(msg)
    }
    // ... existing key handling ...
}
```

### Keyboard Handler Changes

In `keyboard_handler.go`, add `/` handling for calls tab:

```go
case "/":
    switch m.uiState.Tabs.GetActive() {
    case 0: // Capture tab (existing)
        return m.handleEnterFilterMode()
    case 2: // Calls tab (new)
        return m.handleEnterCallFilterMode()
    }
```

### Footer Updates

Update footer to show filter keybinds on calls tab:

```
Calls Tab: [/] Filter  [c] Clear last  [C] Clear all  [↑↓] Navigate
```

---

## Boolean Expression Support

The existing boolean parser (`ParseBooleanExpression`) accepts a `parseSimpleFilter` function parameter. This design allows reuse:

```go
// For packets
filter, _ := filters.ParseBooleanExpression(expr, m.parsePacketFilter)

// For calls
filter, _ := filters.ParseBooleanExpression(expr, m.parseCallFilter)
```

The `parseCallFilter` function would handle call-specific syntax:

```go
func (m *Model) parseCallFilter(filterStr string) filters.Filter {
    // state:active
    if strings.HasPrefix(filterStr, "state:") {
        return parseCallStateFilter(filterStr)
    }
    // duration:>30s
    if strings.HasPrefix(filterStr, "duration:") {
        return parseDurationFilter(filterStr)
    }
    // mos:>3.5, jitter:<50, loss:>5
    if isNumericFilter(filterStr) {
        return parseNumericFilter(filterStr)
    }
    // Default: text search
    return filters.NewTextFilter(filterStr, []string{"all"})
}
```

---

## Future Protocol Support

The `Filterable` interface enables future protocol views:

### Email View (Future)

```go
type Email struct {
    MessageID   string
    From        string
    To          []string
    Subject     string
    Date        time.Time
    Size        int64
    HasAttach   bool
}

func (e Email) GetStringField(name string) string {
    switch name {
    case "from": return e.From
    case "subject": return e.Subject
    case "messageid": return e.MessageID
    }
    return ""
}

func (e Email) RecordType() string { return "email" }
```

Filter syntax: `from:alicent@`, `subject:invoice`, `size:>1MB`

### DNS View (Future)

```go
type DNSQuery struct {
    QueryName   string
    QueryType   string  // A, AAAA, MX, etc.
    ResponseIP  string
    TTL         int
    Latency     time.Duration
}

func (d DNSQuery) GetStringField(name string) string { ... }
func (d DNSQuery) RecordType() string { return "dns" }
```

Filter syntax: `type:A`, `name:*.google.com`, `latency:>100ms`

---

## Risk Assessment

### Low Risk
- `FilterInput` component is already generic (works with any text)
- Boolean parser accepts pluggable filter factory
- Filter stacking pattern is record-agnostic

### Medium Risk
- BPF filters are inherently packet-specific (need `SupportedRecordTypes()` guard)
- Performance characteristics differ (packets=high volume, calls=low volume)
- Some existing VoIP filters blur packet/call boundary

### High Risk
- Changing `Filter.Match()` signature breaks all existing filters
- `PacketStore` and filter integration is tightly coupled
- Test coverage for filters may need significant updates

---

## Migration Strategy

### Phase 1: Interface Preparation
1. Add `Filterable` interface
2. Implement `Filterable` on `PacketDisplay` and `Call`
3. Add `SupportedRecordTypes()` to existing filters (return nil for generic)

### Phase 2: Filter Refactoring
1. Change `Filter.Match()` to accept `Filterable`
2. Update each filter implementation
3. Update `FilterChain.Match()`
4. Update tests

### Phase 3: CallStore Integration
1. Add filter fields to `CallStore`
2. Implement filter methods
3. Add reapply logic (acceptable for low-volume calls)

### Phase 4: UI Integration
1. Add filter mode to `CallsView`
2. Add keyboard handling for calls tab
3. Add call-specific filter parsing
4. Update footer keybinds

### Phase 5: New Filter Types
1. Implement `CallStateFilter`
2. Implement `NumericComparisonFilter`
3. Add duration parsing
4. Update help/documentation

---

## Open Questions

1. **Should we use Go generics?**
   - Pro: Type safety, cleaner API
   - Con: Go 1.18+ generics have limitations, may complicate filter composition
   - Recommendation: Start with interface, consider generics for FilterChain only

2. **Should BPF filters fail silently on non-packets?**
   - Option A: Return false (silent mismatch)
   - Option B: Panic/error (programmer mistake)
   - Recommendation: Return false with optional warning log/toast

3. **How to handle filter persistence across tab switches?**
   - Option A: Separate filter state per tab
   - Option B: Clear filters on tab switch
   - Recommendation: Separate state (filters are tab-specific context)
   - Answer: I reject the question. Packet filters and protocol specific filters are both on the capture tab.
             The real question is whether or not filters should have separate states between views (packet list vs. protocol specific view).
             And the answer to that is: Yes. Packet filters should be separate from i.e. call filters.

4. **Should we support cross-record filtering?**
   - Example: Show packets belonging to filtered calls
   - Adds complexity but powerful for analysis
   - Recommendation: Out of scope for initial implementation
   - Answer: This will be implemented long term.

---

## Estimated Effort

| Component | Effort | Dependencies |
|-----------|--------|--------------|
| Filterable interface | 2h | None |
| PacketDisplay implementation | 2h | Filterable |
| Call implementation | 2h | Filterable |
| Filter interface changes | 4h | Filterable |
| TextFilter refactor | 2h | Filter interface |
| Other filter refactors | 4h | Filter interface |
| CallStateFilter | 2h | Filter interface |
| NumericComparisonFilter | 3h | Filter interface |
| Duration parsing | 1h | None |
| CallStore filtering | 4h | Filter interface |
| CallsView filter mode | 4h | CallStore filtering |
| Keyboard/footer integration | 2h | CallsView |
| Tests | 8h | All above |
| **Total** | **~40h** | |

---

## Appendix: Current Filter Files

```
internal/pkg/tui/filters/
├── filters.go       # Filter interface, FilterChain
├── boolean.go       # AND/OR/NOT parsing
├── text.go          # Text/substring filter
├── voip.go          # VoIP field filter (sip.*)
├── bpf.go           # BPF expression filter
├── metadata.go      # has:voip filter
├── node.go          # node:* filter
├── filters_test.go  # FilterChain tests
├── voip_test.go     # VoIP filter tests
└── node_test.go     # Node filter tests
```
