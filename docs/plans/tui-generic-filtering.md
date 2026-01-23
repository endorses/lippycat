# Implementation Plan: TUI Generic Filtering

**Goal:** Enable `/` filtering on protocol-specific views (VoIP calls first), reusing the packet filter infrastructure.

**Research:** [docs/research/tui-generic-filtering.md](../research/tui-generic-filtering.md)

---

## Phase 1: Filterable Interface

### 1.1 Create Filterable Interface (`internal/pkg/tui/filters/filterable.go`)
- [x] Define `Filterable` interface with `GetStringField()`, `GetNumericField()`, `HasField()`, `RecordType()`
- [x] Define `getCommonFields(recordType string) []string` helper for "search all" behavior

### 1.2 Implement Filterable on PacketDisplay (`internal/pkg/types/packet.go`)
- [x] Add `GetStringField(name string) string` - map src, dst, protocol, info, node, sip.* fields
- [x] Add `GetNumericField(name string) float64` - map length, sip.status, rtp fields, dns/http fields
- [x] Add `HasField(name string) bool`
- [x] Add `RecordType() string` returning `"packet"`

### 1.3 Implement Filterable on Call (`internal/pkg/tui/components/callsview.go`)
- [x] Add `GetStringField(name string) string` - map callid, from, to, state, codec, node
- [x] Add `GetNumericField(name string) float64` - map duration, mos, jitter, loss, packets
- [x] Add `HasField(name string) bool`
- [x] Add `RecordType() string` returning `"call"`

---

## Phase 2: Filter Interface Changes

### 2.1 Update Filter Interface (`internal/pkg/tui/filters/filters.go`)
- [x] Change `Match(packet components.PacketDisplay) bool` to `Match(record Filterable) bool`
- [x] Add `SupportedRecordTypes() []string` (nil = all types)

### 2.2 Update FilterChain (`internal/pkg/tui/filters/filters.go`)
- [x] Change `Match()` to accept `Filterable`

### 2.3 Update Existing Filters
- [x] `text.go` - Use `GetStringField()` and `GetCommonFields()` for generic field access
- [x] `voip.go` - Use `GetStringField()` for sip.* fields, add `SupportedRecordTypes() []string{"packet"}`
- [x] `bpf.go` - Add `SupportedRecordTypes() []string{"packet"}`, return false for non-packets
- [x] `metadata.go` - Update to use `Filterable` and `HasField()`
- [x] `node.go` - Update to use `GetStringField("node")`
- [x] `boolean.go` - Update `Match()` signature

### 2.4 Update Tests
- [x] `filters_test.go` - Tests pass with Filterable (PacketDisplay implements interface)
- [x] `voip_test.go` - Tests pass with Filterable
- [x] `node_test.go` - Tests pass with Filterable

---

## Phase 3: New Filter Types

### 3.1 CallStateFilter (`internal/pkg/tui/filters/call_state.go`)
- [x] Match calls by state: `state:active`, `state:ringing,ended`
- [x] Case-insensitive matching
- [x] `SupportedRecordTypes() []string{"call"}`

### 3.2 NumericComparisonFilter (`internal/pkg/tui/filters/numeric.go`)
- [x] Operators: `>`, `<`, `>=`, `<=`, `=`
- [x] Fields: duration, mos, jitter, loss, packets
- [x] Duration parsing: `30s`, `5m`, `1h`, `1h30m`

### 3.3 Tests
- [x] `call_state_test.go`
- [x] `numeric_test.go`

---

## Phase 4: CallStore Filtering

### 4.1 Add Filter Support to CallStore (`internal/pkg/tui/store/call_store.go`)
- [x] Add `FilterChain *filters.FilterChain`
- [x] Add `filteredCalls []components.Call`
- [x] Add `matchedCalls int64`

### 4.2 Filter Methods
- [x] `AddFilter(filter filters.Filter)` - add and reapply to existing calls
- [x] `RemoveLastFilter() bool`
- [x] `ClearFilter()`
- [x] `HasFilter() bool`
- [x] `GetFilteredCalls() []components.Call`
- [x] `GetFilteredCallCount() int`

### 4.3 Update AddOrUpdateCall
- [x] Apply filter on new/updated calls
- [x] Update filtered calls list

---

## Phase 5: Call Filter Parsing

### 5.1 Add Call Filter Parser (`internal/pkg/tui/filter_helpers.go`)
- [x] Add `parseCallFilter(filterStr string) filters.Filter`
- [x] Handle `state:active` → CallStateFilter
- [x] Handle `duration:>30s` → NumericComparisonFilter
- [x] Handle `mos:>3.5`, `jitter:<50`, `loss:>5` → NumericComparisonFilter
- [x] Handle `from:`, `to:`, `user:`, `callid:`, `codec:` → TextFilter
- [x] Handle `node:` → NodeFilter
- [x] Default: TextFilter on all fields

---

## Phase 6: UI Integration

### 6.1 Add Filter State to Model (`internal/pkg/tui/store/ui_state.go`)
- [x] Add `CallFilterMode bool`
- [x] Add `CallFilterInput components.FilterInput` (separate instance)

### 6.2 Keyboard Handler (`internal/pkg/tui/keyboard_handler.go`)
- [x] Add `/` handler for VoIP subtab (calls view)
- [x] Route to `handleEnterCallFilterMode()`
- [x] Add `c`/`C` handlers for call filter clear

### 6.3 Call Filter Operations (`internal/pkg/tui/filter_operations.go`)
- [x] Add `handleCallFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd)`
- [x] Add `handleEnterCallFilterMode() (Model, tea.Cmd)`
- [x] Add `handleRemoveLastCallFilter() (Model, tea.Cmd)`
- [x] Add `handleClearAllCallFilters() (Model, tea.Cmd)`
- [x] Add `parseAndApplyCallFilter(filterStr string) tea.Cmd`

### 6.4 CallsView Updates (`internal/pkg/tui/capture_events.go`)
- [x] Display filtered calls when filter active
- [x] Show filter count in view (via footer)

### 6.5 Footer Updates (`internal/pkg/tui/components/footer.go`)
- [x] Show filter keybinds when on VoIP calls view: `[/] Filter  [c] Clear last  [C] Clear all`
- [x] Show active filter count (via viewMode-aware keybinds)

### 6.6 View Renderer (`internal/pkg/tui/view_renderer.go`)
- [x] Render call filter input when `callFilterMode` is true

---

## Phase 7: PacketStore Migration

### 7.1 Update PacketStore (`internal/pkg/tui/store/packet_store.go`)
- [x] Update `Match()` calls to pass packet as `Filterable`
- [x] Verify no breakage

---

## Implementation Notes

**Filter state separation:** Packet filters and call filters maintain separate state. Both are on the Capture tab but operate on different views. Switching between packet list and calls view preserves each view's filters.

**BPF filters on calls:** Return false silently (not an error). BPF is packet-specific by nature.

**Reapply on filter change:** Unlike packets (high volume, buffer refills quickly), calls are low volume. Reapplying filters to existing calls on add/remove is acceptable.

**No generics:** Use `Filterable` interface rather than Go generics. Simpler, avoids generic limitations.

**Cross-record filtering:** Out of scope. Future enhancement to show packets belonging to filtered calls.

---

## Files Changed

```
internal/pkg/tui/filters/filterable.go          # NEW: Filterable interface
internal/pkg/tui/filters/filters.go             # Filter interface changes
internal/pkg/tui/filters/text.go                # Use Filterable
internal/pkg/tui/filters/voip.go                # Use Filterable
internal/pkg/tui/filters/bpf.go                 # Add SupportedRecordTypes
internal/pkg/tui/filters/metadata.go            # Use Filterable
internal/pkg/tui/filters/node.go                # Use Filterable
internal/pkg/tui/filters/boolean.go             # Update Match signature
internal/pkg/tui/filters/call_state.go          # NEW: CallStateFilter
internal/pkg/tui/filters/numeric.go             # NEW: NumericComparisonFilter
internal/pkg/tui/store/call_store.go            # Add filtering
internal/pkg/tui/store/packet_store.go          # Update Match calls
internal/pkg/tui/components/packetlist.go       # Implement Filterable
internal/pkg/tui/components/callsview.go        # Implement Filterable
internal/pkg/tui/components/footer.go           # Call filter keybinds
internal/pkg/tui/model.go                       # Call filter state
internal/pkg/tui/filter_helpers.go              # parseCallFilter
internal/pkg/tui/filter_operations.go           # Call filter handlers
internal/pkg/tui/keyboard_handler.go            # / key for calls
internal/pkg/tui/view_renderer.go               # Render call filter input
```

---

## Call Filter Syntax Reference

| Syntax | Example | Description |
|--------|---------|-------------|
| `state:X` | `state:active` | Match call state |
| `state:X,Y` | `state:ringing,ended` | Match multiple states |
| `from:X` | `from:alice` | From field contains |
| `to:X` | `to:bob` | To field contains |
| `user:X` | `user:alice` | From or To contains |
| `callid:X` | `callid:abc123` | Call ID contains |
| `codec:X` | `codec:g711` | Codec contains |
| `duration:OP` | `duration:>30s` | Duration comparison |
| `mos:OP` | `mos:>3.5` | MOS quality threshold |
| `jitter:OP` | `jitter:<50` | Jitter threshold (ms) |
| `loss:OP` | `loss:>5` | Packet loss threshold (%) |
| `node:X` | `node:hunter-1` | Origin node |
| `text` | `alice` | Search all string fields |

Duration formats: `30s`, `5m`, `1h`, `1h30m`

Operators: `>`, `<`, `>=`, `<=`, `=`
