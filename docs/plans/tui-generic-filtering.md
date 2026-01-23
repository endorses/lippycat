# Implementation Plan: TUI Generic Filtering

**Goal:** Enable `/` filtering on protocol-specific views (VoIP calls first), reusing the packet filter infrastructure.

**Research:** [docs/research/tui-generic-filtering.md](../research/tui-generic-filtering.md)

---

## Phase 1: Filterable Interface

### 1.1 Create Filterable Interface (`internal/pkg/tui/filters/filterable.go`)
- [ ] Define `Filterable` interface with `GetStringField()`, `GetNumericField()`, `HasField()`, `RecordType()`
- [ ] Define `getCommonFields(recordType string) []string` helper for "search all" behavior

### 1.2 Implement Filterable on PacketDisplay (`internal/pkg/tui/components/packetlist.go`)
- [ ] Add `GetStringField(name string) string` - map src, dst, protocol, info, node, sip.* fields
- [ ] Add `GetNumericField(name string) float64` - return 0 (packets have no numeric filters)
- [ ] Add `HasField(name string) bool`
- [ ] Add `RecordType() string` returning `"packet"`

### 1.3 Implement Filterable on Call (`internal/pkg/tui/components/callsview.go`)
- [ ] Add `GetStringField(name string) string` - map callid, from, to, state, codec, node
- [ ] Add `GetNumericField(name string) float64` - map duration, mos, jitter, loss, packets
- [ ] Add `HasField(name string) bool`
- [ ] Add `RecordType() string` returning `"call"`

---

## Phase 2: Filter Interface Changes

### 2.1 Update Filter Interface (`internal/pkg/tui/filters/filters.go`)
- [ ] Change `Match(packet components.PacketDisplay) bool` to `Match(record Filterable) bool`
- [ ] Add `SupportedRecordTypes() []string` (nil = all types)

### 2.2 Update FilterChain (`internal/pkg/tui/filters/filters.go`)
- [ ] Change `Match()` to accept `Filterable`

### 2.3 Update Existing Filters
- [ ] `text.go` - Use `GetStringField()` instead of direct field access
- [ ] `voip.go` - Use `GetStringField()` for sip.* fields, add `SupportedRecordTypes() []string{"packet"}`
- [ ] `bpf.go` - Add `SupportedRecordTypes() []string{"packet"}`, return false for non-packets
- [ ] `metadata.go` - Update to use `Filterable`
- [ ] `node.go` - Update to use `GetStringField("node")`
- [ ] `boolean.go` - Update `Match()` signature

### 2.4 Update Tests
- [ ] `filters_test.go` - Update to use Filterable
- [ ] `voip_test.go` - Update test cases
- [ ] `node_test.go` - Update test cases

---

## Phase 3: New Filter Types

### 3.1 CallStateFilter (`internal/pkg/tui/filters/call_state.go`)
- [ ] Match calls by state: `state:active`, `state:ringing,ended`
- [ ] Case-insensitive matching
- [ ] `SupportedRecordTypes() []string{"call"}`

### 3.2 NumericComparisonFilter (`internal/pkg/tui/filters/numeric.go`)
- [ ] Operators: `>`, `<`, `>=`, `<=`, `=`
- [ ] Fields: duration, mos, jitter, loss, packets
- [ ] Duration parsing: `30s`, `5m`, `1h`, `1h30m`

### 3.3 Tests
- [ ] `call_state_test.go`
- [ ] `numeric_test.go`

---

## Phase 4: CallStore Filtering

### 4.1 Add Filter Support to CallStore (`internal/pkg/tui/store/call_store.go`)
- [ ] Add `FilterChain *filters.FilterChain`
- [ ] Add `filteredCalls []components.Call`
- [ ] Add `matchedCalls int64`

### 4.2 Filter Methods
- [ ] `AddFilter(filter filters.Filter)` - add and reapply to existing calls
- [ ] `RemoveLastFilter() bool`
- [ ] `ClearFilter()`
- [ ] `HasFilter() bool`
- [ ] `GetFilteredCalls() []components.Call`
- [ ] `GetFilteredCallCount() int`

### 4.3 Update AddOrUpdateCall
- [ ] Apply filter on new/updated calls
- [ ] Update filtered calls list

---

## Phase 5: Call Filter Parsing

### 5.1 Add Call Filter Parser (`internal/pkg/tui/filter_helpers.go`)
- [ ] Add `parseCallFilter(filterStr string) filters.Filter`
- [ ] Handle `state:active` → CallStateFilter
- [ ] Handle `duration:>30s` → NumericComparisonFilter
- [ ] Handle `mos:>3.5`, `jitter:<50`, `loss:>5` → NumericComparisonFilter
- [ ] Handle `from:`, `to:`, `user:`, `callid:`, `codec:` → TextFilter
- [ ] Handle `node:` → NodeFilter
- [ ] Default: TextFilter on all fields

---

## Phase 6: UI Integration

### 6.1 Add Filter State to Model (`internal/pkg/tui/model.go`)
- [ ] Add `callFilterMode bool`
- [ ] Add `callFilterInput *components.FilterInput` (separate instance)

### 6.2 Keyboard Handler (`internal/pkg/tui/keyboard_handler.go`)
- [ ] Add `/` handler for VoIP subtab (calls view)
- [ ] Route to `handleEnterCallFilterMode()`
- [ ] Add `c`/`C` handlers for call filter clear

### 6.3 Call Filter Operations (`internal/pkg/tui/filter_operations.go`)
- [ ] Add `handleCallFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd)`
- [ ] Add `handleEnterCallFilterMode() (Model, tea.Cmd)`
- [ ] Add `handleRemoveLastCallFilter() (Model, tea.Cmd)`
- [ ] Add `handleClearAllCallFilters() (Model, tea.Cmd)`
- [ ] Add `parseAndApplyCallFilter(filterStr string) tea.Cmd`

### 6.4 CallsView Updates (`internal/pkg/tui/components/callsview.go`)
- [ ] Display filtered calls when filter active
- [ ] Show filter count in view (or rely on footer)

### 6.5 Footer Updates (`internal/pkg/tui/components/footer.go`)
- [ ] Show filter keybinds when on VoIP calls view: `[/] Filter  [c] Clear last  [C] Clear all`
- [ ] Show active filter count

### 6.6 View Renderer (`internal/pkg/tui/view_renderer.go`)
- [ ] Render call filter input when `callFilterMode` is true

---

## Phase 7: PacketStore Migration

### 7.1 Update PacketStore (`internal/pkg/tui/store/packet_store.go`)
- [ ] Update `Match()` calls to pass packet as `Filterable`
- [ ] Verify no breakage

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
