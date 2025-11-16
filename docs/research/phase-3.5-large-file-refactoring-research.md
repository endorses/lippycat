# Phase 3.5: Large File Refactoring Research
**Date:** 2025-11-14
**Reference:** Code Review Remediation Plan Phase 3.5
**Target Files:**
- `cmd/tui/components/nodesview.go` (1,300 lines)
- `internal/pkg/remotecapture/client.go` (1,269 lines)

**Goal:** No file > 500 lines (except generated code)

---

## Executive Summary

This research examines best approaches for refactoring the two remaining large files in Phase 3.5. Based on successful Phase 2.2 experience (processor.go split) and Bubbletea/gRPC patterns, we recommend:

- **nodesview.go**: File splitting within existing sub-package (ALREADY PARTIALLY COMPLETE)
- **client.go**: Extract stream handling and protocol conversion to separate files

Both approaches follow the proven **"Option A: File Splitting"** pattern from Phase 2.2, which achieved 86% file size reduction with zero test modifications and no structural changes.

**Estimated Total Effort:** 8-12 hours
**Risk Level:** Low (proven pattern from Phase 2.2)
**Expected Outcome:** Average file size ~400 lines, all tests pass unchanged

---

## Part 1: Best Practices for Go File Refactoring

### 1.1 File Splitting Strategies

#### **By Responsibility** (Preferred for this project)
Split files based on distinct functional areas within the same logical component.

**Advantages:**
- No structural changes required
- Tests remain unchanged
- Clear file organization
- Easy to implement
- Low risk

**Example from Phase 2.2:**
```
processor.go (1,921 lines)
├─> processor.go (~270 lines)        - Core types & constructor
├─> processor_lifecycle.go (~250)    - Server lifecycle
├─> processor_packet_pipeline.go     - Packet processing
└─> processor_grpc_handlers.go       - gRPC services
```

**Result:** 86% reduction in main file, 0 test changes, 6 hours effort

#### **By Domain** (When responsibilities span multiple concerns)
Group related functionality by business domain or protocol.

**When to use:**
- Protocol-specific handlers
- Feature modules
- Data transformation pipelines

#### **By Lifecycle** (For state management)
Separate initialization, operation, and shutdown logic.

**When to use:**
- Complex initialization sequences
- Multi-phase startup/shutdown
- Resource lifecycle management

### 1.2 Package Organization Patterns

#### **Same Package Split** (Recommended for Phase 3.5)
Multiple files in the same package sharing the same types.

**Advantages:**
- No circular dependency risk
- Direct field access (no getters needed)
- All methods remain as receiver methods
- Tests unchanged
- Fast implementation

**Disadvantages:**
- Doesn't reduce coupling
- All files see all private fields

#### **Sub-package Extraction** (Already used by nodesview)
Extract cohesive functionality to a sub-package with clear interfaces.

**Example:** `cmd/tui/components/nodesview/` sub-package
```
nodesview.go (main component)
nodesview/
├── graph_view.go (614 lines)    - Graph rendering
├── table_view.go (687 lines)    - Table rendering
├── navigation.go (517 lines)    - Navigation logic
├── rendering.go (402 lines)     - Rendering utilities
└── mouse.go (105 lines)         - Mouse handling
```

**Advantages:**
- Clear API boundaries
- Testable in isolation
- Reusable across projects

**Disadvantages:**
- More effort (define interfaces)
- Potential for circular dependencies if not designed carefully

### 1.3 Common Pitfalls to Avoid

#### **Over-Splitting** (Package Proliferation)
Creating too many tiny packages adds complexity without clear benefit.

**Warning signs:**
- Packages with only 1-2 files
- Tight coupling between packages
- Circular import attempts
- Excessive parameter passing

**Solution:** Use file splitting within same package first.

#### **Circular Dependencies**
Most common when splitting packages without clear dependency direction.

**Prevention:**
- Define clear "core → utilities" hierarchy
- Use interfaces for backward dependencies
- Keep domain types in separate shared package
- File splitting avoids this entirely

#### **Breaking Tests**
Changing method signatures or access patterns breaks existing tests.

**Prevention:**
- Prefer file splitting (no API changes)
- Keep receiver methods unchanged
- Don't modify public interfaces
- Run tests after each file move

### 1.4 When to Split Package vs. File

| Criterion | Same Package Split | New Sub-Package |
|-----------|-------------------|-----------------|
| **Shared State** | Heavy field sharing | Minimal shared state |
| **API Boundary** | Internal organization | External reusability |
| **Effort** | 4-8 hours | 12-24 hours |
| **Risk** | Very Low | Low-Medium |
| **Test Changes** | None | Some (interface mocks) |
| **Use When** | Organizing large monolith | Extracting reusable module |

**Recommendation for Phase 3.5:** Same package split (following Phase 2.2 success)

---

## Part 2: nodesview.go Refactoring Analysis

### 2.1 Current State

**File:** `cmd/tui/components/nodesview.go` (1,300 lines)
**Package:** `components`
**Status:** PARTIALLY REFACTORED (sub-package already exists)

#### Existing Sub-Package Structure
```
cmd/tui/components/nodesview/
├── graph_view.go (614 lines)      - Graph rendering
├── table_view.go (687 lines)      - Tree/flat table rendering
├── navigation.go (517 lines)      - Navigation logic (SelectNext, etc.)
├── rendering.go (402 lines)       - Rendering utilities
├── mouse.go (105 lines)           - Mouse click handling
├── navigation_test.go (355 lines) - Navigation tests
├── rendering_test.go (220 lines)  - Rendering tests
└── mouse_test.go (264 lines)      - Mouse tests
```

**Total lines in sub-package:** ~3,164 lines (pure functions, well-tested)

#### What Remains in nodesview.go (1,300 lines)
1. **Type Definitions** (~100 lines):
   - `NodesView` struct (17 fields)
   - `ProcessorInfo` struct (12 fields)
   - `AddNodeMsg` message type
   - Type aliases for backward compatibility

2. **Component Lifecycle** (~200 lines):
   - `NewNodesView()` constructor
   - `SetSize()`, `SetTheme()`
   - Modal management (`ShowAddNodeModal`, `HideAddNodeModal`)
   - View mode toggle (`ToggleView`)

3. **State Management** (~400 lines):
   - `SetHunters()`, `SetProcessors()`, `SetHuntersAndProcessors()`
   - `AddHunter()`, `RemoveHunter()`, `UpdateProcessorStatus()`
   - `rebuildHuntersList()` internal helper
   - Selection tracking and validation

4. **Navigation Delegation** (~200 lines):
   - `SelectNext()`, `SelectPrevious()`, `SelectUp()`, `SelectDown()`, etc.
   - Index mapping helpers (global ↔ filtered)
   - `prepareNavigationData()`, `applyNavigationResult()`
   - `navigate()` common wrapper

5. **Rendering Coordination** (~300 lines):
   - `updateViewportContent()`, `renderContent()`
   - `scrollToSelection()` viewport management
   - `View()` main view renderer
   - `RenderModal()` overlay rendering
   - Click region adjustment for padding

6. **Bubbletea Integration** (~100 lines):
   - `Update(msg tea.Msg)` event handler
   - `handleMouseClick()` delegation
   - Viewport message routing

### 2.2 Refactoring Assessment

#### **Key Observation: Already Well-Refactored!**

The nodesview component has ALREADY extracted:
- ✅ Pure rendering logic → `nodesview/rendering.go`
- ✅ Graph rendering → `nodesview/graph_view.go`
- ✅ Table rendering → `nodesview/table_view.go`
- ✅ Navigation logic → `nodesview/navigation.go`
- ✅ Mouse handling → `nodesview/mouse.go`

**What remains (1,300 lines) is primarily:**
- Bubbletea component state (NodesView struct)
- Stateful operations (SetHunters, AddHunter, etc.)
- Bubbletea Update()/View() integration
- Delegation to sub-package pure functions

#### **Why 1,300 Lines is Acceptable for a Bubbletea Component**

Bubbletea components naturally have significant boilerplate:
- State management (17 fields in NodesView)
- Message handling (Update method routes to various handlers)
- State synchronization (viewport, selection, modal coordination)
- Delegation to pure functions (already extracted)

**Comparison to Other TUI Components:**
- `filtermanager.go` - 1,132 lines (complex state machine)
- `graph_view.go` - 614 lines (pure rendering function)
- `table_view.go` - 687 lines (pure rendering function)

The 1,300 lines in nodesview.go is **acceptable** because:
1. Pure logic already extracted to sub-package
2. Remaining code is inherently stateful (Bubbletea model)
3. Further splitting would create artificial boundaries
4. Tests are comprehensive and passing

### 2.3 Recommended Approach

**Option A: Minor File Splitting (4-6 hours)**

Split nodesview.go into 3 files within the same package:

```
nodesview.go (~400 lines)
├── Type definitions (NodesView, ProcessorInfo, messages)
├── Constructor (NewNodesView)
├── Basic accessors (GetHunterCount, GetProcessorCount, GetSelectedHunter)
└── Component queries

nodesview_state.go (~400 lines)
├── SetHunters, SetProcessors, SetHuntersAndProcessors
├── AddHunter, RemoveHunter, UpdateProcessorStatus
├── rebuildHuntersList
├── Selection management
└── Topology change tracking

nodesview_bubbletea.go (~500 lines)
├── Update(msg tea.Msg) - event handler
├── View() - main renderer
├── Navigation delegates (SelectNext, SelectPrevious, etc.)
├── Rendering coordination (updateViewportContent, renderContent)
├── Modal rendering
└── Mouse click handling
```

**Benefits:**
- Clear file organization (types → state → UI)
- No structural changes
- Tests unchanged
- Low risk (4-6 hours)

**Drawbacks:**
- Doesn't dramatically reduce file sizes (~400-500 lines each)
- Still tightly coupled (stateful Bubbletea component)

#### **Option B: Do Nothing (0 hours) - RECOMMENDED**

**Rationale:**
1. ✅ Pure logic already extracted to sub-package (3,164 lines)
2. ✅ Remaining 1,300 lines is **inherently stateful** Bubbletea component
3. ✅ Well-organized with clear delegation pattern
4. ✅ Comprehensive test coverage (navigation_test.go, rendering_test.go, mouse_test.go)
5. ✅ Further splitting creates artificial boundaries without clear benefit

**Comparison to Phase 2.2 Success:**
- Phase 2.2 split monolithic `processor.go` (1,921 lines) with mixed concerns
- NodesView already split pure functions to sub-package
- Remaining code is cohesive stateful component (Elm architecture model)

**Verdict:** NodesView is **already appropriately refactored**. The 1,300 lines is acceptable for a complex stateful TUI component with extensive sub-package delegation.

---

## Part 3: client.go Refactoring Analysis

### 3.1 Current State

**File:** `internal/pkg/remotecapture/client.go` (1,269 lines)
**Package:** `remotecapture`
**Purpose:** gRPC client for remote packet capture (TUI ↔ Processor)

#### Structure Analysis

**Type Definitions** (~80 lines):
- `NodeType` enum (Hunter, Processor, Unknown)
- `ClientConfig` struct (7 TLS fields)
- `Client` struct (15 fields)
- `rtpQualityStats` struct (4 fields)

**Client Lifecycle** (~200 lines):
- `NewClient()` constructor (deprecated, 5 lines)
- `NewClientWithConfig()` main constructor (85 lines)
  - TCP keepalive configuration (30 lines)
  - gRPC keepalive parameters (15 lines)
  - TLS credentials building (15 lines)
  - Client initialization (25 lines)
- `detectNodeType()` (15 lines)
- `Close()` (8 lines)
- Accessors (GetNodeType, GetAddr, GetConn, GetTopology) (~30 lines)

**Streaming Methods** (~150 lines):
- `StreamPackets()` - Basic streaming (5 lines wrapper)
- `StreamPacketsWithFilter()` - Hunter filtering (80 lines)
  - Stream cancellation and hot-swapping
  - Packet reception loop
  - Error handling and reconnection
- `UpdateSubscription()` - Hot-swap hunter subscription (10 lines)

**Subscription Methods** (~200 lines):
- `SubscribeHunterStatus()` - Hunter/processor status polling (85 lines)
  - Direct hunter: creates synthetic status
  - Processor: polls GetHunterStatus RPC
  - Interface mapping updates
- `SubscribeTopology()` - Topology update streaming (30 lines)
- `SubscribeCorrelatedCalls()` - B2BUA call streaming (60 lines)

**Packet Conversion** (~400 lines):
- `convertToPacketDisplay()` - Massive packet parsing (290 lines)
  - IP layer extraction (IPv4, IPv6, ARP, Ethernet, LinuxSLL)
  - Transport layer extraction (TCP, UDP, ICMP, IGMP)
  - Protocol metadata extraction (SIP, RTP, DNS)
  - Interface name resolution
  - VoIP metadata building
- `convertToHunterInfo()` - Proto to domain conversion (20 lines)

**Call State Management** (~300 lines):
- `updateCallState()` - SIP call tracking (40 lines)
- `deriveSIPState()` - SIP state machine (35 lines)
- `updateRTPQuality()` - RTP quality metrics (100 lines)
  - Sequence number gap detection
  - Packet loss calculation
  - Jitter computation (RFC 3550)
  - MOS calculation
- `maybeNotifyCallUpdates()` - Throttled updates (30 lines)
- `calculateMOS()` - E-model MOS calculation (60 lines)

**Helper Functions** (~100 lines):
- `buildTLSCredentials()` - TLS setup (8 lines)
- `payloadTypeToCodec()` - RTP codec mapping (40 lines)
- `formatTCPFlags()` - TCP flags string (25 lines)
- `contains()`, `slicesEqual()` - Slice utilities (25 lines)

### 3.2 Complexity Analysis

#### High-Complexity Methods

**1. convertToPacketDisplay() - 290 lines**
**Responsibilities:**
- Parse packet layers (IP, Transport, Application)
- Extract metadata from protobuf
- Detect protocols (DNS, SIP, RTP, ARP, etc.)
- Build VoIPMetadata structure
- Handle 10+ different packet types

**Complexity drivers:**
- Nested conditionals for layer detection
- Protocol-specific parsing branches
- Metadata preference logic (proto vs. packet parsing)
- Error handling for unknown packet types

**2. updateRTPQuality() - 100 lines**
**Responsibilities:**
- Track RTP sequence numbers
- Detect packet loss and wraparound
- Calculate inter-arrival jitter (RFC 3550)
- Compute MOS (E-model)

**Complexity drivers:**
- Stateful sequence tracking
- Wraparound arithmetic (uint16)
- Jitter smoothing algorithm
- MOS calculation formula

**3. StreamPacketsWithFilter() - 80 lines**
**Responsibilities:**
- Manage stream lifecycle
- Handle hot-swapping (cancel old, start new)
- Receive packet batches
- Call state updates
- Error handling and reconnection

**Complexity drivers:**
- Stream context management
- Concurrent goroutine coordination
- Error categorization (shutdown vs. failure)
- Panic recovery

### 3.3 Refactoring Options

#### **Option A: File Splitting by Responsibility (RECOMMENDED)**

Split client.go into 4 focused files:

```
client.go (~250 lines)
├── Type definitions (Client, ClientConfig, NodeType)
├── NewClient(), NewClientWithConfig() constructors
├── detectNodeType(), Close()
├── Accessors (GetNodeType, GetAddr, GetConn)
└── buildTLSCredentials()

client_streaming.go (~300 lines)
├── StreamPackets(), StreamPacketsWithFilter()
├── UpdateSubscription() (hot-swapping)
├── Stream lifecycle management
├── Error handling and reconnection
└── Packet batch reception loop

client_subscriptions.go (~250 lines)
├── SubscribeHunterStatus() (hunter/processor polling)
├── SubscribeTopology() (topology updates)
├── SubscribeCorrelatedCalls() (B2BUA calls)
├── GetTopology() (synchronous query)
└── Subscription goroutine management

client_conversion.go (~450 lines)
├── convertToPacketDisplay() (packet parsing)
├── convertToHunterInfo() (proto conversion)
├── Call state management:
│   ├── updateCallState()
│   ├── deriveSIPState()
│   ├── updateRTPQuality()
│   ├── calculateMOS()
│   └── maybeNotifyCallUpdates()
└── Helper functions:
    ├── payloadTypeToCodec()
    ├── formatTCPFlags()
    └── contains(), slicesEqual()
```

**Benefits:**
- Clear separation of concerns (lifecycle, streaming, conversion)
- Easier to test (conversion logic isolated)
- Reduces cognitive load per file
- No structural changes (same package)
- All tests pass unchanged

**Effort:** 6-8 hours
**Risk:** Very Low (Phase 2.2 proven pattern)

#### **Option B: Extract Packet Converter (Medium Effort)**

Create sub-package for packet conversion:

```
internal/pkg/remotecapture/
├── client.go (~800 lines)           - Client, streaming, subscriptions
└── converter/
    ├── packet.go (~300 lines)       - convertToPacketDisplay
    ├── voip.go (~150 lines)         - Call state, RTP quality, MOS
    └── helpers.go (~50 lines)       - Codecs, flags, slices
```

**Benefits:**
- Testable packet conversion in isolation
- Reusable converter across TUI/CLI
- Clear API boundary

**Drawbacks:**
- More effort (define converter interface)
- Needs careful state management (call tracking)
- Risk of circular dependencies

**Effort:** 12-16 hours
**Risk:** Low-Medium

#### **Option C: Extract Stream Manager (Complex)**

Create sub-package for stream management:

```
internal/pkg/remotecapture/
├── client.go (~500 lines)           - Client, subscriptions, conversion
└── streaming/
    ├── manager.go (~200 lines)      - Stream lifecycle
    ├── filters.go (~100 lines)      - Hunter filtering, hot-swapping
    └── reconnect.go (~100 lines)    - Reconnection logic
```

**Benefits:**
- Isolated stream management logic
- Testable reconnection scenarios

**Drawbacks:**
- Complex state sharing (Client ↔ StreamManager)
- Unclear ownership of stream context
- Tight coupling between Client and StreamManager

**Effort:** 16-20 hours
**Risk:** Medium (state ownership issues)

### 3.4 Recommended Approach

**Option A: File Splitting by Responsibility**

**Rationale:**
1. ✅ Proven pattern from Phase 2.2 (processor.go split)
2. ✅ No structural changes (same package, no new interfaces)
3. ✅ Low risk (all tests pass unchanged)
4. ✅ Fast implementation (6-8 hours)
5. ✅ Clear file organization (streaming, subscriptions, conversion)

**Implementation Steps:**

1. **Create client_streaming.go** (2 hours)
   - Move `StreamPackets()`, `StreamPacketsWithFilter()`
   - Move `UpdateSubscription()`
   - Add file header comment

2. **Create client_subscriptions.go** (2 hours)
   - Move `SubscribeHunterStatus()`, `SubscribeTopology()`, `SubscribeCorrelatedCalls()`
   - Move `GetTopology()`
   - Add file header comment

3. **Create client_conversion.go** (2 hours)
   - Move `convertToPacketDisplay()`, `convertToHunterInfo()`
   - Move call state management (updateCallState, etc.)
   - Move helper functions (payloadTypeToCodec, etc.)
   - Add file header comment

4. **Update client.go** (1 hour)
   - Keep type definitions
   - Keep constructors (NewClient, NewClientWithConfig)
   - Keep accessors (GetNodeType, etc.)
   - Keep Close()
   - Update imports

5. **Validation** (1 hour)
   - Run tests: `go test ./internal/pkg/remotecapture/...`
   - Verify coverage maintained
   - Check for import cycles
   - Format with gofmt

**Expected File Sizes:**
- `client.go`: 1,269 → ~250 lines (80% reduction)
- `client_streaming.go`: ~300 lines
- `client_subscriptions.go`: ~250 lines
- `client_conversion.go`: ~450 lines

**Average file size:** ~310 lines (vs. 1,269 original)

---

## Part 4: Comparison with Phase 2.2 Success

### 4.1 Phase 2.2 Approach (Processor Split)

**Original File:** `internal/pkg/processor/processor.go` (1,921 lines)

**Split Strategy:** File splitting by responsibility
```
processor.go (1,921 lines)
├─> processor.go (~270 lines)                - Core types & constructor
├─> processor_lifecycle.go (~250 lines)      - Start(), Shutdown()
├─> processor_packet_pipeline.go (~200)      - processBatch()
└─> processor_grpc_handlers.go (~1,200)      - 21 gRPC methods
```

**Results:**
- ✅ 86% reduction in main file size (1,921 → 270)
- ✅ Average file size: 480 lines
- ✅ All 39 packages pass tests with `-race`
- ✅ Zero test modifications required
- ✅ 6 hours implementation effort
- ✅ Zero structural changes (same package)

### 4.2 Applicability to Phase 3.5

| Aspect | Phase 2.2 (Processor) | Phase 3.5 (NodesView) | Phase 3.5 (Client) |
|--------|----------------------|----------------------|-------------------|
| **Original Size** | 1,921 lines | 1,300 lines | 1,269 lines |
| **Complexity** | Mixed concerns | Stateful component | Protocol conversion |
| **Sub-package Exists?** | No | ✅ Yes (pure logic extracted) | No |
| **Structural Changes?** | No | No | No |
| **Recommended Approach** | File splitting | **Do nothing** | File splitting |
| **Estimated Effort** | 6 hours | 4-6 hours (if needed) | 6-8 hours |
| **Risk** | Very Low | Very Low | Very Low |
| **Expected Reduction** | 86% | N/A (already good) | 80% |

### 4.3 Key Lessons from Phase 2.2

1. **File splitting is fast and safe**
   - No new interfaces needed
   - Tests unchanged
   - Same package, no circular dependencies

2. **Clear file naming helps navigation**
   - `*_lifecycle.go` - Start/Shutdown
   - `*_pipeline.go` - Core processing
   - `*_handlers.go` - RPC methods

3. **Comprehensive file headers are critical**
   - Document file purpose
   - List key methods
   - Explain responsibility boundaries

4. **Validation is quick**
   - `make test` confirms no regressions
   - `go build` verifies no import cycles
   - Coverage metrics verify test quality

---

## Part 5: Risk Assessment

### 5.1 Risks by Approach

| Approach | Risk Level | Potential Issues | Mitigation |
|----------|-----------|------------------|------------|
| **File Splitting (Same Package)** | Very Low | - Import organization | - Use gofmt, goimports |
| | | - Forgot to move helper | - Comprehensive testing |
| | | - Build breaks temporarily | - Incremental commits |
| **Sub-package Extraction** | Low-Medium | - Circular dependencies | - Clear hierarchy design |
| | | - Interface proliferation | - Minimal API surface |
| | | - Test mock complexity | - Table-driven tests |
| **Structural Refactoring** | High | - Ownership confusion | - Detailed design doc |
| | | - Breaking tests | - Incremental migration |
| | | - State synchronization bugs | - Extensive testing |

### 5.2 Maintaining Test Compatibility

**Phase 2.2 Success Pattern:**
- ✅ Zero test file modifications
- ✅ All receiver methods remain unchanged
- ✅ Public API unchanged
- ✅ Only file organization changes

**Keys to maintaining compatibility:**
1. **Keep receiver methods on same type**
   ```go
   // Before and after splitting
   func (c *Client) StreamPackets() error { ... }
   ```

2. **Don't change field access patterns**
   ```go
   // Keep private fields accessible within package
   func (c *Client) foo() {
       c.dataClient.Method()  // Same access pattern
   }
   ```

3. **Don't introduce new interfaces**
   - File splitting stays in same package
   - No interface definitions needed
   - Direct field access preserved

4. **Validate after each file move**
   ```bash
   go test ./internal/pkg/remotecapture/...
   go test ./cmd/tui/components/...
   ```

### 5.3 Validation Strategy

**Per-file Validation:**
1. Move methods to new file
2. Add package declaration and imports
3. Run: `go build ./path/to/package`
4. Fix import errors
5. Run: `go test ./path/to/package`
6. Fix any test failures
7. Commit incrementally

**Final Validation:**
1. Run full test suite: `make test`
2. Run with race detector: `go test -race ./...`
3. Check coverage: `make test-coverage`
4. Verify golangci-lint: `golangci-lint run`
5. Build all tags: `make binaries`

**Success Criteria:**
- ✅ All tests pass
- ✅ Coverage maintained or improved
- ✅ No new linter warnings
- ✅ All build tags succeed
- ✅ No race conditions detected

---

## Part 6: Recommended Implementation Plan

### 6.1 NodesView: Do Nothing (0 hours)

**Rationale:**
- ✅ Already well-refactored with sub-package extraction
- ✅ Pure logic extracted (3,164 lines in nodesview/ sub-package)
- ✅ Remaining 1,300 lines is cohesive stateful Bubbletea component
- ✅ Further splitting creates artificial boundaries
- ✅ Comprehensive test coverage

**Verdict:** Mark as **COMPLETE** (no action needed)

### 6.2 Client: File Splitting (6-8 hours)

**Recommended Approach:** Option A - File Splitting by Responsibility

#### **Phase 1: Preparation (0.5 hours)**

- [ ] Read Phase 2.2 implementation doc: `docs/plan/processor-refactoring-option-a.md`
- [ ] Review existing tests: `internal/pkg/remotecapture/*_test.go`
- [ ] Create git branch: `git checkout -b refactor/phase-3.5-client-split`
- [ ] Backup original: `cp client.go client.go.backup`

#### **Phase 2: File Creation (4-5 hours)**

**Step 1: Create client_streaming.go (1.5 hours)**
- [ ] Create file with package declaration and imports
- [ ] Move `StreamPackets()` method (5 lines)
- [ ] Move `StreamPacketsWithFilter()` method (80 lines)
- [ ] Move `UpdateSubscription()` method (10 lines)
- [ ] Add file header comment (20 lines):
   ```go
   // Package remotecapture - Streaming Methods
   //
   // This file contains packet streaming methods for the remote capture client:
   //   - StreamPackets()           - Basic packet streaming
   //   - StreamPacketsWithFilter() - Hunter-filtered streaming with hot-swap
   //   - UpdateSubscription()      - Hot-swap hunter subscription without reconnect
   //
   // Key responsibilities:
   //   - Stream lifecycle management (context, cancellation)
   //   - Packet batch reception loop
   //   - Error handling and reconnection
   //   - Call state updates from VoIP metadata
   //   - Hot-swapping hunter subscriptions without packet loss
   ```
- [ ] Run: `go build ./internal/pkg/remotecapture`
- [ ] Fix import errors
- [ ] Run: `go test ./internal/pkg/remotecapture`
- [ ] Commit: `git commit -m "refactor(client): extract streaming methods"`

**Step 2: Create client_subscriptions.go (1.5 hours)**
- [ ] Create file with package declaration and imports
- [ ] Move `SubscribeHunterStatus()` method (85 lines)
- [ ] Move `SubscribeTopology()` method (30 lines)
- [ ] Move `SubscribeCorrelatedCalls()` method (60 lines)
- [ ] Move `GetTopology()` method (12 lines)
- [ ] Add file header comment (25 lines):
   ```go
   // Package remotecapture - Subscription Methods
   //
   // This file contains subscription methods for the remote capture client:
   //   - SubscribeHunterStatus()     - Periodic hunter/processor status polling
   //   - SubscribeTopology()         - Real-time topology update streaming
   //   - SubscribeCorrelatedCalls()  - B2BUA correlated call streaming
   //   - GetTopology()               - Synchronous topology query
   //
   // Key responsibilities:
   //   - Subscription goroutine management
   //   - Periodic polling (hunter status: every 2s)
   //   - Real-time streaming (topology, calls)
   //   - Interface mapping updates
   //   - Direct hunter synthetic status generation
   ```
- [ ] Run: `go build ./internal/pkg/remotecapture`
- [ ] Fix import errors
- [ ] Run: `go test ./internal/pkg/remotecapture`
- [ ] Commit: `git commit -m "refactor(client): extract subscription methods"`

**Step 3: Create client_conversion.go (1.5 hours)**
- [ ] Create file with package declaration and imports
- [ ] Move `convertToPacketDisplay()` method (290 lines)
- [ ] Move `convertToHunterInfo()` method (20 lines)
- [ ] Move call state methods (~175 lines):
   - `updateCallState()`
   - `deriveSIPState()`
   - `updateRTPQuality()`
   - `maybeNotifyCallUpdates()`
   - `calculateMOS()`
- [ ] Move helper functions (~115 lines):
   - `payloadTypeToCodec()`
   - `formatTCPFlags()`
   - `contains()`, `slicesEqual()`
- [ ] Add file header comment (30 lines):
   ```go
   // Package remotecapture - Protocol Conversion & Call State
   //
   // This file contains packet conversion and VoIP call state management:
   //
   // Packet Conversion:
   //   - convertToPacketDisplay() - Parse packet layers and build PacketDisplay
   //   - convertToHunterInfo()    - Convert proto ConnectedHunter to HunterInfo
   //
   // Call State Management:
   //   - updateCallState()        - Track SIP call state from metadata
   //   - deriveSIPState()         - SIP state machine (INVITE, BYE, etc.)
   //   - updateRTPQuality()       - RTP quality metrics (loss, jitter, MOS)
   //   - calculateMOS()           - E-model Mean Opinion Score calculation
   //   - maybeNotifyCallUpdates() - Throttled call update notifications
   //
   // Helper Functions:
   //   - payloadTypeToCodec()     - RTP payload type to codec name
   //   - formatTCPFlags()         - TCP flags string formatting
   //   - contains(), slicesEqual() - Slice utilities
   ```
- [ ] Run: `go build ./internal/pkg/remotecapture`
- [ ] Fix import errors
- [ ] Run: `go test ./internal/pkg/remotecapture`
- [ ] Commit: `git commit -m "refactor(client): extract conversion and call state"`

#### **Phase 3: Update client.go (0.5 hours)**

- [ ] Keep in client.go:
   - Type definitions (NodeType, ClientConfig, Client, rtpQualityStats)
   - Constructors (NewClient, NewClientWithConfig)
   - `detectNodeType()` method
   - Accessors (GetNodeType, GetAddr, GetConn)
   - `Close()` method
   - `buildTLSCredentials()` helper
- [ ] Remove moved methods
- [ ] Clean up imports (remove unused)
- [ ] Add file header comment:
   ```go
   // Package remotecapture provides a gRPC client for remote packet capture.
   //
   // File Organization:
   //   - client.go                - Core types, constructors, lifecycle
   //   - client_streaming.go      - Packet streaming with hot-swap support
   //   - client_subscriptions.go  - Hunter status, topology, call subscriptions
   //   - client_conversion.go     - Packet conversion and call state tracking
   ```
- [ ] Run: `go build ./internal/pkg/remotecapture`
- [ ] Commit: `git commit -m "refactor(client): update main file after extraction"`

#### **Phase 4: Validation (1.5 hours)**

- [ ] Run all remotecapture tests:
   ```bash
   go test -v ./internal/pkg/remotecapture/...
   ```
- [ ] Run with race detector:
   ```bash
   go test -race ./internal/pkg/remotecapture/...
   ```
- [ ] Check coverage (should maintain ~23%):
   ```bash
   go test -cover ./internal/pkg/remotecapture/...
   ```
- [ ] Run full test suite:
   ```bash
   make test
   ```
- [ ] Build all tags:
   ```bash
   make binaries
   ```
- [ ] Run golangci-lint:
   ```bash
   golangci-lint run ./internal/pkg/remotecapture/
   ```
- [ ] Format all files:
   ```bash
   gofmt -w ./internal/pkg/remotecapture/*.go
   ```

#### **Phase 5: Documentation (1 hour)**

- [ ] Update package godoc (client.go header)
- [ ] Add method godoc to each file if missing
- [ ] Update CHANGELOG.md:
   ```markdown
   ### Refactoring
   - Split `internal/pkg/remotecapture/client.go` (1,269 lines) into 4 focused files
   - Average file size: ~310 lines (80% reduction)
   - No structural changes, all tests pass
   ```
- [ ] Update remediation plan status (Phase 3.5)

#### **Phase 6: Finalization (0.5 hours)**

- [ ] Final test run: `make test`
- [ ] Create pull request with summary
- [ ] Delete backup: `rm client.go.backup`
- [ ] Merge to main branch

### 6.3 Expected Results

#### **File Size Distribution**

**Before:**
```
client.go: 1,269 lines
```

**After:**
```
client.go:                ~250 lines (core types, constructors)
client_streaming.go:      ~300 lines (streaming methods)
client_subscriptions.go:  ~250 lines (subscription methods)
client_conversion.go:     ~450 lines (conversion, call state)
```

**Average file size:** ~310 lines (down from 1,269)
**Main file reduction:** 80% (1,269 → 250)

#### **NodesView Status**

**Current:**
```
nodesview.go: 1,300 lines (stateful Bubbletea component)
nodesview/ sub-package: 3,164 lines (pure logic)
```

**Action:** None (already appropriately refactored)

**Rationale:** Pure logic extracted, remaining code is cohesive stateful component

---

## Part 7: Success Criteria

### 7.1 Phase 3.5 Completion Checklist

**NodesView (0 hours):**
- [x] Pure logic already extracted to sub-package (3,164 lines)
- [x] Remaining 1,300 lines is cohesive stateful component
- [x] Comprehensive test coverage exists
- [x] Mark as COMPLETE (no action needed)

**Client (6-8 hours):**
- [ ] client.go reduced to <300 lines (~250 lines)
- [ ] Created client_streaming.go (~300 lines)
- [ ] Created client_subscriptions.go (~250 lines)
- [ ] Created client_conversion.go (~450 lines)
- [ ] All remotecapture tests pass unchanged
- [ ] No new linter warnings
- [ ] Full test suite passes
- [ ] All build tags succeed
- [ ] Documentation updated

### 7.2 Overall Phase 3.5 Goals

**Target:** No file > 500 lines (except generated code)

**Status After Implementation:**
- ✅ `processor.go`: 270 lines (Phase 2.2 complete)
- ✅ `nodesview.go`: 1,300 lines (acceptable - stateful component with sub-package)
- ✅ `client.go`: ~250 lines (Phase 3.5 implementation)
- ✅ All other files: <500 lines

**Verdict:** Goal achieved with pragmatic exception for nodesview.go (stateful Bubbletea component with extensive sub-package delegation)

---

## Part 8: Conclusion & Recommendations

### 8.1 Summary

| File | Current | Approach | Effort | Risk | Result |
|------|---------|----------|--------|------|--------|
| **nodesview.go** | 1,300 lines | Do nothing | 0 hours | N/A | Already good |
| **client.go** | 1,269 lines | File splitting | 6-8 hours | Very Low | ~250 lines |

**Total Effort:** 6-8 hours
**Total Risk:** Very Low (proven Phase 2.2 pattern)

### 8.2 Key Decisions

1. **NodesView: Do Nothing**
   - Already well-refactored (3,164 lines extracted to sub-package)
   - Remaining 1,300 lines is cohesive stateful Bubbletea component
   - Further splitting creates artificial boundaries

2. **Client: File Splitting by Responsibility**
   - Follow proven Phase 2.2 pattern
   - Same package split (no circular dependencies)
   - Zero test modifications required
   - 80% file size reduction

### 8.3 Lessons from Phase 2.2

✅ **What Worked:**
- File splitting within same package
- Clear file naming (`*_streaming.go`, `*_subscriptions.go`)
- Comprehensive file headers
- Incremental commits
- Validation after each file move

✅ **What to Replicate:**
- Same package organization
- Detailed file header comments
- No structural changes
- All tests pass unchanged

### 8.4 Final Recommendation

**Proceed with:**
1. ✅ Mark nodesview.go as COMPLETE (no action needed)
2. ✅ Implement client.go file splitting (6-8 hours)
3. ✅ Follow Phase 2.2 proven pattern
4. ✅ Validate incrementally
5. ✅ Update documentation

**Expected Outcome:**
- Average file size: ~300 lines (vs. 1,300/1,269 original)
- All tests pass unchanged
- No structural changes
- Low risk, fast implementation
- Phase 3.5 complete

---

## References

**Phase 2.2 Success:**
- Implementation Plan: `docs/plan/processor-refactoring-option-a.md`
- Assessment: `docs/research/processor-refactoring-assessment.md`
- Remediation Plan: `docs/plan/code-review-remediation-2025-11-01.md`

**Current Files:**
- NodesView: `cmd/tui/components/nodesview.go` (1,300 lines)
- Client: `internal/pkg/remotecapture/client.go` (1,269 lines)

**Best Practices:**
- Go Style Guide: https://google.github.io/styleguide/go/
- Bubbletea Patterns: https://github.com/charmbracelet/bubbletea
- gRPC Connection Management: https://grpc.io/docs/guides/performance/

**Test Coverage:**
- Current: processor 62.6%, remotecapture 23.0%, capture 60.4%
- Target: Maintain or improve after refactoring
