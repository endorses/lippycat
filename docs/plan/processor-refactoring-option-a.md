# Processor Refactoring: Option A - File Splitting

**Status:** Proposed
**Effort:** 4-8 hours
**Risk:** Very Low
**Date:** 2025-11-05

## Overview

Split `internal/pkg/processor/processor.go` (1,921 lines) into 4 focused files while maintaining the current architecture. This is a low-risk organizational improvement that makes the codebase easier to navigate without introducing structural changes or circular dependencies.

## Rationale

From the comprehensive analysis in `docs/research/processor-refactoring-assessment.md`:

- **Current Size**: 1,921 lines in a single file
- **Method Count**: 25 receiver methods + 4 helper functions
- **Problem**: Monolithic file is difficult to navigate and understand
- **Why Not Option D (Three-Way Split)?**:
  - High risk of circular dependencies (Server → Core → Managers)
  - Unclear manager ownership model
  - 40-60 hours effort + 20-30 hours testing
  - `processBatch()` needs access to 9+ managers across all three proposed components

## File Structure (After Split)

### 1. `processor.go` (~270 lines)
**Purpose:** Core types, constructor, and embedded interfaces

**Contents:**
- Type definitions (Config, Processor structs)
- `New()` constructor (197 lines)
- `GetStats()` accessor (2 lines)
- `SetProxyTLSCredentials()` (4 lines)
- Embedded gRPC interfaces (UnimplementedDataServiceServer, UnimplementedManagementServiceServer)
- Package imports

### 2. `processor_lifecycle.go` (~250 lines)
**Purpose:** Server lifecycle management

**Contents:**
- `Start(ctx context.Context) error` (179 lines)
- `Shutdown() error` (58 lines)
- `createReuseAddrListener()` helper (~15 lines)

**Responsibilities:**
- TCP listener creation with SO_REUSEADDR
- gRPC server configuration (TLS, auth, keepalive)
- Service registration
- Component startup (upstream, hunter monitor, VIF)
- Graceful shutdown sequencing

### 3. `processor_packet_pipeline.go` (~200 lines)
**Purpose:** Packet processing logic

**Contents:**
- `processBatch(batch *data.PacketBatch)` (141 lines)
- Packet processing helper methods
- PCAP writing coordination
- Call aggregation/correlation logic

**Processing Order (preserved from current implementation):**
1. Update hunter stats
2. Queue to unified PCAP writer
3. Increment counters
4. Enrich packets (if detector enabled)
5. Aggregate VoIP calls
6. Correlate B2BUA calls
7. Write per-call PCAP files
8. Write auto-rotating PCAP files
9. Forward to upstream
10. Broadcast to subscribers
11. Inject to virtual interface

### 4. `processor_grpc_handlers.go` (~1,200 lines)
**Purpose:** gRPC service implementations

**Contents:**

**Data Service Methods (3 methods):**
- `StreamPackets()` - Hunter packet ingestion (44 lines)
- `SubscribePackets()` - TUI client subscription (90 lines)
- `SubscribeCorrelatedCalls()` - B2BUA call updates (42 lines)

**Management Service Methods (18 methods):**

*Hunter Management:*
- `RegisterHunter()` (37 lines)
- `Heartbeat()` (44 lines)
- `GetHunterStatus()` (32 lines)
- `ListAvailableHunters()` (25 lines)

*Filter Management:*
- `GetFilters()` (6 lines)
- `SubscribeFilters()` (54 lines)
- `UpdateFilter()` (16 lines)
- `DeleteFilter()` (16 lines)
- `UpdateFilterOnProcessor()` (104 lines)
- `DeleteFilterOnProcessor()` (102 lines)
- `GetFiltersFromProcessor()` (97 lines)

*Processor Hierarchy:*
- `RegisterProcessor()` (94 lines)
- `GetTopology()` (51 lines)
- `SubscribeTopology()` (53 lines)
- `RequestAuthToken()` (35 lines)

**Helper Functions:**
- `buildTLSCredentials()` (7 lines)
- `convertChainErrorToStatus()` (19 lines)
- `correlatedCallToProto()` (28 lines)
- Audit logging helpers (6 functions, ~87 lines total)

## Implementation Steps

### Phase 1: File Creation (2 hours)

- [ ] Create `processor_lifecycle.go` with package declaration, imports, and license header
- [ ] Move `Start()`, `Shutdown()`, and `createReuseAddrListener()` to `processor_lifecycle.go`
- [ ] Create `processor_packet_pipeline.go` with package declaration, imports, and license header
- [ ] Move `processBatch()` and related helpers to `processor_packet_pipeline.go`
- [ ] Create `processor_grpc_handlers.go` with package declaration, imports, and license header
- [ ] Move all 21 gRPC service methods to `processor_grpc_handlers.go`
- [ ] Move helper functions (TLS, audit logging, error conversion) to `processor_grpc_handlers.go`
- [ ] Update `processor.go` to keep only: Config, Processor types, New(), GetStats(), SetProxyTLSCredentials(), embedded gRPC interfaces
- [ ] Remove moved methods from `processor.go`

### Phase 2: Import Cleanup (1 hour)

- [ ] Remove unused imports from each file
- [ ] Add missing imports for moved code
- [ ] Verify import organization (standard lib → external → internal)

### Phase 3: Validation (1-2 hours)

- [ ] Build verification: `make build`
- [ ] Test verification: `make test`
- [ ] Test coverage verification: `make test-coverage`
- [ ] Lint verification: `make vet`
- [ ] Run golangci-lint: `golangci-lint run ./internal/pkg/processor/`

### Phase 4: Documentation (2-3 hours)

- [ ] Update `cmd/process/CLAUDE.md` with new file organization
- [ ] Update architecture section in `cmd/process/CLAUDE.md`
- [ ] Add file responsibility table to `cmd/process/CLAUDE.md`
- [ ] Add file header comments explaining purpose of each file
- [ ] Document key methods in each file
- [ ] Update this plan's status to "Completed"

## Expected Results

### File Size Distribution
- `processor.go`: 1,921 lines → **~270 lines** (86% reduction)
- `processor_lifecycle.go`: **~250 lines** (new)
- `processor_packet_pipeline.go`: **~200 lines** (new)
- `processor_grpc_handlers.go`: **~1,200 lines** (new)

**Average file size:** ~480 lines (down from 1,921)

### Benefits
- Easier code navigation (methods grouped by purpose)
- Clearer separation of concerns (lifecycle vs. processing vs. gRPC)
- Faster file loading in editors
- Easier code review (focused diffs)
- No structural changes (all tests pass unchanged)

### Non-Goals
- Does NOT reduce Processor field count (still 17 fields)
- Does NOT create independent components
- Does NOT reduce coupling between managers
- Does NOT change initialization logic

## Testing Strategy

### Existing Tests (No Changes Required)
All existing tests in `internal/pkg/processor/` should pass without modification:

1. `processor_core_test.go` (305 lines) - Constructor validation
2. `processor_registration_test.go` (234 lines) - Hierarchy validation
3. `streaming_test.go` (11,190 lines) - Packet streaming
4. `grpc_errors_test.go` (8,572 lines) - Error handling
5. `tls_test.go` (8,572 lines) - TLS configuration
6. `topology_subscription_test.go` (17,336 lines) - Topology updates

**Why no test changes?**
- Methods remain as Processor receiver methods
- Public API unchanged
- Internal implementation unchanged
- Only file organization changes

### Validation Checklist
- [ ] All processor tests pass
- [ ] All sub-package tests pass (hunter, filtering, etc.)
- [ ] Build succeeds with all tags (all, hunter, processor, cli, tui)
- [ ] Coverage remains at or above 31.4%
- [ ] No new golangci-lint warnings

## Rollback Plan

If issues arise during implementation:

1. **Keep original file as backup:**
   ```bash
   cp processor.go processor.go.backup
   ```

2. **Rollback procedure:**
   ```bash
   rm processor.go processor_*.go
   mv processor.go.backup processor.go
   git checkout processor.go
   ```

3. **Incremental approach:**
   - [ ] Split one file at a time
   - [ ] Verify tests after each split
   - [ ] Commit after each successful split

## Future Considerations

### Option B: Manager Container (Next Step)
After Option A is complete and stable, consider:

**Goal:** Reduce Processor fields from 17 to ~7 by grouping managers

**Approach:**
```go
type Managers struct {
    Hunter      *hunter.Manager
    Filter      *filtering.Manager
    Flow        *flow.Controller
    // ... 11 more managers
}

type Processor struct {
    config Config
    mgr    *Managers  // Single field instead of 14
    // ... 6 other fields
}
```

**Effort:** 16-24 hours
**Risk:** Low
**Benefit:** Clearer manager grouping, reduced field count

### Option D: Three-Way Split (Deferred)
The originally proposed ProcessorCore/ProcessorServer/ProcessorOrchestrator split is **deferred** due to:

**Challenges:**
- Circular dependencies (Server → Core → Managers)
- Unclear manager ownership
- `processBatch()` needs 9+ managers (spans all three components)
- Shared state (counters) across components

**Recommendation:** Only pursue if Options A and B prove insufficient.

## Success Criteria

- [ ] `processor.go` reduced to <300 lines
- [ ] All methods grouped logically in new files
- [ ] All existing tests pass without modification
- [ ] No new linter warnings
- [ ] Build succeeds with all tags
- [ ] Documentation updated
- [ ] Code review approved

## References

- **Assessment Document:** `docs/research/processor-refactoring-assessment.md`
- **Current File:** `internal/pkg/processor/processor.go` (1,921 lines)
- **Test Coverage:** 31.4% (processor package)
- **Related Architecture:** `cmd/process/CLAUDE.md`
