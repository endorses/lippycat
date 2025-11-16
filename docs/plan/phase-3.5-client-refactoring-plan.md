# Phase 3.5: client.go Refactoring Plan
**Date:** 2025-11-16
**Task:** Refactor `internal/pkg/remotecapture/client.go` (1,269 lines → 4 files)
**Effort:** 6-8 hours
**Risk:** Very Low

---

## Executive Summary

Split `client.go` into 4 focused files following the proven Phase 2.2 pattern (processor.go refactoring). This is a **same-package file split** with zero structural changes and zero test modifications required.

**Expected Results:**
- 80% reduction in main file size (1,269 → 250 lines)
- Average file size: ~310 lines per file
- All tests pass unchanged
- Improved code navigation and review

---

## Target File Structure

```
internal/pkg/remotecapture/
├── client.go               (~250 lines)  - Core types, constructor, lifecycle
├── client_streaming.go     (~300 lines)  - Packet streaming, hot-swapping
├── client_subscriptions.go (~250 lines)  - Hunter status, topology, calls
├── client_conversion.go    (~450 lines)  - Packet parsing, call state, MOS
└── client_test.go          (unchanged)
```

---

## File Responsibilities

### client.go (~250 lines)
**Purpose:** Core types, constructor, lifecycle management

**Contents:**
- Type definitions: `Client`, `Config`, `StreamState`
- Constructor: `NewClient()`
- Lifecycle: `Start()`, `Stop()`, `Shutdown()`
- Connection management: `connect()`, `disconnect()`, `handleDisconnect()`
- Core utilities: `getEventHandler()`, validation helpers

**Header Comment:**
```go
// Package remotecapture provides a client for connecting to remote processors
// and subscribing to packet streams, hunter status, and topology updates.
//
// File: client.go - Core types, constructor, and lifecycle management
```

---

### client_streaming.go (~300 lines)
**Purpose:** Packet streaming and hot-swapping

**Contents:**
- `streamPackets()` - Main streaming loop
- `hotSwapEventHandler()` - Dynamic handler swapping
- `processPacketBatch()` - Batch processing
- Stream error handling
- Flow control handling
- Reconnection coordination

**Header Comment:**
```go
// File: client_streaming.go - Packet streaming and hot-swapping
//
// Handles the main packet streaming loop, dynamic EventHandler swapping,
// batch processing, and flow control coordination with the processor.
```

---

### client_subscriptions.go (~250 lines)
**Purpose:** Hunter status, topology, and call subscriptions

**Contents:**
- `subscribeToHunterStatus()` - Hunter status stream
- `subscribeToTopology()` - Topology updates stream
- `subscribeToActiveCalls()` - Active calls stream
- Stream restart logic
- Subscription error handling
- Event handler delegation

**Header Comment:**
```go
// File: client_subscriptions.go - Hunter status, topology, and call subscriptions
//
// Manages subscriptions to hunter status updates, topology changes, and
// active call information from the remote processor.
```

---

### client_conversion.go (~450 lines)
**Purpose:** Packet parsing, call state conversion, MOS calculation

**Contents:**
- `parsePacket()` - Proto to gopacket conversion
- `convertCallState()` - Call state conversion
- `convertCallInfo()` - CallInfo conversion
- `convertHunterInfo()` - HunterInfo conversion
- `convertRTPStats()` - RTP statistics conversion
- `calculateMOS()` - MOS calculation logic
- Helper functions for metadata parsing

**Header Comment:**
```go
// File: client_conversion.go - Packet parsing and state conversion
//
// Handles conversion between protobuf messages and internal types,
// including packet parsing, call state conversion, and MOS calculation.
```

---

## Implementation Steps

### Preparation (15 minutes) ✅ COMPLETE
- [x] Read current `client.go` to understand structure
- [x] Create backup branch: `git checkout -b refactor/phase-3.5-client`
- [x] Run baseline tests: `go test -race ./internal/pkg/remotecapture/...` → ✅ PASS (1.047s)
- [x] Record current test coverage: `go test -cover ./internal/pkg/remotecapture/...` → 23.0% coverage

### Step 1: Create client_conversion.go (1.5 hours)
- [ ] Create new file with header comment and package declaration
- [ ] Move conversion functions from `client.go`
- [ ] Move MOS calculation logic
- [ ] Move helper functions for metadata parsing
- [ ] Run tests: `go test -race ./internal/pkg/remotecapture/...`
- [ ] Verify no compilation errors
- [ ] Format: `gofmt -w internal/pkg/remotecapture/client_conversion.go`
- [ ] Commit: `git add . && git commit -m "refactor(remotecapture): extract conversion logic to client_conversion.go"`

### Step 2: Create client_subscriptions.go (1.5 hours)
- [ ] Create new file with header comment and package declaration
- [ ] Move subscription methods from `client.go`
- [ ] Move stream restart logic
- [ ] Move subscription error handling
- [ ] Run tests: `go test -race ./internal/pkg/remotecapture/...`
- [ ] Verify no compilation errors
- [ ] Format: `gofmt -w internal/pkg/remotecapture/client_subscriptions.go`
- [ ] Commit: `git add . && git commit -m "refactor(remotecapture): extract subscriptions to client_subscriptions.go"`

### Step 3: Create client_streaming.go (2 hours)
- [ ] Create new file with header comment and package declaration
- [ ] Move `streamPackets()` method
- [ ] Move `hotSwapEventHandler()` method
- [ ] Move `processPacketBatch()` method
- [ ] Move stream error handling
- [ ] Move flow control logic
- [ ] Run tests: `go test -race ./internal/pkg/remotecapture/...`
- [ ] Verify no compilation errors
- [ ] Format: `gofmt -w internal/pkg/remotecapture/client_streaming.go`
- [ ] Commit: `git add . && git commit -m "refactor(remotecapture): extract streaming logic to client_streaming.go"`

### Step 4: Clean Up client.go (1 hour)
- [ ] Verify only core types, constructor, and lifecycle remain
- [ ] Update file header comment to reflect new structure
- [ ] Ensure proper organization of remaining code
- [ ] Verify all imports are still needed
- [ ] Remove unused imports
- [ ] Run tests: `go test -race ./internal/pkg/remotecapture/...`
- [ ] Format: `gofmt -w internal/pkg/remotecapture/client.go`
- [ ] Commit: `git add . && git commit -m "refactor(remotecapture): clean up client.go (core types and lifecycle only)"`

### Step 5: Validation (1 hour)
- [ ] Run full test suite: `go test -race ./...`
- [ ] Run tests 10 times to catch flakiness: `go test -race -count=10 ./internal/pkg/remotecapture/...`
- [ ] Verify test coverage unchanged: `go test -cover ./internal/pkg/remotecapture/...`
- [ ] Check file sizes meet targets (all < 500 lines)
- [ ] Review code organization and comments
- [ ] Run linter: `golangci-lint run ./internal/pkg/remotecapture/...`

### Step 6: Documentation (30 minutes)
- [ ] Update `cmd/tui/CLAUDE.md` if it references `client.go` structure
- [ ] Add note about file organization to package godoc
- [ ] Update Phase 3.5 status in `docs/plan/code-review-remediation-2025-11-01.md`
- [ ] Mark `client.go` refactoring as complete
- [ ] Mark `nodesview.go` as complete (already well-structured)
- [ ] Commit documentation updates

### Step 7: Final Commit (15 minutes)
- [ ] Create summary commit for the refactoring
- [ ] Push branch: `git push origin refactor/phase-3.5-client`
- [ ] Merge to main (if all validations pass)

---

## Success Criteria

### Code Quality
- ✅ `client.go` reduced from 1,269 lines to ~250 lines (80% reduction)
- ✅ Average file size: ~310 lines (all under 500 line target)
- ✅ Clear separation of concerns by file
- ✅ All files have descriptive header comments
- ✅ All code properly formatted with `gofmt`

### Testing
- ✅ All tests pass: `go test -race ./internal/pkg/remotecapture/...`
- ✅ No flaky tests: `go test -race -count=10 ./internal/pkg/remotecapture/...`
- ✅ Test coverage unchanged or improved
- ✅ No compilation errors or warnings
- ✅ Linter passes: `golangci-lint run ./internal/pkg/remotecapture/...`

### Zero Changes Required
- ✅ Zero test file modifications
- ✅ Zero structural changes (same package, same types)
- ✅ Zero behavioral changes (identical functionality)
- ✅ Zero import changes in other packages

### Documentation
- ✅ File header comments explain each file's purpose
- ✅ Phase 3.5 marked complete in remediation plan
- ✅ CLAUDE.md updated if needed

---

## Risk Mitigation

### Known Risks (All Very Low)
1. **Accidentally breaking encapsulation** → All code stays in same package
2. **Test failures** → Run tests after each step, revert if needed
3. **Import cycles** → N/A (single package refactoring)
4. **Lost code during move** → Incremental commits allow easy rollback

### Mitigation Strategies
- **Incremental commits** after each file creation
- **Test validation** after every change
- **Backup branch** for easy rollback
- **Following proven pattern** from Phase 2.2 (processor.go success)

---

## Phase 3.5 Final Status

After completing this plan:

### client.go Refactoring
- ✅ Split into 4 focused files
- ✅ 80% reduction in main file size
- ✅ All tests pass
- ✅ Zero breaking changes

### nodesview.go Status
- ✅ Already appropriately refactored (pure logic in nodesview/ sub-package)
- ✅ Cohesive Bubbletea component (Elm pattern)
- ✅ No further action needed

### Overall Phase 3.5
- **Effort:** 6-8 hours (client.go only)
- **Risk:** Very Low
- **Status:** Complete after client.go refactoring

---

## Lessons from Phase 2.2

**What worked well:**
1. Same-package file splitting (no circular dependencies)
2. Clear file responsibilities (lifecycle, pipeline, handlers)
3. Incremental commits with validation at each step
4. Zero test modifications required
5. All tests passed with race detector unchanged

**Apply to Phase 3.5:**
- Follow exact same pattern
- Clear separation by responsibility (streaming, subscriptions, conversion)
- Validate tests at each step
- Expect zero test changes
- Expect all tests to pass identically

---

## Time Estimates

| Step | Task | Time |
|------|------|------|
| Prep | Backup and baseline tests | 15 min |
| 1 | Create client_conversion.go | 1.5 hrs |
| 2 | Create client_subscriptions.go | 1.5 hrs |
| 3 | Create client_streaming.go | 2 hrs |
| 4 | Clean up client.go | 1 hr |
| 5 | Validation | 1 hr |
| 6 | Documentation | 30 min |
| 7 | Final commit | 15 min |
| **Total** | | **8 hours** |

**Conservative estimate:** 8 hours
**Optimistic estimate:** 6 hours
**Expected:** 6-8 hours

---

## Completion Checklist

- [ ] All 4 files created with proper headers
- [ ] client.go reduced to ~250 lines
- [ ] All files under 500 lines
- [ ] All tests pass with `-race` flag
- [ ] No flaky tests (10 consecutive runs pass)
- [ ] Test coverage maintained or improved
- [ ] All code formatted with `gofmt`
- [ ] Documentation updated
- [ ] Phase 3.5 marked complete in remediation plan
- [ ] Code merged to main branch
