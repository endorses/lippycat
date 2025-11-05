# Phase 3.1: Test Coverage Implementation Plan

**Created:** 2025-11-05
**Parent Plan:** docs/plan/code-review-remediation-2025-11-01.md
**Status:** In Progress
**Estimated Duration:** 10-15 days (2-3 weeks)

---

## Overview

Phase 3.1 aims to improve test coverage for three critical packages:
- **processor**: 31.4% → **70%+** (target: +38.6%)
- **remotecapture**: 12.2% → **60%+** (target: +47.8%)
- **capture**: 30.3% → **60%+** (target: +29.7%)

**Total Coverage Increase Needed:** ~116% across 3 packages

**Strategy:** Incremental daily commits, prioritizing high-value untested paths

---

## Current Baseline (from coverage.txt)

```bash
# Package Coverage Summary
internal/pkg/processor              31.4%  (target: 70%+)
internal/pkg/remotecapture          12.2%  (target: 60%+)
internal/pkg/capture                30.3%  (target: 60%+)
internal/pkg/processor/pcap         25.4%  (already has tests)
internal/pkg/processor/filtering    80.9%  (good coverage)
internal/pkg/processor/proxy        85.3%  (good coverage)
```

---

## Architecture Context

### Processor Refactoring (Phase 2.2 - Completed)
The processor was refactored using **Option A: File Splitting** into 4 focused files:
- `processor.go` (~270 lines) - Core types, Config, constructor
- `processor_lifecycle.go` (~250 lines) - Start(), Shutdown(), listener setup
- `processor_packet_pipeline.go` (~200 lines) - processBatch(), packet processing
- `processor_grpc_handlers.go` (~1,200 lines) - 21 gRPC service methods

**Existing Test Files:**
- `processor_core_test.go` - Tests for New(), config validation, basic operations
- `processor_registration_test.go` - Tests for hunter registration
- `streaming_test.go` - Basic processBatch() tests
- `processor_packet_pipeline_test.go` - **NEW** (created today, needs fixes)

**Test Coverage by File (estimated from current 31.4%):**
- `processor.go` - ~45% (constructor well tested)
- `processor_lifecycle.go` - ~15% (Start/Shutdown need tests)
- `processor_packet_pipeline.go` - ~20% (processBatch needs comprehensive tests)
- `processor_grpc_handlers.go` - ~10% (21 gRPC methods mostly untested)

---

## Implementation Plan: Daily Breakdown

### Day 1-2: Fix and Complete processor_packet_pipeline Tests

**Goal:** Get processor coverage from 31.4% → 45%

**Tasks:**
- [ ] Fix `processor_packet_pipeline_test.go` API mismatches:
  - Use `PcapWriterConfig` instead of `UnifiedPcapConfig`
  - Use `AutoRotateConfig` instead of `PerCallPcapConfig`
  - Use `subscriberManager.Add()` instead of `Subscribe()`
  - Remove duplicate `TestProcessBatch_EmptyBatch`
- [ ] Run tests to verify all compile and pass
- [ ] Add missing test cases:
  - [ ] processBatch with upstream forwarding
  - [ ] processBatch with auto-rotate PCAP writer
  - [ ] processBatch with call correlator
  - [ ] processBatch error paths (invalid hunter ID, nil metadata)
- [ ] Run coverage: `go test -coverprofile=processor_coverage.txt ./internal/pkg/processor/`
- [ ] Verify processor coverage ≥ 45%

**Acceptance Criteria:**
- All processor_packet_pipeline tests pass with `-race`
- Coverage report shows ≥ 45% for processor package
- No panics or race conditions detected

---

### Day 3-4: Processor Lifecycle Tests

**Goal:** Get processor coverage from 45% → 55%

**File:** `processor_lifecycle_test.go` (new file)

**Tests to Add:**
- [ ] TestProcessor_Start_Success - Successful gRPC server start
- [ ] TestProcessor_Start_AlreadyRunning - Start called twice
- [ ] TestProcessor_Start_BindError - Port already in use
- [ ] TestProcessor_Shutdown_Clean - Clean shutdown with active hunters
- [ ] TestProcessor_Shutdown_WithPendingWrites - Shutdown waits for PCAP writes
- [ ] TestProcessor_Shutdown_Idempotent - Multiple shutdown calls safe
- [ ] TestProcessor_Shutdown_Timeout - Shutdown with slow hunters
- [ ] TestProcessor_StartStop_Cycle - Multiple start/stop cycles
- [ ] TestProcessor_Shutdown_WithSubscribers - Subscribers notified on shutdown
- [ ] TestProcessor_Shutdown_WithUpstream - Upstream connection closed

**Coverage Target:** processor_lifecycle.go from ~15% → 70%+

**Acceptance Criteria:**
- All lifecycle tests pass with `-race`
- No goroutine leaks (use `goleak` if needed)
- Coverage ≥ 55% for processor package

---

### Day 5-7: Processor gRPC Handlers Tests

**Goal:** Get processor coverage from 55% → 70%+

**File:** `processor_grpc_handlers_test.go` (new file)

**Priority Handlers (by usage frequency):**
1. **RegisterHunter** - Critical path, needs extensive tests
   - [ ] Successful registration
   - [ ] Duplicate hunter ID
   - [ ] Max hunters exceeded
   - [ ] Invalid hunter ID format
   - [ ] Registration with filters
2. **StreamPackets** - Main data path
   - [ ] Successful streaming from hunter
   - [ ] Multiple concurrent hunters streaming
   - [ ] Hunter disconnect handling
   - [ ] Flow control signals
   - [ ] Backpressure handling
3. **SubscribeToPackets** - TUI client subscription
   - [ ] Successful subscription
   - [ ] Subscription with hunter filter
   - [ ] Subscriber disconnect
   - [ ] Slow subscriber handling
4. **CreateFilter, UpdateFilter, DeleteFilter**
   - [ ] Valid filter operations
   - [ ] Invalid filter patterns
   - [ ] Filter application to hunters
5. **GetStats, GetHunters** - Read operations
   - [ ] Stats retrieval
   - [ ] Hunter list retrieval
6. **Low-priority handlers** - Basic smoke tests only
   - Shutdown, ListFilters, GetTopology, etc.

**Test Pattern (table-driven):**
```go
func TestRegisterHunter(t *testing.T) {
    tests := []struct {
        name       string
        req        *data.RegisterRequest
        wantErr    bool
        errContains string
    }{
        {
            name: "successful registration",
            req: &data.RegisterRequest{
                HunterId: "hunter-1",
                Hostname: "host1",
                Interfaces: []string{"eth0"},
            },
            wantErr: false,
        },
        // ... more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

**Acceptance Criteria:**
- All high-priority handlers have comprehensive tests
- Low-priority handlers have smoke tests
- Coverage ≥ 70% for processor package
- All tests pass with `-race`

---

### Day 8-10: remotecapture Client Tests

**Goal:** Get remotecapture coverage from 12.2% → 60%+

**File:** `internal/pkg/remotecapture/client_test.go` (enhance existing)

**Current Coverage Gaps (estimated from 12.2%):**
- `NewClient()`, `NewClientWithConfig()` - ~70% covered (constructor)
- `Connect()` - ~30% covered (needs error paths)
- `SubscribeToPackets()` - ~0% covered (critical gap!)
- `SubscribeToTopology()` - ~0% covered
- `handlePacketStream()` - ~5% covered (goroutine, hard to test)
- `handleTopologyStream()` - ~0% covered
- `reconnectLoop()` - ~0% covered (critical gap!)

**Tests to Add:**

**Integration Tests (highest value):**
- [ ] TestClient_ConnectAndStream - End-to-end packet streaming
- [ ] TestClient_ReconnectOnDisconnect - Reconnection logic
- [ ] TestClient_MultipleSubscribers - Multiple TUI clients
- [ ] TestClient_FilteredStream - Stream with hunter filter
- [ ] TestClient_TopologyUpdates - Topology subscription
- [ ] TestClient_NetworkFailure - Connection loss handling
- [ ] TestClient_SlowConsumer - Backpressure handling

**Unit Tests:**
- [ ] TestClient_Connect_InvalidAddress
- [ ] TestClient_Connect_TLSError
- [ ] TestClient_Connect_AuthenticationFailure
- [ ] TestClient_Disconnect_Clean
- [ ] TestClient_handlePacketStream_Errors
- [ ] TestClient_handleTopologyStream_Errors
- [ ] TestClient_reconnectLoop_ExponentialBackoff
- [ ] TestClient_reconnectLoop_MaxRetries

**Mock gRPC Server Approach:**
```go
// Create mock processor server for testing
type mockProcessorServer struct {
    data.UnimplementedDataServiceServer
    packets chan *data.PacketBatch
}

func (m *mockProcessorServer) SubscribeToPackets(
    req *data.SubscribeRequest,
    stream data.DataService_SubscribeToPacketsServer,
) error {
    for batch := range m.packets {
        if err := stream.Send(batch); err != nil {
            return err
        }
    }
    return nil
}
```

**Acceptance Criteria:**
- Coverage ≥ 60% for remotecapture package
- All reconnection scenarios tested
- Stream handling tested with mock server
- All tests pass with `-race`

---

### Day 11-13: capture Package Tests

**Goal:** Get capture coverage from 30.3% → 60%+

**File:** `internal/pkg/capture/capture_test.go` (enhance existing)

**Current Coverage Gaps (estimated from 30.3%):**
- `Init()`, `InitWithContext()` - ~80% covered (good)
- `InitWithBuffer()` - ~77% covered (good)
- `captureFromInterface()` - ~69% covered (needs error paths)
- `Send()` - ~87% covered (good)
- `Receive()`, `Close()` - ~100% covered (good)
- `Len()`, `Cap()`, `GetPcapTimeout()` - ~0% covered (simple getters)

**Tests to Add:**

**Error Path Tests (highest value):**
- [ ] TestCapture_InitWithBuffer_InvalidBufferSize
- [ ] TestCapture_InitWithBuffer_NilContext
- [ ] TestCapture_CaptureFromInterface_SetBPFFilterError
- [ ] TestCapture_CaptureFromInterface_ActivationError
- [ ] TestCapture_CaptureFromInterface_ReadPacketError
- [ ] TestCapture_Send_ClosedBuffer
- [ ] TestCapture_Send_ContextCancelled

**Concurrency Tests:**
- [ ] TestCapture_ConcurrentSendReceive
- [ ] TestCapture_MultipleReadersOneWriter
- [ ] TestCapture_CloseWhileCapturing

**Getter Tests (easy wins):**
- [ ] TestPacketBuffer_Len
- [ ] TestPacketBuffer_Cap
- [ ] TestPacketSource_GetPcapTimeout

**Edge Cases:**
- [ ] TestCapture_LargePackets
- [ ] TestCapture_HighPacketRate
- [ ] TestCapture_BufferOverflow

**Acceptance Criteria:**
- Coverage ≥ 60% for capture package
- All error paths tested
- Concurrency tests pass with `-race` 100 times
- All tests pass with `-race`

---

### Day 14-15: Load Tests and Finalization

**Goal:** Add performance/stress tests and verify all coverage targets

**Files:**
- `internal/pkg/processor/processor_load_test.go` (new)
- `internal/pkg/remotecapture/client_load_test.go` (new)

**Load Tests to Add:**

**Processor Load Tests:**
- [ ] TestProcessor_HighPacketRate_10Kpps - 10,000 packets/sec
- [ ] TestProcessor_ManyHunters_100Concurrent - 100 concurrent hunters
- [ ] TestProcessor_DeepTopology_5Levels - 5-level hierarchy
- [ ] TestProcessor_ManySubscribers_100Concurrent - 100 TUI clients
- [ ] TestProcessor_DiskFull_PcapWriteFailure - Simulate disk full
- [ ] BenchmarkProcessor_PacketProcessing - Throughput benchmark

**RemoteCapture Load Tests:**
- [ ] TestClient_NetworkFailure_Reconnection - Flaky network
- [ ] TestClient_HighLatency_Streaming - High RTT connection
- [ ] TestClient_PacketBurst_1000Packets - Bursty traffic
- [ ] BenchmarkClient_StreamingThroughput - Streaming benchmark

**Final Verification:**
```bash
# Run full test suite with coverage
go test -v -race -tags=all -coverprofile=coverage.txt -covermode=atomic ./...

# Generate coverage report
go tool cover -func=coverage.txt | grep -E "(processor|remotecapture|capture)/"

# Verify targets met
# processor: ≥ 70%
# remotecapture: ≥ 60%
# capture: ≥ 60%
```

**Acceptance Criteria:**
- All coverage targets met
- All tests pass with `-race` flag
- No test flakiness (run 10 times)
- Load tests document performance baselines
- CHANGELOG.md updated with test coverage improvements

---

## Daily Commit Strategy

Each day should produce a working, mergeable commit:

**Commit Message Format:**
```
test(processor): add comprehensive processBatch tests

- Add tests for PCAP writer integration
- Add tests for protocol enrichment
- Add tests for VoIP call aggregation
- Add tests for subscriber broadcasting
- Add tests for concurrent processing

Coverage: processor package 31.4% → 45%

Part of Phase 3.1 (Day 1/15)
Ref: docs/plan/phase-3.1-test-coverage-implementation.md
```

**Daily Workflow:**
1. Morning: Write tests for 1-2 hours
2. Run tests: `go test -v -race ./internal/pkg/<package>/`
3. Fix any failures
4. Run coverage: `go test -coverprofile=coverage.txt ./internal/pkg/<package>/`
5. Verify coverage increase
6. Format code: `gofmt -w .`
7. Commit with coverage numbers
8. Update this plan with ✅ checkmarks

---

## Risk Mitigation

### Risk: Tests are Flaky
**Mitigation:** Run each test 10 times with `-race -count=10`

### Risk: Coverage Targets Too Ambitious
**Mitigation:**
- Minimum acceptable: processor 60%, remotecapture 50%, capture 55%
- Document why remaining gaps are hard to test (e.g., OS-level errors)

### Risk: Tests Slow Down CI
**Mitigation:**
- Use `t.Parallel()` for independent tests
- Use `testing.Short()` flag for quick smoke tests
- Keep load tests in separate `_load_test.go` files with build tag

### Risk: gRPC Mocking is Complex
**Mitigation:**
- Use existing test patterns from `processor_registration_test.go`
- Create helper functions for common mock server setup
- Document mock server patterns in test file comments

---

## Success Metrics

### Quantitative:
- [ ] processor coverage: ≥ 70% (currently 31.4%)
- [ ] remotecapture coverage: ≥ 60% (currently 12.2%)
- [ ] capture coverage: ≥ 60% (currently 30.3%)
- [ ] All tests pass with `-race` flag
- [ ] CI test suite runs in < 5 minutes
- [ ] Zero test flakiness over 100 runs

### Qualitative:
- [ ] All critical paths tested (packet processing, streaming, lifecycle)
- [ ] Error paths tested (network failures, disk full, invalid input)
- [ ] Concurrency tested (race detector, high load)
- [ ] Performance baselines documented (benchmarks)
- [ ] Test code is maintainable (table-driven, helper functions)

---

## Completion Checklist

### Implementation Complete:
- [ ] All 15 days of work completed
- [ ] All tests passing with `-race`
- [ ] Coverage targets met
- [ ] Code formatted with `gofmt`
- [ ] CHANGELOG.md updated

### Documentation Complete:
- [ ] This plan updated with ✅ checkmarks
- [ ] Phase 3.1 in remediation plan marked complete
- [ ] Coverage improvements documented in commit messages

### Integration Complete:
- [ ] All tests integrated into CI pipeline
- [ ] Coverage reports generated on each commit
- [ ] No regressions in existing tests

---

## Notes

**Current Status (2025-11-05):**
- Created `processor_packet_pipeline_test.go` (needs fixes before it compiles)
- Identified processor refactoring structure (4 files vs original monolithic)
- Baseline coverage measured: processor 31.4%, remotecapture 12.2%, capture 30.3%

**Next Action:**
Start Day 1 tasks - fix `processor_packet_pipeline_test.go` and get it passing.
