# TODO/FIXME Technical Debt Inventory
**Date:** 2025-11-13
**Task:** Phase 3.3 - Resolve TODO/FIXME Technical Debt
**Total Count:** 38 items

---

## Summary by Category

| Category | Count | Priority Distribution |
|----------|-------|----------------------|
| GPU Acceleration (Stub Implementations) | 13 | P3: 13 (Future) |
| Hunter Flow Control & Metadata | 2 | P2: 2 (Medium) |
| Processor Features | 5 | P1: 1, P2: 3, P3: 1 |
| Test Infrastructure | 5 | P2: 5 (Medium) |
| Build Metadata | 2 | P2: 2 (Medium) |
| SIMD Optimization | 3 | P3: 3 (Future) |
| TUI Component Refactoring | 1 | P3: 1 (Low) |
| Protocol Integration | 1 | P2: 1 (Medium) |
| **Total** | **38** | **P1: 1, P2: 13, P3: 24** |

---

## Priority Definitions

- **P0 (Critical):** Blocks production deployment, security risk, data loss risk
- **P1 (High):** Impacts user experience, missing core functionality
- **P2 (Medium):** Improvement opportunities, missing nice-to-have features
- **P3 (Low/Future):** Future optimizations, long-term improvements

---

## P1: High-Priority Items (1 item)

### 1. ✅ FIXED: Validate Empty UpstreamProcessor at Source
**File:** `internal/pkg/processor/proxy/topology_cache.go:325`
**Priority:** P1 (High)
**Effort:** 2-3 hours
**Status:** ✅ COMPLETED (2025-11-13)

**Problem:**
Topology updates for hunter events (HUNTER_CONNECTED, HUNTER_STATUS_CHANGED, HUNTER_DISCONNECTED) were missing the `ProcessorId` field, causing the topology cache to receive updates with empty processor IDs.

**Root Cause:**
`internal/pkg/processor/hunter/manager.go` was not setting the `ProcessorId` field when creating `TopologyUpdate` messages.

**Implementation:**
1. ✅ Added `processorID` field to `hunter.Manager` struct
2. ✅ Updated `NewManager()` constructor to accept `processorID` parameter
3. ✅ Set `ProcessorId` field in all 4 topology update creation points:
   - Line 108: `TOPOLOGY_HUNTER_CONNECTED`
   - Line 188: `TOPOLOGY_HUNTER_STATUS_CHANGED` (heartbeat)
   - Line 305: `TOPOLOGY_HUNTER_STATUS_CHANGED` (stale hunters)
   - Line 358: `TOPOLOGY_HUNTER_DISCONNECTED`
4. ✅ Updated all callers of `hunter.NewManager()`:
   - `processor.go:248`
   - `processor_core_test.go` (3 locations)
   - `grpc_errors_test.go` (2 locations)
5. ✅ Updated topology cache workaround to defensive check with documentation
6. ✅ All tests pass

**Files Modified:**
- `internal/pkg/processor/hunter/manager.go`
- `internal/pkg/processor/processor.go`
- `internal/pkg/processor/processor_core_test.go`
- `internal/pkg/processor/grpc_errors_test.go`
- `internal/pkg/processor/proxy/topology_cache.go`

**Defensive Measure:**
Kept the validation check in `topology_cache.go` as a defensive measure for backward compatibility, but updated comment to reflect that root cause is fixed.

---

## P2: Medium-Priority Items (13 items)

### 2. Hunter Flow Control Implementation
**File:** `internal/pkg/hunter/connection/manager.go:542`
**Priority:** P2 (Medium)
**Effort:** 1-2 days
**Category:** Feature Implementation

**Current Code:**
```go
// TODO: Implement flow control logic
// When processor sends FLOW_PAUSE, stop capturing
// When processor sends FLOW_RESUME, resume capturing
```

**Action Required:**
1. Implement flow control state machine in hunter
2. Handle `FlowControlState` messages from processor
3. Pause/resume packet capture based on state
4. Add metrics for flow control events
5. Test with simulated processor backpressure

**Note:** Already implemented on processor side, needs hunter-side implementation.

---

### 3. Hunter Metadata Extraction
**File:** `internal/pkg/hunter/hunter.go:373`
**Priority:** P2 (Medium)
**Effort:** 3-4 days
**Category:** Feature Enhancement

**Current Code:**
```go
// TODO: Add metadata extraction (SIP, RTP, etc.)
// Extract protocol-specific metadata before forwarding
```

**Action Required:**
1. Integrate with `internal/pkg/analyzer` framework (completed in Phase 3.2)
2. Extract VoIP metadata (SIP Call-ID, RTP codec, etc.) at hunter
3. Add metadata fields to gRPC packet messages
4. Update processor to use hunter-extracted metadata
5. Add configuration for metadata extraction level (basic/full)

**Benefit:** Reduces processor load by offloading metadata extraction to edge.

---

### 4. Processor Upstream Flow Control
**File:** `internal/pkg/processor/upstream/manager.go:259`
**Priority:** P2 (Medium)
**Effort:** 1-2 days
**Category:** Feature Implementation

**Current Code:**
```go
// TODO: Implement flow control from upstream (pause forwarding if FLOW_PAUSE)
// When upstream processor sends FLOW_PAUSE, pause forwarding
```

**Action Required:**
1. Handle flow control messages from upstream processors
2. Propagate flow control state to local hunters
3. Add metrics for upstream flow control
4. Test hierarchical flow control propagation

---

### 5. Downstream Manager TLS Credentials
**File:** `internal/pkg/processor/downstream/manager.go:133`
**Priority:** P2 (Medium)
**Effort:** 1 day
**Category:** Security Enhancement

**Current Code:**
```go
// TODO: Implement TLS credentials similar to remotecapture client
```

**Action Required:**
1. Add TLS configuration structure to downstream manager
2. Implement credential loading from config
3. Apply TLS to downstream processor connections
4. Add tests for TLS connection establishment
5. Document TLS configuration in `docs/SECURITY.md`

---

### 6. Processor ID Configuration
**File:** `internal/pkg/processor/downstream/manager.go:480`
**Priority:** P2 (Medium)
**Effort:** 2-3 hours
**Category:** Configuration Enhancement

**Current Code:**
```go
// TODO: This should be configurable or passed during manager creation
processorID := "local-processor"
```

**Action Required:**
1. Add `processor_id` to processor configuration
2. Pass processor ID during manager creation
3. Update documentation with processor ID configuration
4. Add validation for processor ID format (DNS-safe)

---

### 7. Processor Chain Auditing
**File:** `internal/pkg/processor/processor_grpc_handlers.go:923`
**Priority:** P2 (Medium)
**Effort:** 2-3 hours
**Category:** Feature Enhancement

**Current Code:**
```go
// TODO: Get processor chain from topology cache for auditing
// Log the full processor chain this packet has traversed
```

**Action Required:**
1. Extract processor chain from topology cache
2. Add chain information to packet metadata
3. Add audit logging for packet routing
4. Add metrics for chain depth and latency
5. Document chain auditing in operational procedures

---

### 8. Server-Side BPF Filtering
**File:** `internal/pkg/processor/processor_grpc_handlers.go:996`
**Priority:** P2 (Feature Request)
**Effort:** 1-2 weeks
**Category:** Feature Request

**Current Code:**
```go
// TODO: Implement server-side BPF filtering
// Allow processor to apply BPF filter to incoming packets
```

**Action Required:**
1. Create GitHub issue for feature request
2. Design BPF filter configuration API
3. Implement BPF compilation and validation
4. Apply filters in packet processing pipeline
5. Add metrics for filter performance
6. Document BPF filter configuration

**Note:** This is a feature request, not a bug. Should be tracked as enhancement.

---

### 9. Build Version Metadata
**File:** `internal/pkg/hunter/connection/manager.go:439`
**Priority:** P2 (Medium)
**Effort:** 1 day
**Category:** Build System

**Current Code:**
```go
Version: "0.1.0", // TODO: version from build
```

**Action Required:**
1. Add `-ldflags` to Makefile to inject version from `VERSION` file
2. Update hunter registration to use injected version
3. Update processor registration to use injected version
4. Add build timestamp and git commit hash
5. Test version reporting in TUI and logs

**Implementation:**
```makefile
VERSION := $(shell cat VERSION)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)
```

---

### 10. GPU/AF_XDP Detection
**Files:**
- `internal/pkg/hunter/connection/manager.go:443` (GPU)
- `internal/pkg/hunter/connection/manager.go:444` (AF_XDP)

**Priority:** P2 (Medium)
**Effort:** 1-2 days
**Category:** Feature Enhancement

**Current Code:**
```go
GpuAcceleration: false, // TODO: detect GPU
AfXdp:           false, // TODO: detect AF_XDP
```

**Action Required:**
1. Implement GPU capability detection (CUDA/OpenCL/SIMD)
2. Implement AF_XDP socket support detection
3. Report capabilities in hunter registration
4. Add capability information to TUI nodes view
5. Document capability detection in operational docs

---

### 11. VoIP Protocol Integration
**File:** `internal/pkg/analyzer/voip_protocol.go:127`
**Priority:** P2 (Medium)
**Effort:** 2-3 hours
**Category:** Code Quality

**Current Code:**
```go
// TODO: Integrate with existing voip.ParseSIPHeaders()
// Currently duplicating SIP parsing logic
```

**Action Required:**
1. Refactor to use existing `internal/pkg/voip.ParseSIPHeaders()`
2. Remove duplicated SIP parsing code
3. Ensure test coverage remains the same
4. Verify no performance regression

---

### 12. Test Infrastructure (5 items)
**Files:**
- `internal/pkg/hunter/hunter_core_test.go:234` - Create forwarding manager tests
- `internal/pkg/voip/tcp_integration_test.go:140` - Complete TCP stream integration
- `internal/pkg/voip/tcp_integration_test.go:211` - Process PCAP and extract users
- `internal/pkg/voip/tcp_integration_test.go:340` - Check PCAP file creation
- `internal/pkg/voip/tcp_integration_test.go:534` - Complete TCP stream integration
- `internal/pkg/processor/topology_subscription_test.go:234` - Integration test infrastructure

**Priority:** P2 (Medium)
**Effort:** 3-5 days total
**Category:** Test Coverage

**Action Required:**
1. Create `forwarding/manager_test.go` with comprehensive tests
2. Complete TCP stream integration tests
3. Add PCAP file creation verification tests
4. Implement topology subscription integration tests
5. Run with `-race` flag to verify thread safety

---

## P3: Low-Priority / Future Items (24 items)

### 13. GPU Acceleration Stub Implementations (13 items)
**Files:**
- `internal/pkg/voip/gpu_cuda_backend.go` (7 TODOs)
- `internal/pkg/voip/gpu_opencl_backend.go` (6 TODOs)

**Priority:** P3 (Future)
**Effort:** 4-6 weeks (when CUDA/OpenCL toolkit available)
**Category:** Future Optimization

**Action Required:**
1. Create GitHub issues for GPU acceleration implementation
2. Label as "enhancement" and "future"
3. Document GPU backend requirements in `docs/GPU_ACCELERATION.md`
4. Keep stubs in place for future implementation

**Note:** These are intentional stubs. Implementation requires:
- CUDA Toolkit (for CUDA backend)
- OpenCL SDK (for OpenCL backend)
- Hardware with compatible GPU
- Performance benchmarking infrastructure

**Decision:** Keep TODOs in place, no action needed now.

---

### 14. SIMD Assembly Optimizations (3 items)
**Files:**
- `internal/pkg/voip/simd.go:151` - PCMPESTRI parallel string matching
- `internal/pkg/voip/simd_amd64_nocuda_impl.go:10` - Assembly implementation
- `internal/pkg/voip/simd_amd64_nocuda_impl.go:16` - PCMPESTRI instruction

**Priority:** P3 (Future)
**Effort:** 2-3 weeks
**Category:** Performance Optimization

**Action Required:**
1. Create GitHub issue for SIMD optimization
2. Label as "performance" and "future"
3. Benchmark current Go implementation to establish baseline
4. Document SIMD optimization opportunities

**Note:** Current Go implementation is sufficient. SIMD would provide 2-4x speedup for packet filtering, but not critical path.

---

### 15. TUI Component Refactoring
**File:** `cmd/tui/components/settings.go:454`
**Priority:** P3 (Low)
**Effort:** 1-2 hours
**Category:** Code Quality

**Current Code:**
```go
// TODO: Move this logic into mode-specific methods
```

**Action Required:**
1. Refactor settings component to use mode-specific methods
2. Improve code organization
3. No functional change

**Note:** Low priority, cosmetic improvement.

---

## Immediate Action Plan (Task 3.3)

### Step 1: Address P1 Item (2-3 hours)
- [x] ✅ COMPLETED - Fix topology cache workaround by validating ProcessorId at source
  - Added processorID field to hunter.Manager
  - Set ProcessorId in all topology update messages
  - Updated all callers
  - All tests pass

### Step 2: Document P2 Items as GitHub Issues (1-2 hours)
- [ ] Create issues for 13 P2 items with proper labels and descriptions
- [ ] Link issues to Phase 3.3 milestone
- [ ] Prioritize within P2 category

### Step 3: Document P3 Items (1 hour)
- [ ] Create meta-issue for GPU acceleration implementation
- [ ] Create meta-issue for SIMD optimizations
- [ ] Mark as "future" and "enhancement"
- [ ] Document decision to keep TODOs as intentional placeholders

### Step 4: Update Plan Document (30 minutes)
- [ ] Mark Task 3.3 subtasks as complete in main plan
- [ ] Update completion checklist
- [ ] Document decisions made

---

## Recommendations

### Keep TODOs In Place
These TODOs should remain in code:
- GPU acceleration stubs (intentional placeholders)
- SIMD optimizations (marked as future)
- Feature requests (server-side BPF filtering)

### Remove TODOs After Implementation
These should be removed once addressed:
- P1 topology cache validation
- P2 feature implementations (flow control, TLS, etc.)
- P2 test infrastructure items

### Convert to GitHub Issues
All P1 and P2 items should have corresponding GitHub issues for tracking and prioritization.

---

## Success Criteria for Task 3.3

- [x] Complete inventory of all TODOs/FIXMEs (38 items)
- [ ] P1 item resolved (topology cache validation)
- [ ] All P2 items tracked in GitHub issues
- [ ] P3 items documented with future implementation plan
- [ ] Plan document updated with completion status
- [ ] Obsolete TODOs removed from codebase

---

## Related Documentation

- [Phase 3.3 Plan](code-review-remediation-2025-11-01.md#33-resolve-todofixme-technical-debt)
- [GPU Acceleration](../../docs/GPU_ACCELERATION.md)
- [Security Documentation](../../docs/SECURITY.md)
- [Operational Procedures](../../docs/operational-procedures.md)
