# Multi-Level Management Implementation Plan

**Based on**: [docs/research/multi-level-management.md](../research/multi-level-management.md)
**Status**: Ready for Implementation
**Created**: 2025-10-27
**Estimated Duration**: 6-7 weeks
**Risk Level**: Medium

## Overview

This plan implements hierarchical management capabilities for the lippycat distributed architecture, enabling:
- Real-time topology updates propagating upstream through processor chains
- Transparent management operation proxying across processor hierarchies
- TUI control of hunters connected to downstream processors

## Architecture Summary

```
TUI → Processor A (root)
        ├─ Hunter 1, Hunter 2
        └─ Processor B (downstream) ← TRANSPARENT PROXY
            ├─ Hunter 3, Hunter 4
            └─ Processor C (deeper downstream)
                └─ Hunter 5, Hunter 6
```

**Key Features**:
- Streaming topology updates (`SubscribeTopology()` RPC)
- Processor-scoped operations (`UpdateFilterOnProcessor()` family)
- Event-driven propagation (hunter events → processor chain → TUI)
- Token-based authorization for deep chains
- Support for arbitrary hierarchy depth (recommended max: 10 levels)

---

## Phase 1: Protocol & Core Infrastructure

**Duration**: 2 weeks
**Goal**: Define gRPC protocol and create core packages

### Tasks

#### 1.1
- [x] Define `SubscribeTopology()` RPC in `api/proto/management.proto`
  - [x] Add `TopologySubscribeRequest` message
  - [x] Add `TopologyUpdate` message with oneof update types
  - [x] Add `TopologyUpdateType` enum
  - [x] Add event messages: `HunterConnectedEvent`, `HunterDisconnectedEvent`, etc.

#### 1.2
- [x] Define processor-scoped management RPCs in `api/proto/management.proto`
  - [x] Add `UpdateFilterOnProcessor()` RPC
  - [x] Add `DeleteFilterOnProcessor()` RPC
  - [x] Add `GetFiltersFromProcessor()` RPC
  - [x] Add `ProcessorFilterRequest` message
  - [x] Add `ProcessorFilterDeleteRequest` message
  - [x] Add `ProcessorFilterQueryRequest` message

#### 1.3
- [x] Add authorization token messages for deep chains
  - [x] Add `AuthorizationToken` message with signature field
  - [x] Add token fields to `ProcessorFilterRequest`

#### 1.4
- [x] Add hierarchy metadata to existing messages
  - [x] Add `hierarchy_depth` field to `ProcessorNode`
  - [x] Add `reachable` and `unreachable_reason` fields to `ProcessorNode`
  - [x] Add `upstream_chain` field to processor registration

#### 1.5
- [x] Regenerate protobuf code
  - [x] Run `make proto` or protoc command
  - [x] Verify generated files compile
  - [x] Commit generated code

#### 1.6
- [x] Create `internal/pkg/processor/proxy/` package structure
  - [x] Create `manager.go` with `Manager` struct
  - [x] Create `topology_cache.go` with `TopologyCache` struct
  - [x] Create `auth.go` for token generation/verification
  - [x] Add package documentation

#### 1.7
- [x] Implement `TopologyCache`
  - [x] Implement `Apply(update)` method for state updates
  - [x] Implement `GetSnapshot()` method for current state
  - [x] Add methods: `GetProcessor()`, `GetHunter()`, `GetFilter()`
  - [x] Add thread-safety (RWMutex)

#### 1.8
- [x] Write unit tests for `TopologyCache`
  - [x] Test hunter connect/disconnect events
  - [x] Test processor connect/disconnect events
  - [x] Test filter update events
  - [x] Test concurrent access (race detection)
  - [x] Test snapshot generation

#### 1.9
- [x] Implement authorization token system
  - [x] Implement `issueAuthToken()` in proxy manager
  - [x] Implement `verifyAuthToken()` with signature verification
  - [x] Implement `signToken()` using processor certificate
  - [x] Add token expiration checks (5-minute TTL)

#### 1.10
- [x] Write tests for authorization tokens
  - [x] Test token issuance
  - [x] Test token verification (valid signature)
  - [x] Test token verification (expired token)
  - [x] Test token verification (invalid signature)

### Deliverables
- ✅ Updated protobuf definitions with all new RPCs and messages
- ✅ Generated Go code compiles successfully
- ✅ `internal/pkg/processor/proxy/` package with core types
- ✅ `TopologyCache` implementation with >90% test coverage
- ✅ Authorization token system with tests (79.3% package coverage)

---

## Phase 2: Downstream Topology Subscription

**Duration**: 1.5 weeks
**Goal**: Enable processors to subscribe to downstream topology changes

### Tasks

#### 2.1
- [x] Enhance `internal/pkg/processor/downstream/manager.go`
  - [x] Add `ProcessorInfo.TopologyStream` field
  - [x] Add `ProcessorInfo.TopologyCancel` field
  - [x] Add `ProcessorInfo.TopologyUpdateChan` field
  - [x] Implement `SubscribeToDownstream(proc)` method
  - [x] Implement `receiveTopologyUpdates(proc, stream)` goroutine
  - [x] Add health monitoring for topology stream

#### 2.2
- [x] Implement topology subscription lifecycle
  - [x] Subscribe when downstream processor connects
  - [x] Unsubscribe when downstream processor disconnects
  - [x] Automatic reconnection on stream failure (with backoff)
  - [x] Cleanup on manager shutdown

#### 2.3
- [x] Implement `SubscribeTopology()` RPC handler in `internal/pkg/processor/processor.go`
  - [x] Create subscriber channel (buffered, size 100)
  - [x] Register subscriber in proxy manager
  - [x] Send initial topology snapshot to subscriber
  - [x] Stream topology updates until context canceled
  - [x] Clean up subscriber on disconnect

#### 2.4
- [x] Enhance `internal/pkg/processor/hunter/manager.go` to publish events
  - [x] Add `TopologyPublisher` interface
  - [x] Add `topologyPublisher` field to `Manager`
  - [x] Call `PublishHunterConnected()` on registration
  - [x] Call `PublishHunterDisconnected()` on removal
  - [x] Call `PublishHunterStatusChanged()` on status changes

#### 2.5
- [x] Implement event publisher in proxy manager
  - [x] Implement `PublishTopologyUpdate(update)` method
  - [x] Update topology cache on each event
  - [x] Broadcast to all subscribers

#### 2.6
- [x] Implement topology update broadcasting
  - [x] Create `broadcastTopologyUpdate(update)` method
  - [x] Non-blocking send to subscriber channels
  - [x] Drop updates for slow subscribers (with warning log)
  - [x] Track broadcast metrics

#### 2.7
- [x] Wire up event flow
  - [x] Connect hunter manager to proxy manager publisher
  - [x] Connect downstream manager to proxy manager
  - [x] Test event propagation: hunter → processor → upstream

#### 2.8
- [x] Write integration tests
  - [x] Test: hunter connects → upstream receives event
  - [x] Test: hunter disconnects → upstream receives event
  - [x] Test: downstream processor connects → topology refreshed
  - [x] Test: topology stream failure → automatic reconnection (marked as skip - requires gRPC integration environment)
  - [x] Test: slow subscriber → updates dropped gracefully

### Deliverables
- ✅ Processors subscribe to downstream topology changes
- ✅ Hunter events propagate from leaf to root
- ✅ Topology cache stays synchronized across hierarchy
- ✅ Integration tests: topology subscription, event propagation, slow subscribers, concurrent updates

---

## Phase 3: Management Operation Proxying

**Duration**: 1.5 weeks
**Goal**: Enable management operations to be proxied through processor hierarchy

### Tasks

#### 3.1
- [x] Implement `UpdateFilterOnProcessor()` RPC handler
  - [x] Check if target is local processor (handle directly)
  - [x] Find downstream processor by ID
  - [x] Forward request via gRPC to downstream
  - [x] Verify authorization token (placeholder - full verification in phase 3.7)
  - [x] Return result to caller

#### 3.2
- [ ] Implement `DeleteFilterOnProcessor()` RPC handler
  - [ ] Check if target is local processor
  - [ ] Route to downstream if needed
  - [ ] Verify authorization token
  - [ ] Return result

#### 3.3
- [ ] Implement `GetFiltersFromProcessor()` RPC handler
  - [ ] Check if target is local processor
  - [ ] Route to downstream if needed
  - [ ] Verify authorization token
  - [ ] Return filters

#### 3.4
- [ ] Add routing logic in proxy manager
  - [ ] Implement `routeToProcessor(processorID, request)` method
  - [ ] Handle processor not found errors
  - [ ] Handle downstream connection errors
  - [ ] Add timeout per hop (5 seconds base + depth scaling)

#### 3.5
- [ ] Enhance downstream manager for operation forwarding
  - [ ] Add `ForwardFilterOperation(targetID, operation)` method
  - [ ] Recursive routing (if target not direct child)
  - [ ] Error propagation with chain context

#### 3.6
- [ ] Implement error context for chains
  - [ ] Create `ChainError` type with processor path
  - [ ] Track which processor failed in chain
  - [ ] Include chain depth in error
  - [ ] Return detailed error to client

#### 3.7
- [ ] Add authorization checks
  - [ ] Verify token at each hop
  - [ ] Check token expiration
  - [ ] Verify signature from root processor
  - [ ] Log authorization attempts (audit trail)

#### 3.8
- [ ] Implement audit logging
  - [ ] Log all proxied operations (requester, target, operation)
  - [ ] Log authorization successes and failures
  - [ ] Log operation results
  - [ ] Include chain depth in logs

#### 3.9
- [ ] Write integration tests
  - [ ] Test: filter update through 2-level hierarchy
  - [ ] Test: filter update through 3-level hierarchy
  - [ ] Test: filter delete through hierarchy
  - [ ] Test: operation with expired token (rejected)
  - [ ] Test: operation with invalid token (rejected)
  - [ ] Test: operation on non-existent processor (error)
  - [ ] Test: mid-chain processor failure (error propagation)

### Deliverables
- ✅ Filter operations work across processor hierarchy
- ✅ Authorization tokens verified at each hop
- ✅ Detailed error messages for chain failures
- ✅ Integration test: TUI → P-A → P-B → P-C → Hunter

---

## Phase 4: TUI Integration

**Duration**: 1.5 weeks
**Goal**: Update TUI to use streaming topology and processor-scoped operations

### Tasks

#### 4.1
- [ ] Replace one-shot topology query with subscription
  - [ ] Remove `queryProcessorTopology()` call
  - [ ] Add `subscribeToProcessorTopology()` method
  - [ ] Create goroutine to receive topology updates
  - [ ] Send updates to TUI event loop via `currentProgram.Send()`

#### 4.2
- [ ] Add topology update message handler in `cmd/tui/capture_events.go`
  - [ ] Define `TopologyUpdateMsg` type
  - [ ] Implement `handleTopologyUpdateMsg(msg)` method
  - [ ] Handle `TOPOLOGY_HUNTER_CONNECTED` event
  - [ ] Handle `TOPOLOGY_HUNTER_DISCONNECTED` event
  - [ ] Handle `TOPOLOGY_PROCESSOR_CONNECTED` event
  - [ ] Handle `TOPOLOGY_PROCESSOR_DISCONNECTED` event
  - [ ] Handle `TOPOLOGY_FILTER_UPDATED` event

#### 4.3
- [ ] Update nodes view for real-time updates
  - [ ] Implement `addHunterToView(processorID, hunter)` method
  - [ ] Implement `removeHunterFromView(processorID, hunterID)` method
  - [ ] Implement `updateProcessorStatus(processorID, status)` method
  - [ ] Add visual indicators for new/removed hunters
  - [ ] Add timestamp for last topology change

#### 4.4
- [ ] Update filter operations in `cmd/tui/filter_operations.go`
  - [ ] Replace `UpdateFilter()` calls with `UpdateFilterOnProcessor()`
  - [ ] Replace `DeleteFilter()` calls with `DeleteFilterOnProcessor()`
  - [ ] Include target processor ID in requests
  - [ ] Request auth token from root processor
  - [ ] Include token in all proxied operations

#### 4.5
- [ ] Implement root processor lookup
  - [ ] Add `getRootProcessorForAddress(targetAddr)` method
  - [ ] Walk up hierarchy to find directly connected processor
  - [ ] Cache root processor for each downstream processor
  - [ ] Handle case where root not found (error)

#### 4.6
- [ ] Add hierarchy depth indicators in UI
  - [ ] Show depth number next to processor names
  - [ ] Show full processor path on hover/selection
  - [ ] Add latency estimate for deep operations
  - [ ] Warn when depth > 7 (high latency risk)

#### 4.7
- [ ] Update subscription management
  - [ ] Ensure hunter subscriptions work across hierarchy
  - [ ] Update `UpdateSubscription()` to use root processor connection
  - [ ] Handle subscription changes without reconnecting

#### 4.8
- [ ] Add error handling for chain operations
  - [ ] Display `ChainError` with full context
  - [ ] Show which processor in chain failed
  - [ ] Offer retry option for failed operations
  - [ ] Show "unreachable" status for partitioned subtrees

#### 4.9
- [ ] Write end-to-end tests
  - [ ] Test: TUI connects → receives topology subscription
  - [ ] Test: Hunter connects to downstream → TUI updates immediately
  - [ ] Test: TUI creates filter on downstream hunter → succeeds
  - [ ] Test: TUI deletes filter on downstream hunter → succeeds
  - [ ] Test: Downstream processor disconnects → TUI shows unreachable
  - [ ] Test: 5-level hierarchy with all operations

### Deliverables
- ✅ TUI receives real-time topology updates
- ✅ TUI can manage filters on any hunter in hierarchy
- ✅ TUI shows hierarchy depth and health status
- ✅ End-to-end test: Complete workflow with 3-level hierarchy

---

## Phase 5: Performance & Reliability

**Duration**: 1 week
**Goal**: Optimize for performance and handle failure scenarios

### Tasks

#### 5.1
- [ ] Implement topology update batching
  - [ ] Create `TopologyUpdateBatcher` with max size and delay
  - [ ] Batch multiple updates within time window (100ms)
  - [ ] Flush on max size (10 updates) or timeout
  - [ ] Test: verify reduced update frequency

#### 5.2
- [ ] Add retry logic for proxied operations
  - [ ] Implement exponential backoff (100ms, 200ms, 400ms, 800ms)
  - [ ] Maximum 3 retries per operation
  - [ ] Only retry on transient errors (connection, timeout)
  - [ ] Don't retry on authorization failures

#### 5.3
- [ ] Implement topology cache TTL
  - [ ] Add timestamp to cached entries
  - [ ] Expire entries after 5 minutes
  - [ ] Periodic cleanup goroutine (every 1 minute)
  - [ ] Refresh on cache miss

#### 5.4
- [ ] Add hierarchy depth limits
  - [ ] Define `MaxHierarchyDepth = 10`
  - [ ] Reject processor registration if depth exceeded
  - [ ] Return error with depth information
  - [ ] Test: 11-level hierarchy rejected

#### 5.5
- [ ] Implement cycle detection
  - [ ] Add `upstream_chain` field to processor registration
  - [ ] Check if registering processor is in upstream chain
  - [ ] Reject registration if cycle detected
  - [ ] Test: A → B → C → A (cycle rejected)

#### 5.6
- [ ] Add operation timeout scaling
  - [ ] Base timeout: 5 seconds
  - [ ] Add per-hop timeout: 500ms × depth
  - [ ] Example: 7-level chain = 5s + (7 × 500ms) = 8.5s
  - [ ] Configure timeouts in context

#### 5.7
- [ ] Implement graceful shutdown
  - [ ] Cancel all topology subscriptions
  - [ ] Drain subscriber channels
  - [ ] Wait for in-flight operations (with timeout)
  - [ ] Clean up downstream connections

#### 5.8
- [ ] Add network partition handling
  - [ ] Health check goroutine for downstream connections (30s interval)
  - [ ] Automatic reconnection on stream failure
  - [ ] Mark subtree as unreachable on partition
  - [ ] Full topology re-sync on reconnection

#### 5.9
- [ ] Performance testing
  - [ ] Load test: 10 processors, 100 hunters
  - [ ] Measure topology update latency at each depth
  - [ ] Measure operation latency through chain
  - [ ] Verify <1% network bandwidth for topology updates

#### 5.10
- [ ] Reliability testing
  - [ ] Test: downstream disconnect/reconnect (topology restored)
  - [ ] Test: mid-chain processor failure (error propagation)
  - [ ] Test: network partition for 1 minute (automatic recovery)
  - [ ] Test: 1000 hunters connecting simultaneously (no drops)

#### 5.11
- [ ] Documentation
  - [ ] Update `docs/DISTRIBUTED_MODE.md` with multi-level management
  - [ ] Add hierarchy depth guidelines (optimal: 1-3, max: 10)
  - [ ] Document operation latency by depth
  - [ ] Add troubleshooting section for chain failures

### Deliverables
- ✅ System handles 10 processors, 100 hunters efficiently
- ✅ Topology updates use <1% network bandwidth
- ✅ Automatic recovery from network partitions
- ✅ Graceful degradation for deep hierarchies (depth > 7)
- ✅ Updated documentation in `docs/DISTRIBUTED_MODE.md`

---

## Phase 6: Security Hardening

**Duration**: 1 week
**Goal**: Ensure secure operation across processor hierarchies

### Tasks

#### 6.1
- [ ] Security audit of proxied operations
  - [ ] Review all RPC handlers for authorization checks
  - [ ] Verify token validation at each hop
  - [ ] Check for authorization bypass vulnerabilities
  - [ ] Document threat model

#### 6.2
- [ ] Implement processor-level authorization
  - [ ] Define authorization policies (who can manage which processors)
  - [ ] Check client certificate from gRPC context
  - [ ] Implement `CanManage(client, processorID, operation)` check
  - [ ] Add role-based access control (RBAC) support

#### 6.3
- [ ] Add topology update authentication
  - [ ] Sign topology updates with processor certificate
  - [ ] Add signature field to `TopologyUpdate` message
  - [ ] Verify signature at each hop before re-broadcasting
  - [ ] Reject unsigned or invalid updates

#### 6.4
- [ ] Enhance TLS certificate validation
  - [ ] Verify certificate chain for downstream connections
  - [ ] Check certificate expiration
  - [ ] Validate Common Name (CN) matches processor ID
  - [ ] Support certificate rotation

#### 6.5
- [ ] Implement rate limiting
  - [ ] Create `TopologyRateLimiter` per processor (10 updates/sec)
  - [ ] Rate limit proxied operations per client (100 ops/min)
  - [ ] Return `429 Too Many Requests` on limit exceeded
  - [ ] Add metrics for rate limit hits

#### 6.6
- [ ] Add operation audit logging
  - [ ] Log requester identity (from TLS cert)
  - [ ] Log target processor ID and hunter ID
  - [ ] Log operation type and parameters (sanitized)
  - [ ] Log result (success/failure/error)
  - [ ] Log authorization token (hashed)
  - [ ] Structured logging (JSON format)

#### 6.7
- [ ] Security testing
  - [ ] Test: unauthorized client attempts operation (rejected)
  - [ ] Test: expired token used (rejected)
  - [ ] Test: invalid token signature (rejected)
  - [ ] Test: unsigned topology update (rejected)
  - [ ] Test: rate limit exceeded (throttled)
  - [ ] Test: TLS certificate mismatch (connection refused)

#### 6.8
- [ ] Penetration testing scenarios
  - [ ] Attempt to bypass authorization with crafted tokens
  - [ ] Attempt topology poisoning with fake updates
  - [ ] Attempt DoS via topology update flood
  - [ ] Attempt man-in-the-middle on processor connections
  - [ ] Document findings and mitigations

#### 6.9
- [ ] Security documentation
  - [ ] Update `docs/SECURITY.md` with multi-level security model
  - [ ] Document authorization token mechanism
  - [ ] Document topology update authentication
  - [ ] Add security best practices for deep hierarchies
  - [ ] Add incident response procedures

### Deliverables
- ✅ Security audit report with no critical findings
- ✅ Authorization checks on all proxied operations
- ✅ Topology update authentication with signatures
- ✅ Rate limiting prevents abuse
- ✅ Comprehensive audit logging for compliance
- ✅ Updated security documentation in `docs/SECURITY.md`

---

## Testing Strategy

### Unit Tests
- All new packages have >90% test coverage
- Mocked gRPC clients for isolation
- Race detector enabled (`go test -race`)

### Integration Tests
- 2-level hierarchy: root processor + 1 downstream
- 3-level hierarchy: root + 2 downstream levels
- Event propagation: hunter → processor → upstream → TUI
- Operation proxying: TUI → root → downstream → hunter

### End-to-End Tests
- Full workflow: TUI connects → subscribes → receives updates → manages hunters
- Failure scenarios: processor disconnect, network partition, authorization failure
- Performance tests: 10 processors, 100 hunters, 1000 operations

### Regression Tests
- Existing single-processor mode still works
- Direct hunter-to-processor mode unchanged
- Backward compatibility with older protocol versions

---

## Rollout Plan

### Week 1-2: Protocol Development
- Merge Phase 1 changes to main branch
- Tag as `v0.3.0-alpha.1`
- Internal testing with protobuf changes

### Week 3-4: Core Functionality
- Merge Phase 2 (topology subscription)
- Merge Phase 3 (operation proxying)
- Tag as `v0.3.0-alpha.2`
- Deploy to staging environment for testing

### Week 5: TUI Integration
- Merge Phase 4 (TUI changes)
- Tag as `v0.3.0-beta.1`
- User acceptance testing with 3-level hierarchy

### Week 6: Performance & Reliability
- Merge Phase 5 (optimizations)
- Tag as `v0.3.0-rc.1`
- Load testing and performance validation

### Week 7: Security & Release
- Merge Phase 6 (security hardening)
- Security review and penetration testing
- Tag as `v0.3.0`
- Release to production

---

## Success Criteria

### Functional Requirements
- [ ] **FR1**: TUI can manage hunters on downstream processors (3 levels deep)
- [ ] **FR2**: New hunter appears in TUI within 2 seconds
- [ ] **FR3**: Disconnected hunter removed from TUI within 2 seconds
- [ ] **FR4**: Filter operations work across hierarchy
- [ ] **FR5**: Subscription changes work across hierarchy

### Performance Requirements
- [ ] **PR1**: Topology updates use <1% network bandwidth
- [ ] **PR2**: Proxied operations complete within 5 seconds (3-level hierarchy)
- [ ] **PR3**: System handles 100 hunters across 10 processors
- [ ] **PR4**: Operation latency <100ms per hop

### Reliability Requirements
- [ ] **RR1**: Automatic recovery from network partition (1 minute)
- [ ] **RR2**: Graceful handling of mid-chain processor failure
- [ ] **RR3**: No topology updates lost (99.9% delivery rate)
- [ ] **RR4**: System survives 1000 hunters connecting simultaneously

### Security Requirements
- [ ] **SR1**: All proxied operations authenticated via TLS/mTLS
- [ ] **SR2**: Authorization tokens verified at each hop
- [ ] **SR3**: Topology updates signed and verified
- [ ] **SR4**: Unauthorized operations logged and rejected
- [ ] **SR5**: Rate limiting prevents DoS attacks

---

## Risk Mitigation

### Risk: Complex State Management
**Impact**: High | **Probability**: Medium
**Mitigation**:
- Thorough unit testing of `TopologyCache`
- Integration tests for state synchronization
- Add debug endpoints to inspect cache state

### Risk: Performance Degradation in Deep Chains
**Impact**: Medium | **Probability**: High
**Mitigation**:
- Hard limit on hierarchy depth (max 10 levels)
- Timeout scaling by depth
- UI warnings for deep operations
- Performance testing with realistic topologies

### Risk: Authorization Token Vulnerabilities
**Impact**: High | **Probability**: Low
**Mitigation**:
- Short token TTL (5 minutes)
- Signature verification at each hop
- Security audit before release
- Penetration testing

### Risk: Backward Compatibility Issues
**Impact**: Medium | **Probability**: Medium
**Mitigation**:
- Maintain old `GetTopology()` RPC for compatibility
- Feature flag for multi-level management
- Gradual rollout with canary deployments
- Regression testing

### Risk: Network Partition Edge Cases
**Impact**: Medium | **Probability**: Medium
**Mitigation**:
- Comprehensive partition testing
- Clear "unreachable" indicators in UI
- Automatic reconnection with exponential backoff
- Manual override option (direct connection)

---

## Open Questions & Decisions Needed

### Q1: Maximum Hierarchy Depth
**Decision**: Start with max depth of 10 levels, configurable via flag
**Rationale**: Balances flexibility with performance, matches typical network topologies

### Q2: Topology Update Delivery Guarantee
**Decision**: Best-effort with explicit `RefreshTopology()` RPC for manual sync
**Rationale**: Simpler implementation, sufficient for most use cases, can upgrade later

### Q3: Topology Conflict Resolution
**Decision**: Downstream authoritative (downstream state always wins)
**Rationale**: Downstream processor is source of truth for its hunters

### Q4: Automatic Filter Propagation
**Decision**: Explicit targeting only (no automatic propagation)
**Rationale**: Safer default, prevents accidental filter application

### Q5: Partial Failure Handling
**Decision**: Return partial success with detailed error list
**Rationale**: Allows user to retry failed operations, better visibility

### Q6: Topology Subscription Filtering
**Decision**: Full hierarchy always (no filtering initially)
**Rationale**: Reduces complexity, can add filtering later if needed

### Q7: Reconnection Handling
**Decision**: Full topology re-sync on processor reconnection
**Rationale**: Simpler and more robust, optimize later if needed

---

## Monitoring & Observability

### Metrics to Add
- `topology_update_count{processor_id, update_type}` - Rate of topology changes
- `operation_latency_seconds{operation, depth}` - Latency by chain depth
- `chain_depth_distribution{processor_id}` - Histogram of depths
- `chain_broken_count{root_processor}` - Number of partitioned chains
- `authorization_failures{processor_id, reason}` - Failed auth attempts
- `topology_cache_size{processor_id}` - Cache entries count

### Alerts to Configure
- Chain depth > 7 (latency risk)
- Operation latency > 5s (performance degradation)
- Chain broken for > 5 minutes (partition not recovering)
- Authorization failure rate > 10/min (potential attack)
- Topology update rate > 100/sec (potential flood)

### Dashboards to Create
- Hierarchy topology visualization (graph)
- Operation latency heatmap by depth
- Topology update timeline
- Authorization audit log viewer

---

## Documentation Updates

### Files to Update
- `docs/DISTRIBUTED_MODE.md` - Add multi-level management section
- `docs/SECURITY.md` - Add authorization token mechanism
- `docs/PERFORMANCE.md` - Add latency guidance by depth
- `cmd/tui/README.md` - Document hierarchical management UI
- `CHANGELOG.md` - Add v0.3.0 release notes

### New Documentation
- `docs/MULTI_LEVEL_MANAGEMENT.md` - User guide for hierarchical deployments
- `docs/TROUBLESHOOTING_CHAINS.md` - Debug guide for chain issues

---

## References

- [Multi-Level Management Research](../research/multi-level-management.md) - Original analysis
- [Distributed Mode Documentation](../DISTRIBUTED_MODE.md) - Current architecture
- [Security Documentation](../SECURITY.md) - TLS/mTLS configuration
- [Performance Tuning](../PERFORMANCE.md) - Performance guidelines
