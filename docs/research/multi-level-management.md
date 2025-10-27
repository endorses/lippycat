# Multi-Level Management in Hierarchical Processor Architecture

**Status**: Research & Design
**Created**: 2025-10-27
**Author**: Analysis of lippycat distributed architecture

## Executive Summary

The current lippycat distributed architecture supports **topology discovery** across multiple processor levels but does NOT support **management operations** (filter updates, subscription changes) for hunters connected to downstream processors. Additionally, topology changes (new hunters, disconnections) are not propagated upstream in real-time.

This document analyzes the current architecture, identifies gaps, and proposes a design for full multi-level management capabilities.

## Table of Contents

1. [Current Architecture](#current-architecture)
2. [Identified Gaps](#identified-gaps)
3. [Requirements](#requirements)
4. [Proposed Solution](#proposed-solution)
5. [Implementation Plan](#implementation-plan)
6. [Security Considerations](#security-considerations)
7. [Alternative Approaches](#alternative-approaches)
8. [Open Questions](#open-questions)

---

## Current Architecture

### Topology Discovery (What Works)

**Flow:**
```
TUI connects to → Upstream Processor A
                    ├─ Queries GetTopology() RPC
                    └─ Receives full hierarchy:
                        ├─ Processor A (self)
                        │   ├─ Hunter 1
                        │   └─ Hunter 2
                        └─ Downstream Processor B (via recursive query)
                            ├─ Hunter 3
                            └─ Hunter 4
```

**Implementation:**
- `ManagementService.GetTopology()` (api/proto/management.proto:36-38)
- Processor recursively queries downstream processors (internal/pkg/processor/downstream/manager.go:134-177)
- TUI processes topology tree and displays full hierarchy (cmd/tui/capture_events.go:548-645)

**Result:** TUI can **see** all hunters in the hierarchy, but cannot **manage** them.

### Management Operations (What Doesn't Work)

**Current Implementation:**
- Filter operations: `ManagementService.UpdateFilter()` (api/proto/management.proto:27-28)
- Subscription changes: `UpdateSubscription()` via remote capture client (internal/pkg/remotecapture/client.go:332-343)

**Problem:**
1. TUI only maintains gRPC connections to **directly connected** processors (cmd/tui/capture_events.go:586-595)
2. Downstream processors are **discovered but not connected** (state = `ProcessorStateUnknown`)
3. Management operations fail with "processor not connected" (cmd/tui/filter_operations.go:162)

**Code Flow (Current - Fails):**
```
TUI selects Hunter 3 (on Processor B)
  ├─ hunter.ProcessorAddr = "processor-b:50051"
  ├─ Look up processor-b in connectionMgr.Processors
  └─ NOT FOUND ✗ (only processor-a exists)
      └─ Error: "processor not connected"
```

### Real-Time Updates (What's Missing)

**Problem:** Topology is static after initial query:
- New hunters connecting to downstream processors → No notification to upstream
- Hunters disconnecting → No notification
- Downstream processor status changes → No notification

**Current Behavior:**
- Topology is queried once at connection time (cmd/tui/capture_events.go:352)
- No subscription mechanism for topology changes
- TUI would need to re-query `GetTopology()` manually to see updates

---

## Identified Gaps

### Gap 1: No Management Proxying

**Issue:** Upstream processors don't proxy management operations to downstream processors.

**Missing Operations:**
- `UpdateFilter()` on downstream hunters
- `DeleteFilter()` on downstream hunters
- `SubscribePackets()` with downstream hunter filter
- `GetFilters()` for downstream hunters

**Example Scenario:**
```
TUI wants to add filter for Hunter 3 (on Processor B)
  ├─ TUI connected to: Processor A
  ├─ Hunter 3 connected to: Processor B
  └─ Current: Operation fails
      Required: Processor A proxies to Processor B
```

### Gap 2: No Real-Time Topology Updates

**Issue:** Topology changes don't propagate upstream.

**Missing Notifications:**
- Hunter connects to downstream processor → Upstream not notified
- Hunter disconnects → Upstream not notified
- Downstream processor status changes → Upstream not notified
- Filter additions/deletions → Upstream not notified

**Impact:**
- TUI shows stale topology
- Management operations fail on hunters that disconnected
- New hunters aren't visible until manual refresh

### Gap 3: No Topology Subscription Mechanism

**Issue:** No streaming RPC for topology changes.

**Current:**
- `GetTopology()` is one-shot request/response (api/proto/management.proto:36-38)
- Client must poll to detect changes

**Required:**
- Streaming RPC for topology updates
- Push notifications for topology changes

---

## Requirements

### Functional Requirements

**FR1: Transparent Management Proxying**
- TUI must be able to manage hunters on downstream processors through upstream processor
- Filter operations must work regardless of processor hierarchy depth
- Subscription changes must work across hierarchy

**FR2: Real-Time Topology Updates**
- Upstream processors must receive notifications when downstream topology changes
- TUI must receive notifications when any processor in hierarchy topology changes
- Updates must propagate within 1-2 seconds

**FR3: Hierarchical Filter Distribution**
- Filters created at upstream processor must propagate to downstream hunters (if targeted)
- Filter deletions must propagate
- Filter status (active/inactive) must be reflected across hierarchy

**FR4: Hunter Subscription Management**
- TUI must be able to subscribe to hunters on any processor in hierarchy
- Subscription changes must be possible without reconnecting
- Subscriptions must survive processor reconnections

### Non-Functional Requirements

**NFR1: Performance**
- Topology updates must not flood the network
- Batch topology changes when possible
- Use efficient delta updates (not full topology refresh)

**NFR2: Security**
- Management operations must respect TLS/mTLS boundaries
- Downstream processors must authenticate upstream proxied requests
- No bypass of security controls

**NFR3: Reliability**
- Topology updates must be reliable (no missed updates)
- Management operations must have clear success/failure semantics
- Handle network partitions gracefully

**NFR4: Scalability**
- Support arbitrary depth of processor hierarchy (tested to 5 levels)
- Support hundreds of hunters across dozens of processors
- Topology updates must scale with number of upstream subscribers

---

## Proposed Solution

### Architecture Overview

**Design Principle:** Upstream processors act as **transparent proxies** for management operations on downstream resources.

```
┌─────────────────────────────────────────────────────────────┐
│                         TUI Client                          │
│  (Connects to Processor A only)                             │
└────────────────┬────────────────────────────────────────────┘
                 │ gRPC (TLS)
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                      Processor A (Upstream)                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Management Proxy Layer                               │   │
│  │  - Routes operations to downstream processors        │   │
│  │  - Aggregates responses                              │   │
│  │  - Subscribes to downstream topology changes         │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────────┘
                 │ gRPC (TLS)
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    Processor B (Downstream)                 │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Management Service                                   │   │
│  │  - Executes operations on local hunters              │   │
│  │  - Publishes topology changes to upstream            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Hunters: [Hunter 3] [Hunter 4]                             │
└─────────────────────────────────────────────────────────────┘
```

### Component 1: Enhanced gRPC Service

**New RPCs in `ManagementService`:**

```protobuf
service ManagementService {
    // ... existing RPCs ...

    // Topology subscription (replaces polling GetTopology)
    rpc SubscribeTopology(TopologySubscribeRequest) returns (stream TopologyUpdate);

    // Processor-scoped filter management (supports downstream targets)
    rpc UpdateFilterOnProcessor(ProcessorFilterRequest) returns (FilterUpdateResult);
    rpc DeleteFilterOnProcessor(ProcessorFilterDeleteRequest) returns (FilterUpdateResult);
    rpc GetFiltersFromProcessor(ProcessorFilterQueryRequest) returns (FilterResponse);

    // Processor-scoped hunter queries (for downstream hunters)
    rpc GetHunterStatusFromProcessor(ProcessorHunterQueryRequest) returns (ConnectedHunter);
}

// Topology subscription request
message TopologySubscribeRequest {
    // Include downstream processors (recursive)
    bool include_downstream = 1;

    // Minimum update interval (seconds) - prevents flooding
    uint32 min_update_interval_sec = 2;
}

// Topology update (streamed)
message TopologyUpdate {
    // Update type
    TopologyUpdateType update_type = 1;

    // Timestamp of change
    int64 timestamp_ns = 2;

    // Update payload (depends on type)
    oneof update {
        HunterConnectedEvent hunter_connected = 3;
        HunterDisconnectedEvent hunter_disconnected = 4;
        ProcessorConnectedEvent processor_connected = 5;
        ProcessorDisconnectedEvent processor_disconnected = 6;
        FilterUpdatedEvent filter_updated = 7;
        ProcessorStatusChangedEvent processor_status_changed = 8;
    }
}

enum TopologyUpdateType {
    TOPOLOGY_HUNTER_CONNECTED = 0;
    TOPOLOGY_HUNTER_DISCONNECTED = 1;
    TOPOLOGY_PROCESSOR_CONNECTED = 2;
    TOPOLOGY_PROCESSOR_DISCONNECTED = 3;
    TOPOLOGY_FILTER_UPDATED = 4;
    TOPOLOGY_PROCESSOR_STATUS_CHANGED = 5;
}

message HunterConnectedEvent {
    string processor_id = 1;       // Which processor hunter connected to
    ConnectedHunter hunter = 2;    // Hunter details
}

message HunterDisconnectedEvent {
    string processor_id = 1;
    string hunter_id = 2;
    string reason = 3;             // Disconnect reason
}

message ProcessorConnectedEvent {
    string parent_processor_id = 1;  // Parent in hierarchy
    ProcessorNode processor = 2;     // New processor details
}

message ProcessorDisconnectedEvent {
    string parent_processor_id = 1;
    string processor_id = 2;
    string reason = 3;
}

message FilterUpdatedEvent {
    string processor_id = 1;         // Which processor owns filter
    FilterUpdate filter_update = 2;  // Filter change details
}

message ProcessorStatusChangedEvent {
    string processor_id = 1;
    ProcessorStatus old_status = 2;
    ProcessorStatus new_status = 3;
}

// Processor-scoped filter request
message ProcessorFilterRequest {
    // Target processor ID (empty = this processor)
    string processor_id = 1;

    // Filter to update
    Filter filter = 2;
}

message ProcessorFilterDeleteRequest {
    string processor_id = 1;
    string filter_id = 2;
}

message ProcessorFilterQueryRequest {
    string processor_id = 1;
    string hunter_id = 2;  // Optional: filter by hunter
}

message ProcessorHunterQueryRequest {
    string processor_id = 1;
    string hunter_id = 2;
}
```

### Component 2: Processor Management Proxy Layer

**New Package:** `internal/pkg/processor/proxy/`

**Responsibilities:**
1. Route management operations to downstream processors
2. Aggregate responses from multiple downstream operations
3. Maintain topology subscription to downstream processors
4. Re-broadcast topology changes to upstream subscribers

**Implementation:**

```go
// internal/pkg/processor/proxy/manager.go
package proxy

import (
    "context"
    "sync"

    "github.com/endorses/lippycat/api/gen/management"
    "github.com/endorses/lippycat/internal/pkg/processor/downstream"
)

// Manager proxies management operations to downstream processors
type Manager struct {
    mu                sync.RWMutex
    downstreamMgr     *downstream.Manager

    // Topology change subscribers (TUI clients)
    topologySubscribers map[string]chan *management.TopologyUpdate

    // Cache of current topology state
    topologyCache     *TopologyCache
}

// NewManager creates a new proxy manager
func NewManager(downstreamMgr *downstream.Manager) *Manager {
    m := &Manager{
        downstreamMgr:       downstreamMgr,
        topologySubscribers: make(map[string]chan *management.TopologyUpdate),
        topologyCache:       NewTopologyCache(),
    }

    // Subscribe to downstream topology changes
    m.startDownstreamTopologySubscriptions()

    return m
}

// UpdateFilterOnProcessor routes filter update to target processor
func (m *Manager) UpdateFilterOnProcessor(ctx context.Context, req *management.ProcessorFilterRequest) (*management.FilterUpdateResult, error) {
    // If target is this processor, handle locally
    if req.ProcessorId == "" || req.ProcessorId == m.thisProcessorID {
        return m.localFilterMgr.Update(req.Filter)
    }

    // Route to downstream processor
    downstream := m.downstreamMgr.GetByID(req.ProcessorId)
    if downstream == nil {
        return nil, fmt.Errorf("processor not found: %s", req.ProcessorId)
    }

    // Forward request via gRPC
    return downstream.Client.UpdateFilterOnProcessor(ctx, req)
}

// SubscribeTopology subscribes a client to topology changes
func (m *Manager) SubscribeTopology(req *management.TopologySubscribeRequest, stream management.ManagementService_SubscribeTopologyServer) error {
    // Create subscriber channel
    subID := generateSubscriberID()
    updateChan := make(chan *management.TopologyUpdate, 100)

    m.mu.Lock()
    m.topologySubscribers[subID] = updateChan
    m.mu.Unlock()

    defer func() {
        m.mu.Lock()
        delete(m.topologySubscribers, subID)
        close(updateChan)
        m.mu.Unlock()
    }()

    // Send initial topology snapshot
    if err := m.sendInitialTopology(stream); err != nil {
        return err
    }

    // Stream topology updates
    for {
        select {
        case <-stream.Context().Done():
            return nil
        case update := <-updateChan:
            if err := stream.Send(update); err != nil {
                return err
            }
        }
    }
}

// startDownstreamTopologySubscriptions subscribes to all downstream processors
func (m *Manager) startDownstreamTopologySubscriptions() {
    // For each downstream processor, start a topology subscription
    for _, downstream := range m.downstreamMgr.GetAll() {
        go m.subscribeToDownstream(downstream)
    }
}

// subscribeToDownstream subscribes to a single downstream processor's topology
func (m *Manager) subscribeToDownstream(downstream *downstream.ProcessorInfo) {
    ctx := context.Background()

    stream, err := downstream.Client.SubscribeTopology(ctx, &management.TopologySubscribeRequest{
        IncludeDownstream: true,  // Recursive
    })
    if err != nil {
        logger.Error("Failed to subscribe to downstream topology",
            "processor", downstream.ProcessorID,
            "error", err)
        return
    }

    // Receive and re-broadcast topology updates
    for {
        update, err := stream.Recv()
        if err != nil {
            logger.Error("Downstream topology stream error",
                "processor", downstream.ProcessorID,
                "error", err)
            return
        }

        // Update local cache
        m.topologyCache.Apply(update)

        // Re-broadcast to our subscribers
        m.broadcastTopologyUpdate(update)
    }
}

// broadcastTopologyUpdate sends update to all subscribers
func (m *Manager) broadcastTopologyUpdate(update *management.TopologyUpdate) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    for _, subChan := range m.topologySubscribers {
        select {
        case subChan <- update:
            // Sent
        default:
            // Subscriber slow, drop update (non-blocking)
            logger.Warn("Dropped topology update for slow subscriber")
        }
    }
}
```

**Topology Cache:**

```go
// internal/pkg/processor/proxy/topology_cache.go
package proxy

import (
    "sync"

    "github.com/endorses/lippycat/api/gen/management"
)

// TopologyCache maintains current state of topology
type TopologyCache struct {
    mu         sync.RWMutex
    processors map[string]*management.ProcessorNode  // processor_id -> node
    hunters    map[string]*management.ConnectedHunter // hunter_id -> hunter
    filters    map[string]*management.Filter          // filter_id -> filter
}

func NewTopologyCache() *TopologyCache {
    return &TopologyCache{
        processors: make(map[string]*management.ProcessorNode),
        hunters:    make(map[string]*management.ConnectedHunter),
        filters:    make(map[string]*management.Filter),
    }
}

// Apply applies a topology update to the cache
func (tc *TopologyCache) Apply(update *management.TopologyUpdate) {
    tc.mu.Lock()
    defer tc.mu.Unlock()

    switch update.UpdateType {
    case management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED:
        event := update.GetHunterConnected()
        tc.hunters[event.Hunter.HunterId] = event.Hunter

    case management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED:
        event := update.GetHunterDisconnected()
        delete(tc.hunters, event.HunterId)

    case management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED:
        event := update.GetProcessorConnected()
        tc.processors[event.Processor.ProcessorId] = event.Processor

    case management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED:
        event := update.GetProcessorDisconnected()
        delete(tc.processors, event.ProcessorId)

    case management.TopologyUpdateType_TOPOLOGY_FILTER_UPDATED:
        event := update.GetFilterUpdated()
        filterUpdate := event.FilterUpdate

        switch filterUpdate.UpdateType {
        case management.FilterUpdateType_UPDATE_ADD,
             management.FilterUpdateType_UPDATE_MODIFY:
            tc.filters[filterUpdate.Filter.Id] = filterUpdate.Filter
        case management.FilterUpdateType_UPDATE_DELETE:
            delete(tc.filters, filterUpdate.Filter.Id)
        }
    }
}

// GetSnapshot returns current topology snapshot
func (tc *TopologyCache) GetSnapshot() *management.TopologyResponse {
    tc.mu.RLock()
    defer tc.mu.RUnlock()

    // Build processor tree
    // ... (implementation details)

    return &management.TopologyResponse{
        Processor: rootNode,
    }
}
```

### Component 3: Downstream Manager Enhancement

**Modify:** `internal/pkg/processor/downstream/manager.go`

**Add:**
1. Track processor IDs (not just addresses)
2. Establish bidirectional gRPC connections
3. Subscribe to downstream topology changes

```go
// Enhanced ProcessorInfo
type ProcessorInfo struct {
    ProcessorID   string
    ListenAddress string
    Version       string
    RegisteredAt  time.Time
    LastSeen      time.Time

    // gRPC clients
    Client     management.ManagementServiceClient
    DataClient data.DataServiceClient  // For future use
    Conn       *grpc.ClientConn

    // Topology subscription
    TopologyStream management.ManagementService_SubscribeTopologyClient
    TopologyCancel context.CancelFunc
}

// Subscribe to downstream processor topology
func (m *Manager) SubscribeToDownstream(proc *ProcessorInfo) error {
    ctx, cancel := context.WithCancel(context.Background())
    proc.TopologyCancel = cancel

    stream, err := proc.Client.SubscribeTopology(ctx, &management.TopologySubscribeRequest{
        IncludeDownstream: true,
        MinUpdateIntervalSec: 1,
    })
    if err != nil {
        return fmt.Errorf("failed to subscribe to topology: %w", err)
    }

    proc.TopologyStream = stream

    // Start receiving updates in goroutine
    go m.receiveTopologyUpdates(proc, stream)

    return nil
}
```

### Component 4: Hunter Manager Enhancement

**Modify:** `internal/pkg/processor/hunter/manager.go`

**Add:**
1. Publish topology events to proxy manager
2. Notify on hunter connect/disconnect
3. Notify on filter changes

```go
// Add event publisher
type Manager struct {
    // ... existing fields ...

    topologyPublisher TopologyPublisher
}

type TopologyPublisher interface {
    PublishHunterConnected(hunter *HunterInfo)
    PublishHunterDisconnected(hunterID string, reason string)
    PublishFilterUpdated(hunterID string, filter *management.Filter, updateType management.FilterUpdateType)
}

// Call publisher on events
func (m *Manager) handleHunterRegistration(hunterID string, reg *management.HunterRegistration) error {
    // ... existing registration logic ...

    // Publish event
    if m.topologyPublisher != nil {
        m.topologyPublisher.PublishHunterConnected(hunter)
    }

    return nil
}

func (m *Manager) removeHunter(hunterID string, reason string) {
    // ... existing removal logic ...

    // Publish event
    if m.topologyPublisher != nil {
        m.topologyPublisher.PublishHunterDisconnected(hunterID, reason)
    }
}
```

### Component 5: TUI Integration

**Modify:** `cmd/tui/capture_events.go`

**Changes:**
1. Subscribe to `SubscribeTopology()` instead of one-shot `GetTopology()`
2. Handle streaming topology updates
3. Support filter operations on any processor in hierarchy

```go
// Subscribe to topology stream (replaces one-shot GetTopology call)
func (m *Model) subscribeToProcessorTopology(client *remotecapture.Client, address string) tea.Cmd {
    return func() tea.Msg {
        ctx := context.Background()

        mgmtClient := management.NewManagementServiceClient(client.GetConn())
        stream, err := mgmtClient.SubscribeTopology(ctx, &management.TopologySubscribeRequest{
            IncludeDownstream:    true,
            MinUpdateIntervalSec: 1,
        })
        if err != nil {
            logger.Error("Failed to subscribe to topology",
                "processor", address,
                "error", err)
            return nil
        }

        // Start goroutine to receive updates
        go func() {
            for {
                update, err := stream.Recv()
                if err != nil {
                    logger.Error("Topology stream error",
                        "processor", address,
                        "error", err)
                    return
                }

                // Send update to TUI event loop
                currentProgram.Send(TopologyUpdateMsg{
                    ProcessorAddr: address,
                    Update:        update,
                })
            }
        }()

        return nil
    }
}

// Handle topology update message
func (m Model) handleTopologyUpdateMsg(msg TopologyUpdateMsg) (Model, tea.Cmd) {
    update := msg.Update

    switch update.UpdateType {
    case management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED:
        event := update.GetHunterConnected()
        // Add hunter to NodesView
        m.addHunterToView(event.ProcessorId, event.Hunter)

    case management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED:
        event := update.GetHunterDisconnected()
        // Remove hunter from NodesView
        m.removeHunterFromView(event.ProcessorId, event.HunterId)

    // ... handle other update types ...
    }

    return m, nil
}
```

**Modify:** `cmd/tui/filter_operations.go`

**Changes:**
1. Use `UpdateFilterOnProcessor()` instead of `UpdateFilter()`
2. Include target processor ID in request

```go
// executeFilterOperation with processor-scoped routing
func (m *Model) executeFilterOperation(msg components.FilterOperationMsg) tea.Cmd {
    return func() tea.Msg {
        // Get processor from connection manager
        // NOTE: Now we only need the ROOT processor connection
        rootProc := m.getRootProcessorForAddress(msg.ProcessorAddr)
        if rootProc == nil || rootProc.Client == nil {
            return components.FilterOperationResultMsg{
                Success: false,
                Error:   "root processor not connected",
            }
        }

        client, ok := rootProc.Client.(*remotecapture.Client)
        if !ok {
            return components.FilterOperationResultMsg{
                Success: false,
                Error:   "invalid client type",
            }
        }

        mgmtClient := management.NewManagementServiceClient(client.GetConn())
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        var result *management.FilterUpdateResult
        var err error

        switch msg.Operation {
        case "create", "update", "toggle":
            // Use processor-scoped RPC
            result, err = mgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
                ProcessorId: msg.ProcessorAddr,  // Target processor
                Filter:      msg.Filter,
            })

        case "delete":
            result, err = mgmtClient.DeleteFilterOnProcessor(ctx, &management.ProcessorFilterDeleteRequest{
                ProcessorId: msg.ProcessorAddr,
                FilterId:    msg.FilterID,
            })
        }

        // ... handle result ...
    }
}

// Get root processor for any processor address in hierarchy
func (m *Model) getRootProcessorForAddress(targetAddr string) *store.ProcessorConnection {
    // Walk up the hierarchy to find root (directly connected) processor
    current := targetAddr
    for {
        proc, exists := m.connectionMgr.Processors[current]
        if !exists {
            return nil
        }

        // If this processor has no upstream, it's the root
        if proc.UpstreamAddr == "" {
            return proc
        }

        // Walk up to parent
        current = proc.UpstreamAddr
    }
}
```

---

## Implementation Plan

### Phase 1: Protocol & Core Infrastructure (Week 1-2)

**Tasks:**
1. Define new gRPC messages and RPCs in `api/proto/management.proto`
2. Regenerate protobuf code (`make proto` or similar)
3. Create `internal/pkg/processor/proxy/` package structure
4. Implement `TopologyCache` for state management
5. Write unit tests for topology cache

**Deliverables:**
- Updated protobuf definitions
- Proxy package skeleton
- Topology cache implementation with tests

### Phase 2: Downstream Topology Subscription (Week 2-3)

**Tasks:**
1. Enhance `downstream.Manager` to subscribe to downstream processors
2. Implement `SubscribeTopology()` RPC handler in processor
3. Implement topology event publishing in `hunter.Manager`
4. Wire up event flow: hunter event → proxy → upstream subscribers
5. Integration tests for topology propagation

**Deliverables:**
- Topology events propagate from hunter through downstream processor to upstream
- Integration test: connect hunter, verify upstream receives event

### Phase 3: Management Operation Proxying (Week 3-4)

**Tasks:**
1. Implement `UpdateFilterOnProcessor()` RPC handler
2. Implement `DeleteFilterOnProcessor()` RPC handler
3. Add routing logic in proxy manager
4. Implement filter operation forwarding in downstream manager
5. Integration tests for filter management across hierarchy

**Deliverables:**
- Filter operations work across processor hierarchy
- Integration test: TUI → upstream processor → downstream processor → hunter

### Phase 4: TUI Integration (Week 4-5)

**Tasks:**
1. Replace `GetTopology()` call with `SubscribeTopology()` subscription
2. Implement topology update handler in TUI
3. Update filter operations to use processor-scoped RPCs
4. Update subscription management to use processor-scoped operations
5. Add UI indicators for hierarchical processors (depth, path)
6. End-to-end testing

**Deliverables:**
- TUI receives real-time topology updates
- TUI can manage hunters on any processor in hierarchy
- End-to-end test: 3-level hierarchy with filter management

### Phase 5: Performance & Reliability (Week 5-6)

**Tasks:**
1. Implement topology update batching (reduce network overhead)
2. Add retry logic for proxied operations
3. Implement topology cache TTL/cleanup
4. Performance testing with large hierarchies (10+ processors, 100+ hunters)
5. Network partition testing (downstream disconnect/reconnect)
6. Documentation updates

**Deliverables:**
- System handles 10+ processors, 100+ hunters efficiently
- Topology updates use <1% network bandwidth
- Documentation in `docs/DISTRIBUTED_MODE.md`

### Phase 6: Security Hardening (Week 6-7)

**Tasks:**
1. Audit proxied operations for security implications
2. Implement processor-level authorization checks
3. Add TLS certificate validation for downstream connections
4. Security testing: unauthorized access attempts
5. Security documentation

**Deliverables:**
- Security audit report
- Authorization layer for proxied operations
- Security documentation in `docs/SECURITY.md`

---

## Security Considerations

### Threat Model

**Threats:**
1. **Unauthorized Management**: Attacker gains TUI access to root processor, attempts to manage downstream hunters
2. **Man-in-the-Middle**: Attacker intercepts traffic between processors
3. **Replay Attacks**: Attacker replays captured management operations
4. **Topology Poisoning**: Attacker sends fake topology updates
5. **DoS via Topology Flood**: Attacker floods upstream with topology updates

### Mitigations

**M1: TLS/mTLS for All Connections**
- All processor-to-processor connections use TLS (existing)
- Validate certificates at each hop
- No plaintext transmission of management operations

**M2: Processor-Level Authorization**
```go
// Check if requester is authorized to manage target processor
func (m *Manager) authorizeOperation(ctx context.Context, targetProcessorID string, operation string) error {
    // Extract client certificate from context
    peer, ok := peer.FromContext(ctx)
    if !ok {
        return fmt.Errorf("no peer info in context")
    }

    tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
    clientCert := tlsInfo.State.PeerCertificates[0]

    // Check if client has permission for this processor
    if !m.authz.CanManage(clientCert, targetProcessorID, operation) {
        return fmt.Errorf("unauthorized: cannot %s on processor %s", operation, targetProcessorID)
    }

    return nil
}
```

**M3: Topology Update Authentication**
- Sign topology updates with processor certificate
- Verify signature at each hop
- Reject unsigned or invalid updates

**M4: Rate Limiting**
```go
// Rate limit topology updates per processor
type TopologyRateLimiter struct {
    limits map[string]*rate.Limiter  // processor_id -> limiter
}

func (trl *TopologyRateLimiter) Allow(processorID string) bool {
    limiter := trl.getLimiter(processorID)
    return limiter.Allow()  // e.g., 10 updates/sec
}
```

**M5: Operation Audit Logging**
- Log all proxied operations with full context:
  - Requester identity (from TLS cert)
  - Target processor ID
  - Target hunter ID
  - Operation type
  - Result (success/failure)
- Store audit logs for compliance/forensics

### Security Best Practices

1. **Principle of Least Privilege**: Only grant management access to processors that need it
2. **Defense in Depth**: Multiple layers of authorization (TLS + operation-level)
3. **Audit Everything**: All management operations logged
4. **Fail Secure**: On error, deny operation (don't fail open)
5. **Regular Security Reviews**: Quarterly review of proxy code and authorization logic

---

## Deep Chain Considerations

### Challenge: Arbitrary-Depth Processor Chains

The proposed architecture supports arbitrary-depth chains:
```
Hunter-1 → Processor-1 → Processor-2 → ... → Processor-N → TUI
```

However, deep chains introduce specific challenges that require careful handling.

### Latency Accumulation

**Problem:** Each hop adds latency.

**Latency Budget (per hop):**
- gRPC call overhead: ~50ms (local network)
- Filter operation processing: ~10ms
- Topology update propagation: ~20ms

**Example: 5-level chain**
```
TUI → P-5 → P-4 → P-3 → P-2 → P-1 → Hunter
      50ms  50ms  50ms  50ms  50ms
      = 250ms base latency (one-way)
```

**Mitigation Strategies:**

1. **Hard Limit on Depth:** Enforce maximum chain depth of 10 levels
   ```go
   const MaxHierarchyDepth = 10

   func (m *Manager) validateHierarchyDepth(depth int) error {
       if depth > MaxHierarchyDepth {
           return fmt.Errorf("hierarchy depth %d exceeds maximum %d", depth, MaxHierarchyDepth)
       }
       return nil
   }
   ```

2. **Latency Budget Tracking:** Include depth in topology metadata
   ```protobuf
   message ProcessorNode {
       // ... existing fields ...
       uint32 hierarchy_depth = 10;  // Distance from leaf (0 = leaf)
   }
   ```

3. **UI Warnings:** TUI shows latency estimate for deep operations
   ```
   ⚠️  Hunter is 7 levels deep - operations may take 3-5 seconds
   ```

4. **Timeout Scaling:** Scale operation timeouts with depth
   ```go
   timeout := baseTimeout + (time.Duration(depth) * perHopTimeout)
   // Example: 5s + (7 * 500ms) = 8.5s timeout for 7-level chain
   ```

**Recommended Limits:**
- **Optimal depth:** 1-3 levels (< 500ms latency)
- **Acceptable depth:** 4-7 levels (< 2s latency)
- **Maximum depth:** 10 levels (< 5s latency)
- **Beyond 10 levels:** Consider architectural redesign (hub-and-spoke, regional aggregation)

### Error Propagation in Chains

**Problem:** Mid-chain failures disconnect entire downstream subtree.

**Scenario:**
```
TUI → P-5 → P-4 → P-3 (NETWORK FAILURE) ✗
                    ↓
                  [P-2 → P-1 → Hunter] (orphaned subtree)
```

**Error Handling Strategy:**

1. **Operation Errors:** Return full chain context
   ```go
   type ChainError struct {
       ProcessorChain []string  // Full path: ["p-5", "p-4", "p-3"]
       FailedAt       string    // Which processor failed: "p-3"
       OriginalError  error     // Root cause
       Depth          int       // How deep in chain
   }
   ```

2. **Topology Disconnections:** Mark subtree as "unreachable"
   ```protobuf
   message ProcessorNode {
       // ... existing fields ...
       bool reachable = 11;           // False if upstream broken
       string unreachable_reason = 12; // "upstream processor-3 disconnected"
   }
   ```

3. **Automatic Recovery:** When mid-chain processor reconnects, trigger topology re-sync
   ```go
   func (m *Manager) onDownstreamReconnect(processorID string) {
       // Force full topology refresh for this subtree
       m.refreshTopologySubtree(processorID)

       // Notify upstream of reconnection
       m.publishTopologyUpdate(&management.TopologyUpdate{
           UpdateType: management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
           // ...
       })
   }
   ```

4. **Partial Failure Reporting:** For operations targeting multiple hunters in chain
   ```go
   type BulkOperationResult struct {
       Successful []string  // Hunter IDs that succeeded
       Failed     []string  // Hunter IDs that failed
       Errors     map[string]error  // hunter_id -> error
       ChainDepth map[string]int    // hunter_id -> depth (for latency analysis)
   }
   ```

### Cycle Detection

**Problem:** Misconfiguration could create cycles in processor graph.

**Detection Strategy:**

1. **Registration-Time Check:** Processor includes its upstream chain in registration
   ```protobuf
   message ProcessorRegistration {
       // ... existing fields ...
       repeated string upstream_chain = 10;  // IDs of all upstream processors
   }
   ```

2. **Validation Logic:**
   ```go
   func (m *Manager) validateNoCycle(newProcessorID string, upstreamChain []string) error {
       // Check if we're in the upstream chain (cycle detected)
       for _, upstreamID := range upstreamChain {
           if upstreamID == m.thisProcessorID {
               return fmt.Errorf("cycle detected: %s is already upstream of %s",
                   m.thisProcessorID, newProcessorID)
           }
       }
       return nil
   }
   ```

3. **Topology Query Protection:** Limit recursion depth
   ```go
   func (m *Manager) getTopologyRecursive(ctx context.Context, depth int, visited map[string]bool) (*management.ProcessorNode, error) {
       // Prevent infinite recursion
       if depth > MaxHierarchyDepth {
           return nil, fmt.Errorf("maximum hierarchy depth exceeded")
       }

       // Detect cycles via visited set
       if visited[m.thisProcessorID] {
           return nil, fmt.Errorf("cycle detected: %s already visited", m.thisProcessorID)
       }

       visited[m.thisProcessorID] = true
       // ... continue recursive query ...
   }
   ```

### Authentication and Authorization in Chains

**Problem:** How does a deep processor verify that TUI is authorized to manage its hunters?

**Challenge:**
```
TUI (authenticated to P-5)
  → P-5 (trusts TUI, forwards request)
    → P-4 (how to verify TUI's authority?)
      → P-3
        → P-2
          → P-1 (should this trust TUI?)
```

**Solution: Token-Based Authorization Chain**

1. **TUI Request Includes Auth Token:**
   ```protobuf
   message ProcessorFilterRequest {
       // ... existing fields ...

       // Authorization context (signed by root processor)
       AuthorizationToken auth_token = 10;
   }

   message AuthorizationToken {
       string requester_id = 1;      // TUI client ID
       string root_processor_id = 2; // Processor TUI connected to
       int64 issued_at = 3;          // Unix timestamp
       int64 expires_at = 4;         // TTL (e.g., 5 minutes)
       bytes signature = 5;          // HMAC(requester_id + root + timestamps)
   }
   ```

2. **Root Processor Issues Token:**
   ```go
   func (m *Manager) issueAuthToken(requesterID string) (*management.AuthorizationToken, error) {
       now := time.Now()
       token := &management.AuthorizationToken{
           RequesterId:      requesterID,
           RootProcessorId:  m.config.ProcessorID,
           IssuedAt:         now.Unix(),
           ExpiresAt:        now.Add(5 * time.Minute).Unix(),
       }

       // Sign token with processor's private key
       token.Signature = m.signToken(token)
       return token, nil
   }
   ```

3. **Each Processor Verifies Token:**
   ```go
   func (m *Manager) verifyAuthToken(token *management.AuthorizationToken) error {
       // Check expiration
       if time.Now().Unix() > token.ExpiresAt {
           return fmt.Errorf("token expired")
       }

       // Verify signature from root processor
       rootProcessor := m.getRootProcessorInfo(token.RootProcessorId)
       if !m.verifySignature(token, rootProcessor.PublicKey) {
           return fmt.Errorf("invalid token signature")
       }

       // Check authorization policy
       if !m.authz.IsAuthorized(token.RequesterId, token.RootProcessorId) {
           return fmt.Errorf("requester %s not authorized via %s",
               token.RequesterId, token.RootProcessorId)
       }

       return nil
   }
   ```

4. **Token Propagation:**
   ```go
   // Processor forwarding request downstream includes token
   resp, err := downstream.Client.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
       ProcessorId: req.ProcessorId,
       Filter:      req.Filter,
       AuthToken:   req.AuthToken,  // Propagate unchanged
   })
   ```

**Benefits:**
- ✅ End-to-end authentication (leaf processor knows TUI's identity)
- ✅ No need for processor-to-processor trust relationships
- ✅ Short-lived tokens (5-minute TTL) limit replay attack window
- ✅ Auditable (token includes requester identity)

**Limitations:**
- ⚠️ Root processor must be trusted by all downstream processors
- ⚠️ Token renewal needed for long-running operations
- ⚠️ Requires public key distribution mechanism

### Network Partition Handling

**Problem:** What happens when mid-chain processor loses connectivity?

**Scenario:**
```
[TUI → P-5 → P-4] ──✗ PARTITION ✗──→ [P-3 → P-2 → P-1 → Hunters]
      (visible)                        (invisible, but still capturing)
```

**Handling Strategy:**

1. **Graceful Degradation:**
   - TUI can still manage P-5 and P-4
   - P-3 subtree marked as "unreachable" in topology
   - Hunters continue capturing (data plane unaffected)

2. **Automatic Reconnection:**
   ```go
   // Downstream manager monitors connection health
   func (m *Manager) monitorDownstream(proc *ProcessorInfo) {
       ticker := time.NewTicker(30 * time.Second)
       defer ticker.Stop()

       for {
           select {
           case <-ticker.C:
               // Check if topology stream is alive
               if !proc.isHealthy() {
                   logger.Warn("Downstream processor unhealthy, reconnecting",
                       "processor", proc.ProcessorID)

                   // Attempt reconnection
                   if err := m.reconnectDownstream(proc); err != nil {
                       logger.Error("Reconnection failed", "error", err)
                       m.markSubtreeUnreachable(proc.ProcessorID)
                   } else {
                       m.refreshTopologySubtree(proc.ProcessorID)
                   }
               }
           }
       }
   }
   ```

3. **Split-Brain Prevention:**
   - Each processor tracks its upstream connection state
   - If upstream lost, processor continues operating but marks itself as "isolated"
   - When reconnecting, perform topology reconciliation

4. **Manual Override:**
   - TUI can connect directly to isolated subtree (if network accessible)
   - Useful for troubleshooting during partitions

### Performance Optimization for Deep Chains

**Techniques:**

1. **Request Pipelining:**
   - Don't wait for operation to complete at each hop
   - Forward request immediately while processing locally
   ```go
   // Parallel: forward downstream + process locally
   downstreamFuture := m.forwardToDownstream(req)
   localResult := m.processLocally(req)
   downstreamResult := downstreamFuture.Wait()
   return aggregate(localResult, downstreamResult)
   ```

2. **Topology Update Batching:**
   - Batch multiple topology changes into single update
   - Reduce per-update overhead in deep chains
   ```go
   type TopologyUpdateBatcher struct {
       updates  []*management.TopologyUpdate
       maxSize  int
       maxDelay time.Duration
   }

   func (b *TopologyUpdateBatcher) Add(update *management.TopologyUpdate) {
       b.updates = append(b.updates, update)
       if len(b.updates) >= b.maxSize {
           b.Flush()
       }
   }
   ```

3. **Streaming Response Aggregation:**
   - For operations affecting many hunters, stream results back as they arrive
   - Don't wait for entire chain to complete
   ```go
   // Stream results back to TUI as hunters respond
   for hunterResult := range resultStream {
       stream.Send(&management.FilterUpdateProgress{
           HunterId: hunterResult.HunterID,
           Success:  hunterResult.Success,
           Error:    hunterResult.Error,
       })
   }
   ```

4. **Smart Topology Caching:**
   - Cache topology at each level (TTL: 60 seconds)
   - Only query downstream on cache miss or explicit refresh
   - Reduces repeated queries in deep chains

### Monitoring and Observability

**Metrics for Deep Chains:**

1. **Chain Depth Distribution:**
   ```
   hierarchy_depth{processor="p-5"} 5
   hierarchy_depth{processor="p-1"} 1
   ```

2. **Operation Latency by Depth:**
   ```
   operation_latency_seconds{operation="UpdateFilter",depth="3"} 0.15
   operation_latency_seconds{operation="UpdateFilter",depth="7"} 0.35
   ```

3. **Chain Health:**
   ```
   chain_broken_count{root="p-5"} 0
   chain_broken_count{root="p-3"} 1  # P-3 lost connection to P-2
   ```

4. **Topology Update Propagation Time:**
   ```
   topology_update_propagation_seconds{depth="5"} 0.12
   ```

**Alerting:**
- Alert when chain depth > 7 (latency concern)
- Alert when chain breaks (connectivity issue)
- Alert when propagation time > 2s (performance degradation)

---

## Alternative Approaches

### Alternative 1: Direct TUI Connections to All Processors

**Description:** TUI establishes gRPC connections to every processor in the hierarchy.

**Pros:**
- Simpler implementation (no proxying)
- Direct communication reduces latency
- No single point of failure

**Cons:**
- Breaks hierarchical security model (TUI must reach all processors)
- Complex connection management in TUI
- Doesn't scale with large hierarchies (connection overhead)
- TUI must handle authentication to every processor
- Topology discovery still needed

**Verdict:** ❌ Rejected - Breaks security boundaries and doesn't scale

### Alternative 2: Central Management Plane (Separate Service)

**Description:** Dedicated management service that all processors register with.

**Pros:**
- Clean separation of data plane and control plane
- Single source of truth for topology
- Can use different protocols (REST, gRPC-web)

**Cons:**
- Requires additional infrastructure component
- Single point of failure (needs HA setup)
- More complex deployment
- Still needs hierarchical awareness

**Verdict:** 🤔 Consider for future - Good for large deployments, overkill for current scale

### Alternative 3: Polling-Based Topology Discovery

**Description:** Keep current one-shot `GetTopology()`, have TUI poll periodically.

**Pros:**
- Minimal code changes
- Simple implementation
- Works with existing infrastructure

**Cons:**
- Stale topology (polling interval delay)
- Unnecessary network traffic (polling when no changes)
- Still doesn't solve management operation proxying
- Doesn't scale with hierarchy depth

**Verdict:** ❌ Rejected - Doesn't meet real-time requirement, doesn't solve core issue

### Alternative 4: Event-Driven Architecture with Message Queue

**Description:** Use message queue (NATS, Kafka) for topology events.

**Pros:**
- Decouples components
- Built-in reliability (message persistence)
- Excellent scalability
- Publish-subscribe model fits well

**Cons:**
- Requires external dependency (message broker)
- Adds operational complexity
- Overkill for current scale
- Still need gRPC for synchronous operations

**Verdict:** 🤔 Consider for future - Great for very large scale (1000+ hunters)

---

## Open Questions

### Q1: How deep should we support hierarchies?

**Options:**
- **A:** Arbitrary depth (current proposal)
- **B:** Fixed maximum depth (e.g., 5 levels)
- **C:** Two-level only (hub-and-spoke)

**Recommendation:** Start with fixed maximum (5 levels), test with 3 levels initially. Add recursion limit to prevent infinite loops.

### Q2: Should topology updates be guaranteed-delivery or best-effort?

**Options:**
- **A:** Best-effort (dropped updates acceptable, eventual consistency)
- **B:** Guaranteed-delivery (buffering, acknowledgments, retries)

**Recommendation:** Start with best-effort (simpler), add explicit `RefreshTopology()` RPC for manual sync. Monitor in production, add guaranteed-delivery if needed.

### Q3: How should we handle topology update conflicts?

**Example:** Hunter connects to downstream processor, but upstream still has stale "disconnected" state.

**Options:**
- **A:** Last-write-wins (timestamp-based)
- **B:** Downstream authoritative (downstream state always wins)
- **C:** Versioned updates (reject older versions)

**Recommendation:** Downstream authoritative (B) - downstream processor is source of truth for its hunters. Add sequence numbers for debugging.

### Q4: Should filters created at upstream automatically apply to downstream hunters?

**Example:** TUI creates filter on upstream processor with `target_hunters=[]` (all hunters). Should it apply to downstream hunters?

**Options:**
- **A:** Yes, automatically propagate to all downstream hunters
- **B:** No, only apply to local hunters (explicit targeting required)
- **C:** Configurable per filter (new flag: `propagate_downstream`)

**Recommendation:** Start with (B) for safety (explicit is better than implicit). Can add (C) in future release.

### Q5: How should we handle partial failures in hierarchy?

**Example:** Filter update succeeds on 3/5 downstream processors, fails on 2.

**Options:**
- **A:** Return partial success (list successes and failures)
- **B:** All-or-nothing (rollback on any failure)
- **C:** Best-effort (ignore failures, log them)

**Recommendation:** Return partial success (A) with detailed error info. TUI shows warning, user can retry failed processors. Add `--force` flag for best-effort mode.

### Q6: Should we support topology subscriptions at different hierarchy levels?

**Example:** Can TUI subscribe to just one downstream processor's topology (not full hierarchy)?

**Options:**
- **A:** Always full hierarchy (recursive)
- **B:** Support filtered subscriptions (`processor_id_filter`)
- **C:** Support depth limiting (`max_depth`)

**Recommendation:** Start with (A) - full hierarchy always. Add filtering in future if needed (reduces complexity initially).

### Q7: How should we handle processor reconnections in topology?

**Example:** Downstream processor disconnects and reconnects. Should upstream send full topology re-sync or just "reconnected" event?

**Options:**
- **A:** Full re-sync on reconnect (send all hunters again)
- **B:** Incremental updates only (assume upstream cached state)
- **C:** Hybrid (send lightweight "still connected" heartbeat with hunter count, full sync on mismatch)

**Recommendation:** Full re-sync (A) initially - simpler and more robust. Optimize later if network overhead becomes issue.

---

## Success Criteria

### Functional Success

✅ **SC1:** TUI connected to root processor can manage filters on hunters 3 levels deep
✅ **SC2:** New hunter connecting to downstream processor appears in TUI within 2 seconds
✅ **SC3:** Hunter disconnecting from downstream processor removed from TUI within 2 seconds
✅ **SC4:** Filter created at root processor propagates to targeted downstream hunters
✅ **SC5:** Subscription changes work across hierarchy levels

### Performance Success

✅ **SC6:** Topology updates consume <1% network bandwidth (1 Gbps link)
✅ **SC7:** Proxied filter operations complete within 5 seconds (3-level hierarchy)
✅ **SC8:** System handles 100 hunters across 10 processors with <100ms latency

### Reliability Success

✅ **SC9:** Downstream processor reconnection restores topology automatically
✅ **SC10:** Network partition (1 minute) recovers without manual intervention
✅ **SC11:** No topology updates lost during normal operation (99.9% delivery)

### Security Success

✅ **SC12:** All proxied operations authenticated via TLS/mTLS
✅ **SC13:** Unauthorized management attempts logged and rejected
✅ **SC14:** Topology updates verified for authenticity

---

## Conclusion

The current lippycat architecture successfully implements **topology discovery** but lacks **management operation proxying** and **real-time topology updates**. This research document proposes:

1. **Streaming topology updates** via `SubscribeTopology()` RPC
2. **Processor-scoped management operations** via `UpdateFilterOnProcessor()` family of RPCs
3. **Transparent proxy layer** in upstream processors to route operations downstream
4. **Event-driven topology propagation** from hunters through processor hierarchy to TUI

This design maintains the hierarchical security model, scales to arbitrary depth, and provides real-time visibility and control across the entire distributed system.

**Recommended Next Steps:**
1. Review this design with team
2. Prototype Phase 1 (protocol definitions)
3. Build proof-of-concept with 2-level hierarchy
4. Iterate based on performance/usability feedback
5. Proceed with full implementation

**Estimated Effort:** 6-7 weeks for full implementation and testing
**Risk Level:** Medium (significant architectural changes, requires careful testing)
**Priority:** High (critical for usability of distributed deployments)
