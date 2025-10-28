# internal/pkg/processor/proxy - Hierarchical Management Proxy

## Overview

This package implements hierarchical management capabilities for the lippycat distributed architecture, enabling multi-level processor topologies with transparent operation proxying and real-time topology updates.

## Architecture

### Hierarchy Example

```
TUI → Processor A (root)
        ├─ Hunter 1, Hunter 2
        └─ Processor B (downstream) ← TRANSPARENT PROXY
            ├─ Hunter 3, Hunter 4
            └─ Processor C (deeper downstream)
                └─ Hunter 5, Hunter 6
```

### Key Components

**Manager**: Coordinates topology subscription and operation proxying. Maintains the topology cache and handles authorization token lifecycle.

**TopologyCache**: Thread-safe in-memory cache of the complete hierarchy topology. Applies streaming topology updates and provides snapshot queries.

**Authorization**: Token-based authorization for deep chains. Each hop verifies tokens signed by the root processor to ensure secure operation proxying.

## Topology Updates

Processors subscribe to downstream topology changes via the `SubscribeTopology()` gRPC stream. Updates flow from leaf hunters up through the processor chain:

```
Hunter connects → Downstream Processor publishes HunterConnectedEvent →
Upstream Processor receives update → Cache updated → Re-broadcast to TUI
```

### Event Flow

1. Event occurs on downstream processor (hunter connect, filter update, etc.)
2. Downstream processor publishes `TopologyUpdate` message
3. Upstream processor receives update via gRPC stream
4. Upstream applies update to its `TopologyCache`
5. Upstream re-broadcasts to its subscribers (TUI clients, further upstream processors)

## Operation Proxying

Management operations (`UpdateFilter`, `DeleteFilter`, `GetFilters`) can target any processor in the hierarchy. The root processor routes requests through the chain transparently:

```
TUI sends UpdateFilterOnProcessor(targetID) → Root Processor checks if local →
If not local, find downstream processor → Forward request via gRPC →
Downstream repeats routing → Target processor executes operation
```

### Routing Logic

1. Check if target processor is this processor (handle directly)
2. If not, look up target in topology cache
3. Determine which downstream processor is on the path to target
4. Forward request to that downstream processor
5. Downstream processor repeats routing until target reached

## Authorization Model

Deep chains use authorization tokens to prevent unauthorized access:

- Root processor issues tokens signed with its TLS certificate
- Each hop verifies token signature and expiration (5-minute TTL)
- Failed verification rejects the operation
- All authorization attempts are audit logged

### Token Lifecycle

1. TUI requests operation on downstream hunter
2. TUI requests auth token from root processor for target
3. Root processor signs token with its TLS private key
4. TUI includes token in operation request
5. Each hop verifies token signature and expiration
6. Target processor executes operation after successful verification

## Failure Handling

Network partitions and processor failures are handled gracefully:

- Automatic topology stream reconnection with exponential backoff
- Subtrees marked as "unreachable" during partitions
- Full topology re-sync on reconnection
- Detailed chain error context for debugging

## Performance Considerations

- Topology updates are batched (100ms window, max 10 updates)
- Slow subscribers are dropped to prevent backpressure
- Operation timeouts scale with chain depth (5s + 500ms per hop)
- Maximum hierarchy depth: 10 levels (configurable)

## Thread Safety

All public methods are thread-safe:

- `TopologyCache` uses `RWMutex` for concurrent reads
- Event broadcasting uses buffered channels with non-blocking sends
- Subscriber map protected by `sync.RWMutex`

## Usage Example

```go
// Create proxy manager
mgr := proxy.NewManager(logger, "processor-a")

// Configure TLS credentials for token signing
mgr.SetTLSCredentials(certPEM, keyPEM)

// Subscribe to downstream processor topology
mgr.SubscribeToDownstream(downstreamConn, "processor-b")

// Handle topology updates from downstream
for update := range topologyUpdateChan {
    mgr.ApplyTopologyUpdate(update)
}

// Proxy filter operation to downstream hunter
token, err := mgr.IssueAuthToken("processor-b")
if err != nil {
    return err
}
result, err := mgr.ProxyFilterOperation("processor-b", "hunter-3", filter, token)
```

## Files

- `manager.go`: Main proxy manager with subscriber management and coordination
- `topology_cache.go`: Thread-safe topology cache with update application
- `auth.go`: Authorization token generation and verification

## Implementation Status

- [x] Package structure created (Phase 1, Task 1.6)
- [ ] TopologyCache implementation (Phase 1, Task 1.7)
- [ ] Authorization token system (Phase 1, Task 1.9)
- [ ] Topology subscription (Phase 2)
- [ ] Operation proxying (Phase 3)
