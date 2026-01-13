# TAP Node Virtual Hunter Research

**Date:** 2025-01-13
**Status:** Research
**Goal:** Display TAP node capture statistics in TUI using existing hunter infrastructure

## Problem Statement

TAP nodes capture packets locally (like hunters do) but currently don't display capture statistics in the TUI nodes tab. Hunters show stats like packets captured, forwarded, uptime, etc. TAP nodes should show the same.

## Proposed Solution

Create a "virtual hunter" that represents the TAP node's local capture. This synthetic hunter would:
- Appear in the hunter list under the TAP node
- Display statistics from `LocalSource.Stats()`
- Use existing TUI hunter rendering (no UI changes needed)
- Have ID format: `{processor-id}-local`

## Architecture Analysis

### Hunter Data Flow

Hunter information flows through three main gRPC methods:

| Method | File | Lines | Used By |
|--------|------|-------|---------|
| `GetTopology()` | processor_grpc_handlers.go | 440-502 | TUI NodesView |
| `GetHunterStatus()` | processor_grpc_handlers.go | 281-313 | CLI `show hunters` |
| `ListAvailableHunters()` | processor_grpc_handlers.go | 315-341 | TUI HunterSelector |

All three would need virtual hunter injection for consistency.

### Hunter Manager

The hunter manager (`internal/pkg/processor/hunter/manager.go`) tracks connected hunters:

```go
type ConnectedHunter struct {
    ID              string
    Hostname        string
    RemoteAddr      string
    Interfaces      []string
    Capabilities    *management.HunterCapabilities
    ConnectedAt     int64
    LastHeartbeat   int64
    PacketsReceived uint64
    Status          management.HunterStatus
    // ... stats fields
}
```

**Key insight:** The manager expects hunters to send heartbeats. Virtual hunter cannot do this.

### LocalSource Statistics

TAP nodes already track capture stats via `LocalSource` (`internal/pkg/processor/source/local.go`):

```go
type Stats struct {
    PacketsReceived uint64
    PacketsDropped  uint64
    BytesReceived   uint64
    BatchesReceived uint64
    LastPacketTime  time.Time
    StartTime       time.Time
}
```

These map directly to hunter stats fields.

## Potential Issues

### 1. Heartbeat Timeout Cleanup

**Risk:** HIGH
**Location:** `hunter/manager.go:267-375`

The manager marks hunters as ERROR after heartbeat timeout, then removes them after grace period:

```
MarkStale(timeout=3min) → STATUS_ERROR → RemoveStale(grace=5min) → deleted
```

**Problem:** Virtual hunter never sends heartbeats, would be marked ERROR and removed.

**Solution:** Don't add virtual hunter to the manager. Synthesize it only in gRPC response methods.

### 2. Filter Distribution

**Risk:** MEDIUM
**Location:** `processor_grpc_handlers.go:224-278`

Filter updates are distributed to hunters via gRPC channels. Virtual hunter has no gRPC connection.

**Problem:** Filter manager would try to send updates to non-existent channel.

**Solution:** Skip adding virtual hunter to filter distribution. TAP nodes apply filters via `LocalTarget` directly.

### 3. TUI Hunter Subscription

**Risk:** LOW
**Location:** TUI subscribes to specific hunters via `has_hunter_filter`

**Problem:** User might try to unsubscribe from virtual hunter.

**Solution:** Virtual hunter should be included in packet routing. LocalSource batches need matching hunter ID.

### 4. Packet Batch Source ID

**Risk:** MEDIUM
**Location:** `source/local.go:407-409`

Currently `LocalSource.SourceID()` returns `"local"`. For virtual hunter to work:

```go
func (s *LocalSource) SourceID() string {
    return "local"  // Current
    // Needs to return: "{processor-id}-local"
}
```

**Solution:** Pass processor ID to LocalSource config, use for SourceID.

### 5. Mode Detection (VoIP vs Generic)

**Risk:** LOW
**Location:** `nodesview/rendering.go:69-84`

`IsVoIPHunter()` checks capabilities for "sip_user" filter type:

```go
func IsVoIPHunter(capabilities *management.HunterCapabilities) bool {
    for _, ft := range capabilities.FilterTypes {
        if ft == "sip_user" {
            return true
        }
    }
    return false
}
```

**Solution:** Set capabilities based on whether TAP has VoIP processor configured.

## Implementation Strategy

### Recommended Approach: Response-Level Injection

Synthesize virtual hunter **only in gRPC response methods**, not in the hunter manager:

```
GetTopology()         → inject virtual hunter in response
GetHunterStatus()     → inject virtual hunter in response
ListAvailableHunters() → inject virtual hunter in response
```

This avoids:
- Heartbeat monitoring issues
- Filter distribution complications
- Manager state complexity

### Required Changes

#### 1. Processor Method: `synthesizeVirtualHunter()`

New method to create synthetic hunter from LocalSource stats:

```go
func (p *Processor) synthesizeVirtualHunter() *management.ConnectedHunter {
    if !p.IsLocalMode() {
        return nil
    }

    localSource := p.packetSource.(*source.LocalSource)
    stats := localSource.Stats()

    return &management.ConnectedHunter{
        HunterId:         p.config.ProcessorID + "-local",
        Hostname:         hostname.Get(),  // Local hostname
        Status:           management.HunterStatus_HUNTER_STATUS_HEALTHY,
        ConnectedAt:      stats.StartTime.UnixNano(),
        LastHeartbeat:    time.Now().UnixNano(),
        PacketsCaptured:  stats.PacketsReceived,
        PacketsForwarded: stats.PacketsReceived,  // All captured = forwarded for local
        PacketsDropped:   stats.PacketsDropped,
        Interfaces:       localSource.Interfaces(),
        Capabilities:     p.getLocalCapabilities(),
    }
}
```

#### 2. Update Response Methods

Inject virtual hunter in:
- `GetTopology()` (line ~466)
- `GetHunterStatus()` (line ~305)
- `ListAvailableHunters()` (line ~335)

#### 3. LocalSource SourceID

Update to use processor-derived ID:

```go
// Config addition
type LocalSourceConfig struct {
    // ... existing fields
    ProcessorID string  // For virtual hunter ID
}

func (s *LocalSource) SourceID() string {
    if s.config.ProcessorID != "" {
        return s.config.ProcessorID + "-local"
    }
    return "local"
}
```

#### 4. Capabilities for VoIP Mode

```go
func (p *Processor) getLocalCapabilities() *management.HunterCapabilities {
    caps := &management.HunterCapabilities{
        FilterTypes: []string{},
    }

    if p.hasVoIPProcessor() {
        caps.FilterTypes = append(caps.FilterTypes, "sip_user", "phone_number")
    }

    return caps
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `internal/pkg/processor/processor.go` | Add `synthesizeVirtualHunter()`, `getLocalCapabilities()` |
| `internal/pkg/processor/processor_grpc_handlers.go` | Inject virtual hunter in 3 response methods |
| `internal/pkg/processor/source/local.go` | Update `SourceID()` to use processor ID |
| `internal/pkg/processor/source/source.go` | Add `ProcessorID` to `LocalSourceConfig` |
| `cmd/tap/tap.go` or similar | Pass processor ID to LocalSource config |

## What Does NOT Need to Change

- Proto definitions (no new fields needed)
- TUI components (existing hunter rendering works)
- Hunter manager (virtual hunter not added to manager)
- Filter distribution (skipped for virtual hunter)

## Open Questions

1. **Should virtual hunter appear in remote TUI connections?**
   - Currently: Yes, via GetTopology()
   - Consideration: Makes sense, shows TAP capture stats to remote viewers

2. **Should virtual hunter be selectable in hunter subscription?**
   - Currently: Yes, appears in ListAvailableHunters()
   - Consideration: Useful for filtering to only local capture

3. **What if ProcessorID is empty?**
   - Fallback to "tap-local" or similar
   - Should be rare in practice

## Conclusion

The virtual hunter approach is **feasible with moderate complexity**. The key insight is to synthesize the virtual hunter only in response methods, avoiding the heartbeat/manager complications entirely.

Estimated changes: ~100-150 lines across 4-5 files, no proto changes, no TUI changes.
