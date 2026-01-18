# Node CPU and RAM Statistics Research

**Date:** 2026-01-18
**Status:** Research
**Goal:** Display CPU and RAM usage for nodes in the TUI nodes tab

## Problem Statement

The TUI nodes tab currently displays packet statistics (captured, forwarded, filters, uptime) but lacks system resource metrics. Adding CPU and RAM usage would help operators:
- Identify resource-constrained nodes
- Detect memory leaks or runaway CPU usage
- Make informed decisions about node placement and scaling

## Current Architecture

### Data Flow Overview

```
Hunter Node                    Processor Node                 TUI Client
    │                              │                              │
    │ HunterHeartbeat              │                              │
    │ (includes HunterStats)       │                              │
    ├─────────────────────────────→│                              │
    │                              │ GetTopology()                │
    │                              │ GetHunterStatus()            │
    │                              │←─────────────────────────────┤
    │                              │ ConnectedHunter              │
    │                              │ (includes HunterStats)       │
    │                              ├─────────────────────────────→│
    │                              │                              │
```

TAP nodes use a virtual hunter that is synthesized from `LocalSource` stats:

```
TAP Node (Processor + Local Capture)
    │
    │ SynthesizeVirtualHunter()
    │ (builds ConnectedHunter from LocalSource.Stats())
    ├───────────────────────────────────────────────────→ TUI Client
```

### Protocol Buffer Definitions

**File:** `api/proto/management.proto`

```protobuf
// Lines 193-212
message HunterStats {
    uint64 packets_captured = 1;
    uint64 packets_matched = 2;
    uint64 packets_forwarded = 3;
    uint64 packets_dropped = 4;
    uint64 buffer_bytes = 5;
    uint32 active_filters = 6;
    // No CPU/RAM fields currently
}

// Lines 460-490
message ConnectedHunter {
    string hunter_id = 1;
    string hostname = 2;
    HunterStatus status = 3;
    uint64 connected_duration_sec = 4;
    int64 last_heartbeat_ns = 5;
    HunterStats stats = 6;           // ← Stats included here
    repeated string interfaces = 7;
    HunterCapabilities capabilities = 8;
}
```

### Hunter Stats Collection

**File:** `internal/pkg/hunter/stats/collector.go`

Current atomic fields (lines 1-95):
- `packetsCaptured`
- `packetsMatched`
- `packetsForwarded`
- `packetsDropped`
- `bufferBytes`
- `activeFilters`

The `ToProto()` method (lines 85-94) converts these to `management.HunterStats`.

### TAP Virtual Hunter

**File:** `internal/pkg/processor/processor.go`

The `SynthesizeVirtualHunter()` method (lines 536-590) creates a synthetic `ConnectedHunter` from `LocalSource` stats:

```go
func (p *Processor) SynthesizeVirtualHunter() *management.ConnectedHunter {
    localSource, ok := p.packetSource.(*source.LocalSource)
    // ...
    stats := localSource.Stats()
    // ...
    return &management.ConnectedHunter{
        HunterId: p.config.ProcessorID + "-local",
        Stats: &management.HunterStats{
            PacketsCaptured:  stats.PacketsCaptured,
            PacketsForwarded: stats.PacketsForwarded,
            PacketsDropped:   stats.PacketsDropped,
            ActiveFilters:    activeFilters,
        },
        // ...
    }
}
```

### LocalSource Stats

**File:** `internal/pkg/processor/source/source.go`

```go
// Lines 70-85
type Stats struct {
    PacketsCaptured  uint64
    PacketsForwarded uint64
    PacketsDropped   uint64
    BytesReceived    uint64
    BatchesReceived  uint64
    LastPacketTime   time.Time
    StartTime        time.Time
    // No CPU/RAM fields
}
```

### TUI Display

**File:** `internal/pkg/tui/components/nodesview/table_view.go`

Current columns (lines 369-378):
1. Status (S) - 1 char
2. Hunter ID - variable
3. Mode - 8 chars
4. IP Address - variable
5. Uptime - variable
6. Captured - variable
7. Forwarded - variable
8. Filters - variable

**File:** `internal/pkg/tui/components/nodesview/rendering.go`

`ColumnWidthCalculator` (lines 259-318) manages responsive column widths with minimum and preferred values.

### Shared Types

**File:** `internal/pkg/types/packet.go`

```go
// Lines 264-281
type HunterInfo struct {
    ID               string
    Hostname         string
    RemoteAddr       string
    Status           management.HunterStatus
    ConnectedAt      int64
    LastHeartbeat    int64
    PacketsCaptured  uint64
    PacketsMatched   uint64
    PacketsForwarded uint64
    PacketsDropped   uint64
    ActiveFilters    uint32
    Interfaces       []string
    ProcessorAddr    string
    Capabilities     *management.HunterCapabilities
    // No CPU/RAM fields
}
```

### CLI Commands (lc show)

The CLI commands `lc show topology`, `lc show hunters`, and `lc show status` output JSON via the `statusclient` package.

**File:** `internal/pkg/statusclient/json.go`

```go
// Lines 35-42
type HunterStatsJSON struct {
    PacketsCaptured  uint64 `json:"packets_captured"`
    PacketsMatched   uint64 `json:"packets_matched"`
    PacketsForwarded uint64 `json:"packets_forwarded"`
    PacketsDropped   uint64 `json:"packets_dropped"`
    BufferBytes      uint64 `json:"buffer_bytes"`
    ActiveFilters    uint32 `json:"active_filters"`
    // No CPU/RAM fields
}
```

The `hunterToJSON()` function (lines 112-143) maps proto fields to these JSON structures.

**Commands affected:**
- `lc show hunters` - Lists hunters with stats
- `lc show topology` - Shows full topology tree including hunter stats
- `lc show status` - Shows processor summary (no hunter details)

## System Metrics Collection

### Go Runtime (Memory Only)

Go's `runtime` package provides memory statistics:

```go
var m runtime.MemStats
runtime.ReadMemStats(&m)
// m.Alloc - bytes allocated and still in use
// m.Sys - bytes obtained from system
// m.HeapAlloc - bytes in heap objects
```

**Limitation:** No CPU usage. Memory is Go heap only, not RSS.

### /proc Filesystem (Linux)

For accurate process metrics on Linux:

**CPU:** `/proc/self/stat` - parse utime + stime, calculate percentage over interval
**Memory:** `/proc/self/status` - VmRSS field for resident set size

```go
// Example: Read RSS from /proc/self/status
func getRSSBytes() (uint64, error) {
    data, err := os.ReadFile("/proc/self/status")
    // Parse "VmRSS:" line, convert kB to bytes
}
```

### gopsutil Library

`github.com/shirou/gopsutil` provides cross-platform system metrics:

```go
import "github.com/shirou/gopsutil/v3/process"

proc, _ := process.NewProcess(int32(os.Getpid()))
cpuPercent, _ := proc.CPUPercent()  // Requires interval
memInfo, _ := proc.MemoryInfo()     // RSS, VMS, etc.
```

**Pros:** Cross-platform (Linux, macOS, Windows), well-tested
**Cons:** Additional dependency (~2MB binary increase), CGo on some platforms

### Recommendation

For a security-focused tool that primarily targets Linux:

1. **Primary:** Direct `/proc` parsing for Linux (no dependencies)
2. **Fallback:** `runtime.ReadMemStats()` for non-Linux or when /proc unavailable
3. **CPU:** Calculate from `/proc/self/stat` utime+stime delta over 1-second intervals

This approach:
- Adds no external dependencies
- Provides accurate RSS (not just Go heap)
- Works on all Linux deployments (the primary target platform)

## Implementation Layers

### Layer 1: Protocol Buffer Changes

**File:** `api/proto/management.proto`

Add to `HunterStats` message:
```protobuf
message HunterStats {
    // ... existing fields 1-6
    float cpu_percent = 7;      // CPU usage percentage (0-100)
    uint64 memory_rss_bytes = 8; // Resident set size in bytes
    uint64 memory_limit_bytes = 9; // Optional: cgroup memory limit
}
```

**Backward Compatibility:** Proto3 default values (0) for missing fields. Old hunters report 0, new hunters report actual values. TUI can detect "not available" by checking if both CPU and memory are 0.

### Layer 2: Hunter Metrics Collection

**New File:** `internal/pkg/hunter/stats/sysmetrics.go`

```go
type SystemMetrics struct {
    CPUPercent      float64
    MemoryRSSBytes  uint64
    MemoryLimitBytes uint64
}

type SystemMetricsCollector interface {
    Collect() SystemMetrics
    Start(ctx context.Context, interval time.Duration)
    Stop()
}
```

**Modify:** `internal/pkg/hunter/stats/collector.go`
- Add atomic fields for CPU/memory
- Update `ToProto()` to include new fields
- Optionally embed `SystemMetricsCollector`

**Modify:** `internal/pkg/hunter/hunter.go`
- Start metrics collection goroutine alongside heartbeat loop

### Layer 3: TAP/LocalSource Metrics

**Modify:** `internal/pkg/processor/source/source.go`
- Add CPU/memory fields to `Stats` struct
- Add fields to `AtomicStats`

**Modify:** `internal/pkg/processor/source/local.go`
- Start metrics collection goroutine in `Start()`
- Update stats periodically

**Modify:** `internal/pkg/processor/processor.go`
- Include CPU/memory in `SynthesizeVirtualHunter()` at line 581-586

### Layer 4: Shared Types

**Modify:** `internal/pkg/types/packet.go`

Add to `HunterInfo`:
```go
type HunterInfo struct {
    // ... existing fields
    CPUPercent       float64  // 0-100
    MemoryRSSBytes   uint64
    MemoryLimitBytes uint64
}
```

### Layer 5: Proto-to-Type Conversion

**Modify:** `internal/pkg/remotecapture/client_conversion.go`

Map proto fields to `HunterInfo`:
```go
CPUPercent:       hunter.Stats.CpuPercent,
MemoryRSSBytes:   hunter.Stats.MemoryRssBytes,
MemoryLimitBytes: hunter.Stats.MemoryLimitBytes,
```

### Layer 6: CLI JSON Output

**Modify:** `internal/pkg/statusclient/json.go`

Add to `HunterStatsJSON`:
```go
type HunterStatsJSON struct {
    // ... existing fields
    CPUPercent       float64 `json:"cpu_percent"`
    MemoryRSSBytes   uint64  `json:"memory_rss_bytes"`
    MemoryLimitBytes uint64  `json:"memory_limit_bytes,omitempty"`
}
```

Update `hunterToJSON()` to map proto fields:
```go
if h.Stats != nil {
    hunter.Stats = &HunterStatsJSON{
        // ... existing fields
        CPUPercent:       float64(h.Stats.CpuPercent),
        MemoryRSSBytes:   h.Stats.MemoryRssBytes,
        MemoryLimitBytes: h.Stats.MemoryLimitBytes,
    }
}
```

This ensures `lc show hunters` and `lc show topology` include CPU/RAM in JSON output.

### Layer 7: TUI Display

**Modify:** `internal/pkg/tui/components/nodesview/rendering.go`

Add formatting helpers:
```go
func FormatCPU(percent float64) string {
    if percent < 0 {
        return "N/A"
    }
    return fmt.Sprintf("%.1f%%", percent)
}

func FormatMemory(bytes uint64) string {
    // Use existing K/M/G formatting pattern
}
```

Update `ColumnWidthCalculator`:
- Add CPU column (min: 5, preferred: 6) - "99.9%"
- Add RAM column (min: 5, preferred: 6) - "1.2G"

**Modify:** `internal/pkg/tui/components/nodesview/table_view.go`

Update header and row rendering:
```
S Hunter ID    Mode     Host          CPU    RAM   Captured Forwarded Filters
● pie          VoIP     192.168.4.1  12.5%  245M  389.8K   389.8K    0
```

**Modify:** `internal/pkg/tui/components/nodesview/graph_view.go`

Update hunter box rendering to include CPU/RAM lines.

## Potential Issues

### 1. Metrics Collection Overhead

**Risk:** LOW

CPU percentage calculation requires sampling over time (typically 1 second). This adds minimal overhead but requires a background goroutine.

**Mitigation:** Collect metrics at heartbeat interval (default 5 seconds), not more frequently.

### 2. Cross-Platform Support

**Risk:** MEDIUM

Direct `/proc` parsing only works on Linux. Hunters/TAP nodes on macOS or Windows would need alternative implementations.

**Mitigation:**
- Abstract behind interface with platform-specific implementations
- Fall back to `runtime.ReadMemStats()` for memory-only on non-Linux
- Return -1 or 0 for unavailable metrics

### 3. Container Environments

**Risk:** LOW

In containers, `/proc/self/` still works but memory limits should come from cgroups:
- cgroups v1: `/sys/fs/cgroup/memory/memory.limit_in_bytes`
- cgroups v2: `/sys/fs/cgroup/memory.max`

**Mitigation:** Optionally detect and report cgroup memory limits in `memory_limit_bytes`.

### 4. TUI Column Width

**Risk:** LOW

Adding 2 columns (~12 chars) may cause truncation on narrow terminals.

**Mitigation:**
- Make CPU/RAM columns collapsible (hide at narrow widths)
- Use existing responsive column width system

### 5. Backward Compatibility

**Risk:** LOW

Old hunters (pre-update) will send `HunterStats` without CPU/RAM fields. Proto3 defaults these to 0.

**Mitigation:** TUI should treat 0/0 as "metrics unavailable" rather than "0% CPU, 0 bytes RAM".

### 6. Stale Metrics on Connection Issues

**Risk:** LOW

If heartbeats are delayed, displayed metrics may be stale.

**Mitigation:** Already handled - TUI shows last heartbeat time, users can infer staleness.

## Design Decisions

### 1. Where to Collect Metrics

**Option A:** In heartbeat handler (lazy)
- Collect metrics only when preparing heartbeat
- Pro: Simple, no background goroutine
- Con: CPU calculation needs previous sample, first heartbeat has no CPU data

**Option B:** Background goroutine (periodic) ✓ Recommended
- Collect every N seconds, store latest values
- Pro: Always have fresh metrics, proper CPU calculation
- Con: Additional goroutine

### 2. Shared Metrics Package

**Option A:** Duplicate code in hunter and LocalSource
- Pro: No shared dependency
- Con: Code duplication, divergent implementations

**Option B:** Shared package `internal/pkg/sysmetrics/` ✓ Recommended
- Pro: Single implementation, consistent behavior
- Con: Minor coupling between hunter and processor packages

### 3. CPU Percentage Basis

**Option A:** Per-core percentage (can exceed 100% on multi-core)
- Pro: Shows actual CPU consumption
- Con: Confusing display "450% CPU"

**Option B:** Normalized to 100% max ✓ Recommended
- Pro: Intuitive display
- Con: Doesn't show multi-core utilization

**Option C:** Show both (45.2% / 8 cores)
- Pro: Complete information
- Con: Takes more space

### 4. Memory Metric

**Option A:** Go heap only (`runtime.MemStats.Alloc`)
- Pro: No syscalls, cross-platform
- Con: Doesn't include CGo allocations, stack, etc.

**Option B:** Process RSS ✓ Recommended
- Pro: Accurate total memory footprint
- Con: Requires platform-specific code

### 5. Column Placement

**Option A:** After IP Address, before packet stats
```
S Hunter ID    Mode     Host          CPU    RAM   Captured Forwarded Filters
```

**Option B:** At the end
```
S Hunter ID    Mode     Host          Captured Forwarded Filters CPU    RAM
```

**Option C:** Replace or combine columns
- Not recommended - packet stats are important

**Recommendation:** Option A - resource usage logically groups with host info

## File Change Summary

| File | Type | Description |
|------|------|-------------|
| `api/proto/management.proto` | Modify | Add cpu_percent, memory_rss_bytes, memory_limit_bytes to HunterStats |
| `internal/pkg/sysmetrics/collector.go` | **New** | Platform-agnostic metrics collection interface |
| `internal/pkg/sysmetrics/collector_linux.go` | **New** | Linux /proc implementation |
| `internal/pkg/sysmetrics/collector_other.go` | **New** | Fallback for non-Linux |
| `internal/pkg/hunter/stats/collector.go` | Modify | Add CPU/RAM fields, integrate sysmetrics |
| `internal/pkg/hunter/hunter.go` | Modify | Start metrics collection |
| `internal/pkg/processor/source/source.go` | Modify | Add CPU/RAM to Stats struct |
| `internal/pkg/processor/source/local.go` | Modify | Integrate sysmetrics for TAP |
| `internal/pkg/processor/processor.go` | Modify | Include CPU/RAM in SynthesizeVirtualHunter() |
| `internal/pkg/types/packet.go` | Modify | Add CPU/RAM to HunterInfo |
| `internal/pkg/remotecapture/client_conversion.go` | Modify | Map proto fields to HunterInfo |
| `internal/pkg/statusclient/json.go` | Modify | Add CPU/RAM to HunterStatsJSON, update hunterToJSON() |
| `internal/pkg/tui/components/nodesview/rendering.go` | Modify | Add FormatCPU, FormatMemory, update ColumnWidthCalculator |
| `internal/pkg/tui/components/nodesview/table_view.go` | Modify | Add CPU/RAM columns |
| `internal/pkg/tui/components/nodesview/graph_view.go` | Modify | Add CPU/RAM to hunter boxes |
| `internal/pkg/tui/components/nodesview/rendering_test.go` | Modify | Update tests for new columns |

## Open Questions

1. **Should processor nodes also report their own CPU/RAM?**
   - Currently processors only relay hunter stats
   - Could add `ProcessorStats` fields for processor resource usage
   - Would require additional TUI display changes

2. **What interval for metrics collection?**
   - Match heartbeat interval (default 5s)?
   - Independent shorter interval (1s) for more responsive display?

3. **Should we show memory as percentage of limit?**
   - Useful in containerized environments
   - Requires detecting cgroup limits
   - Could show "245M / 512M (48%)"

4. **How to handle unavailable metrics?**
   - Display "N/A" or "-"
   - Hide column entirely if no node reports metrics
   - Show 0 (current proto3 default behavior)

## Conclusion

Adding CPU and RAM statistics is feasible with moderate complexity. The main work involves:

1. **Proto changes** - 3 new fields in HunterStats
2. **Metrics collection** - New shared package with platform-specific implementations
3. **Integration** - Hunter stats collector and LocalSource both use the shared package
4. **CLI output** - Update statusclient JSON structures for `lc show` commands
5. **TUI updates** - 2 new columns with responsive width handling

The virtual hunter architecture for TAP nodes already provides the right abstraction - CPU/RAM stats will flow through the same path as packet stats with no special handling required.

Estimated scope: ~450-550 lines of new code across 16 files.
