# Plan: Node CPU and RAM Statistics

## Overview

Add CPU and RAM usage statistics to the TUI nodes tab and CLI `lc show` commands. Hunters and TAP virtual hunters will report system metrics alongside existing packet stats.

## Design Decisions

Based on [research](../research/node-cpu-ram-stats.md):

1. **Metrics collection:** Background goroutine (not lazy in heartbeat)
2. **Shared package:** `internal/pkg/sysmetrics/` used by both hunter and TAP
3. **CPU basis:** Normalized to 100% max
4. **Memory metric:** Process RSS (not Go heap)
5. **Platform:** Linux `/proc` primary, runtime fallback for non-Linux
6. **Column placement:** After Host, before Captured

## Implementation

### Phase 1: Proto and Metrics Collection

#### 1.1 Update Proto

**File:** `api/proto/management.proto`

Add to `HunterStats` message:
```protobuf
message HunterStats {
    // ... existing fields 1-6
    float cpu_percent = 7;
    uint64 memory_rss_bytes = 8;
    uint64 memory_limit_bytes = 9;
}
```

Run `make proto` to regenerate.

#### 1.2 Create sysmetrics Package

**File:** `internal/pkg/sysmetrics/collector.go`

```go
package sysmetrics

type Metrics struct {
    CPUPercent       float64
    MemoryRSSBytes   uint64
    MemoryLimitBytes uint64
}

type Collector interface {
    Start(ctx context.Context)
    Stop()
    Get() Metrics
}
```

**File:** `internal/pkg/sysmetrics/collector_linux.go`

```go
//go:build linux

// Implements Collector using /proc/self/stat and /proc/self/status
// CPU: Calculate from utime+stime delta over interval
// Memory: Parse VmRSS from /proc/self/status
// Limit: Read from cgroup if available
```

**File:** `internal/pkg/sysmetrics/collector_other.go`

```go
//go:build !linux

// Fallback using runtime.ReadMemStats() for memory only
// CPU returns -1 (unavailable)
```

### Phase 2: Hunter Integration

#### 2.1 Update Hunter Stats Collector

**File:** `internal/pkg/hunter/stats/collector.go`

Add fields:
```go
cpuPercent       atomic.Value // float64
memoryRSSBytes   atomic.Uint64
memoryLimitBytes atomic.Uint64
```

Add methods:
```go
func (c *Collector) SetSystemMetrics(m sysmetrics.Metrics)
func (c *Collector) GetSystemMetrics() sysmetrics.Metrics
```

Update `ToProto()`:
```go
return &management.HunterStats{
    // ... existing fields
    CpuPercent:       c.cpuPercent.Load().(float64),
    MemoryRssBytes:   c.memoryRSSBytes.Load(),
    MemoryLimitBytes: c.memoryLimitBytes.Load(),
}
```

#### 2.2 Start Metrics Collection in Hunter

**File:** `internal/pkg/hunter/hunter.go`

In `Start()`:
```go
// Start system metrics collection
metricsCollector := sysmetrics.New()
metricsCollector.Start(ctx)
defer metricsCollector.Stop()

// Periodically update stats
go func() {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            h.statsCollector.SetSystemMetrics(metricsCollector.Get())
        }
    }
}()
```

### Phase 3: TAP Integration

#### 3.1 Update LocalSource Stats

**File:** `internal/pkg/processor/source/source.go`

Add to `Stats` struct:
```go
CPUPercent       float64
MemoryRSSBytes   uint64
MemoryLimitBytes uint64
```

Add to `AtomicStats`:
```go
cpuPercent       atomic.Value // float64
memoryRSSBytes   atomic.Uint64
memoryLimitBytes atomic.Uint64
```

#### 3.2 Collect Metrics in LocalSource

**File:** `internal/pkg/processor/source/local.go`

In `Start()`:
```go
// Start system metrics collection
metricsCollector := sysmetrics.New()
metricsCollector.Start(ctx)

s.wg.Add(1)
go func() {
    defer s.wg.Done()
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            metricsCollector.Stop()
            return
        case <-ticker.C:
            m := metricsCollector.Get()
            s.stats.SetSystemMetrics(m)
        }
    }
}()
```

#### 3.3 Include in Virtual Hunter

**File:** `internal/pkg/processor/processor.go`

Update `SynthesizeVirtualHunter()` (line ~581):
```go
Stats: &management.HunterStats{
    PacketsCaptured:  stats.PacketsCaptured,
    PacketsForwarded: stats.PacketsForwarded,
    PacketsDropped:   stats.PacketsDropped,
    ActiveFilters:    activeFilters,
    CpuPercent:       float32(stats.CPUPercent),
    MemoryRssBytes:   stats.MemoryRSSBytes,
    MemoryLimitBytes: stats.MemoryLimitBytes,
},
```

### Phase 4: Type Updates

#### 4.1 Update HunterInfo

**File:** `internal/pkg/types/packet.go`

Add to `HunterInfo`:
```go
CPUPercent       float64
MemoryRSSBytes   uint64
MemoryLimitBytes uint64
```

#### 4.2 Update Proto Conversion

**File:** `internal/pkg/remotecapture/client_conversion.go`

In hunter conversion:
```go
CPUPercent:       float64(hunter.Stats.CpuPercent),
MemoryRSSBytes:   hunter.Stats.MemoryRssBytes,
MemoryLimitBytes: hunter.Stats.MemoryLimitBytes,
```

### Phase 5: CLI Output

**File:** `internal/pkg/statusclient/json.go`

Update `HunterStatsJSON`:
```go
type HunterStatsJSON struct {
    // ... existing fields
    CPUPercent       float64 `json:"cpu_percent"`
    MemoryRSSBytes   uint64  `json:"memory_rss_bytes"`
    MemoryLimitBytes uint64  `json:"memory_limit_bytes,omitempty"`
}
```

Update `hunterToJSON()`:
```go
hunter.Stats = &HunterStatsJSON{
    // ... existing fields
    CPUPercent:       float64(h.Stats.CpuPercent),
    MemoryRSSBytes:   h.Stats.MemoryRssBytes,
    MemoryLimitBytes: h.Stats.MemoryLimitBytes,
}
```

### Phase 6: TUI Display

#### 6.1 Add Formatting Helpers

**File:** `internal/pkg/tui/components/nodesview/rendering.go`

```go
func FormatCPU(percent float64) string {
    if percent < 0 {
        return "-"
    }
    return fmt.Sprintf("%.0f%%", percent)
}

func FormatMemory(bytes uint64) string {
    if bytes == 0 {
        return "-"
    }
    return FormatPacketNumber(bytes) // Reuse existing K/M/G formatter
}
```

#### 6.2 Update Column Calculator

**File:** `internal/pkg/tui/components/nodesview/rendering.go`

Update `ColumnWidthCalculator` to add CPU (min: 4, pref: 5) and RAM (min: 4, pref: 5) columns.

#### 6.3 Update Table View

**File:** `internal/pkg/tui/components/nodesview/table_view.go`

Update header:
```
S Hunter ID    Mode     Host          CPU   RAM   Captured Forwarded Filters
```

Update hunter row rendering to include `FormatCPU()` and `FormatMemory()`.

#### 6.4 Update Graph View

**File:** `internal/pkg/tui/components/nodesview/graph_view.go`

Add CPU/RAM lines to hunter box rendering.

### Phase 7: Tests

- [x] `internal/pkg/sysmetrics/collector_test.go` - Unit tests for metrics collection
- [ ] `internal/pkg/hunter/stats/collector_test.go` - Update for new fields
- [ ] `internal/pkg/tui/components/nodesview/rendering_test.go` - Update column width tests

## Files Modified

- [x] `api/proto/management.proto` - Add CPU/RAM fields to HunterStats
- [x] `internal/pkg/sysmetrics/collector.go` - New: interface and types
- [x] `internal/pkg/sysmetrics/collector_linux.go` - New: Linux implementation
- [x] `internal/pkg/sysmetrics/collector_other.go` - New: Non-Linux fallback
- [x] `internal/pkg/hunter/stats/collector.go` - Add CPU/RAM fields
- [x] `internal/pkg/hunter/hunter.go` - Start metrics collection
- [x] `internal/pkg/processor/source/source.go` - Add CPU/RAM to Stats
- [x] `internal/pkg/processor/source/local.go` - Integrate sysmetrics
- [x] `internal/pkg/processor/processor.go` - Update SynthesizeVirtualHunter()
- [x] `internal/pkg/types/packet.go` - Add CPU/RAM to HunterInfo
- [x] `internal/pkg/remotecapture/client_conversion.go` - Map new fields
- [x] `internal/pkg/statusclient/json.go` - Add CPU/RAM to JSON output
- [ ] `internal/pkg/tui/components/nodesview/rendering.go` - FormatCPU, FormatMemory, columns
- [ ] `internal/pkg/tui/components/nodesview/table_view.go` - Add columns
- [ ] `internal/pkg/tui/components/nodesview/graph_view.go` - Add to hunter boxes
- [ ] `internal/pkg/tui/components/nodesview/rendering_test.go` - Update tests

## Verification

1. `make proto` - Regenerate proto
2. `make test` - All tests pass
3. `make build` - Compiles cleanly

4. Manual testing - Hunter:
   ```bash
   # Start processor
   lc process --listen :50051 --insecure

   # Start hunter
   sudo lc hunt --processor localhost:50051 -i eth0 --insecure

   # Check CLI output
   lc show hunters -P localhost:50051 --insecure
   # Verify cpu_percent and memory_rss_bytes in JSON

   # Check TUI
   lc watch remote --nodes localhost:50051 --insecure
   # Verify CPU and RAM columns show values
   ```

5. Manual testing - TAP:
   ```bash
   sudo lc tap voip -i eth0 --insecure

   lc show hunters -P localhost:50051 --insecure
   # Virtual hunter should show CPU/RAM

   lc watch remote --nodes localhost:50051 --insecure
   # Virtual hunter row should show CPU/RAM
   ```

6. Edge cases:
   - Non-Linux: CPU shows "-", RAM shows Go heap
   - Old hunter (pre-update): CPU/RAM show "-" (0 values)
   - Narrow terminal: Columns collapse gracefully
