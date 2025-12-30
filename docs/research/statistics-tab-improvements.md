# Statistics Tab Improvements - Research

## Overview

This document researches improvements to the TUI Statistics tab, focusing on protocol-agnostic metrics and visualization. Protocol-specific statistics are treated as an optional extension that activates only when a protocol is selected via the Protocol Selector.

## Design Principles

1. **Protocol-agnostic by default** - Core statistics apply to all traffic
2. **Protocol-specific is optional** - Only shown when a protocol filter is active
3. **Extensible** - Protocol stats framework supports future protocols (HTTP, DNS, SMTP, etc.)
4. **Visual feedback** - Sparklines, progress bars, and health indicators
5. **Actionable** - Click-to-filter, export capabilities

## Current State

**File:** `internal/pkg/tui/components/statistics.go`

### Current Statistics Structure

```go
type Statistics struct {
    ProtocolCounts *BoundedCounter // Protocol -> packet count (max 1000)
    SourceCounts   *BoundedCounter // Source IP -> packet count (max 10000)
    DestCounts     *BoundedCounter // Dest IP -> packet count (max 10000)
    TotalBytes     int64
    TotalPackets   int64
    MinPacketSize  int
    MaxPacketSize  int
}
```

### Current Display

- Overview: Total packets, bytes, avg/min/max size
- Protocol Distribution: Top 5 protocols with percentages
- Top Source IPs: Top 5 sources
- Top Destination IPs: Top 5 destinations

### Limitations

1. No time-series data (rates, trends)
2. No system health metrics (drops, buffer utilization)
3. No interactivity (can't click to filter)
4. No distributed mode aggregates
5. Static text rendering (no charts/sparklines)
6. No protocol-specific sections

## Existing Metrics Infrastructure

### Hunter Stats (`internal/pkg/hunter/stats/collector.go`)

```go
type Collector struct {
    packetsCaptured  atomic.Uint64
    packetsMatched   atomic.Uint64
    packetsForwarded atomic.Uint64
    packetsDropped   atomic.Uint64
    bufferBytes      atomic.Uint64
}
```

### Processor Stats (`internal/pkg/processor/stats/collector.go`)

```go
type Stats struct {
    TotalHunters          uint32
    HealthyHunters        uint32
    WarningHunters        uint32
    ErrorHunters          uint32
    TotalPacketsReceived  uint64
    TotalPacketsForwarded uint64
    TotalFilters          uint32
}
```

### Capture Stats (`internal/pkg/voip/capture_engine.go`)

```go
type CaptureStats struct {
    PacketsReceived  atomic.Uint64
    BytesReceived    atomic.Uint64
    PacketsDropped   atomic.Uint64
    PacketsProcessed atomic.Uint64
    BatchesProcessed atomic.Uint64
}
```

### TCP Metrics (`internal/pkg/voip/tcp_metrics.go`)

```go
type TCPStreamMetrics struct {
    ActiveStreams         int64
    TotalStreamsCreated   int64
    TotalStreamsCompleted int64
    TotalStreamsFailed    int64
    QueuedStreams         int64
    DroppedStreams        int64
}
```

### Histogram Support (`internal/pkg/voip/monitoring/metrics.go`)

```go
type HistogramStats struct {
    Count        int64
    Sum          float64
    Average      float64
    Min          float64
    Max          float64
    Percentiles  map[string]float64 // p50, p90, p95, p99
}
```

**Observation:** Rich metrics infrastructure already exists but is not exposed in the Statistics tab.

## Visualization Libraries

### ntcharts (Recommended)

[NimbleMarkets/ntcharts](https://github.com/NimbleMarkets/ntcharts) - MIT licensed, designed for Bubbletea/Lipgloss.

**Features:**
- Sparklines (time-series)
- Bar charts (horizontal/vertical)
- Line charts with axes
- Heatmaps
- Candlestick charts
- BubbleZone integration for mouse support

**Installation:**
```go
import "github.com/NimbleMarkets/ntcharts/sparkline"
import "github.com/NimbleMarkets/ntcharts/barchart"
```

**Sparkline example:**
```go
sl := sparkline.New(width, height)
sl.Push(42.0)  // Add data point
sl.Draw()      // Returns styled string
```

### Alternative: asciigraph

[guptarohit/asciigraph](https://pkg.go.dev/github.com/guptarohit/asciigraph) - Simpler, standalone ASCII graphs.

```go
import "github.com/guptarohit/asciigraph"

data := []float64{3, 4, 9, 6, 2, 4, 5, 8, 5, 10}
graph := asciigraph.Plot(data, asciigraph.Height(10))
```

**Trade-off:** asciigraph is simpler but doesn't integrate with Lipgloss styling. ntcharts is purpose-built for Bubbletea.

## Proposed Improvements

### 1. Time-Series Metrics

**New data structures:**

```go
type RateTracker struct {
    samples    []RateSample
    maxSamples int           // e.g., 300 for 5 minutes at 1s intervals
    interval   time.Duration // sampling interval
}

type RateSample struct {
    Timestamp time.Time
    Packets   int64
    Bytes     int64
}

type RateStats struct {
    CurrentPacketsPerSec float64
    CurrentBytesPerSec   float64
    AvgPacketsPerSec     float64
    AvgBytesPerSec       float64
    PeakPacketsPerSec    float64
    PeakBytesPerSec      float64
}
```

**Display:**
```
📈 Traffic Rate
  Current:  1,234 pkt/s  |  2.5 MB/s
  Average:    892 pkt/s  |  1.8 MB/s
  Peak:     3,456 pkt/s  |  7.2 MB/s

  ▁▂▃▄▅▆▇█▇▆▅▄▃▂▁▂▃▄▅▆  (last 5 min)
```

### 2. System Health Dashboard

**Metrics to expose:**

| Metric | Source | Display |
|--------|--------|---------|
| Buffer utilization | `PacketBuffer.dropped` | Progress bar |
| Kernel drops | pcap stats | Counter + rate |
| Application drops | capture engine | Counter + rate |
| Active goroutines | `TCPStreamMetrics` | Gauge |
| Queue depth | TCP assembler | Progress bar |
| Memory usage | `runtime.MemStats` | Progress bar |

**Display:**
```
🏥 System Health                          [●] Healthy

  Buffer Usage    [████████░░░░░░░░░░░░]  42%
  Queue Depth     [██░░░░░░░░░░░░░░░░░░]  12%
  Memory          [██████░░░░░░░░░░░░░░]  31%  (128 MB / 412 MB)

  Drops:  Kernel: 0  |  App: 127  |  Rate: 0.01%
```

**Health indicator logic:**
```go
func calculateHealth() HealthStatus {
    if bufferUtil > 0.9 || dropRate > 0.05 {
        return HealthCritical  // Red
    }
    if bufferUtil > 0.7 || dropRate > 0.01 {
        return HealthWarning   // Yellow
    }
    return HealthGood          // Green
}
```

### 3. Enhanced Drop Statistics

**Aggregate from multiple sources:**

```go
type DropStats struct {
    // Kernel level (from pcap)
    KernelDrops     int64
    KernelDropRate  float64

    // Application level
    BufferDrops     int64   // PacketBuffer overflow
    QueueDrops      int64   // TCP assembler queue full
    FilterDrops     int64   // Filtered out (intentional)

    // Distributed mode
    HunterDrops     int64   // Aggregated from all hunters
    NetworkDrops    int64   // gRPC stream drops

    // Totals
    TotalDrops      int64
    DropPercentage  float64
}
```

**Display:**
```
📉 Drop Statistics

  Source          Count       Rate
  ──────────────────────────────────
  Kernel              0      0.00%
  Buffer            127      0.01%
  Queue               0      0.00%
  ──────────────────────────────────
  Total             127      0.01%
```

### 4. Distributed Mode Aggregates

**When in remote capture mode, show system-wide metrics:**

```go
type DistributedStats struct {
    // Fleet overview
    TotalHunters    int
    HealthyHunters  int
    TotalProcessors int

    // Aggregate throughput
    CombinedPacketRate  float64  // All hunters combined
    CombinedByteRate    float64

    // Load distribution
    HunterContributions []HunterContribution  // % from each hunter

    // Capacity
    EstimatedHeadroom   float64  // How much more can system handle
}

type HunterContribution struct {
    HunterID   string
    Percentage float64
    PacketRate float64
}
```

**Display:**
```
🌐 Distributed System                    3 hunters | 1 processor

  Combined Rate:  4,521 pkt/s  |  9.2 MB/s

  Load Distribution:
    hunter-edge-01  [████████████░░░░░░░░]  58%  2,622 pkt/s
    hunter-edge-02  [██████░░░░░░░░░░░░░░]  31%  1,401 pkt/s
    hunter-edge-03  [██░░░░░░░░░░░░░░░░░░]  11%    498 pkt/s

  Fleet Health: ●●○  (2 healthy, 1 warning)
```

**Note:** This complements the Nodes tab (which shows topology/details) by providing aggregate metrics.

### 5. Interactive Features

#### Click-to-Filter

When user selects a row in top talkers:

```go
type InteractiveStats struct {
    selectedSection  string  // "protocols", "sources", "destinations"
    selectedIndex    int
    selectionActive  bool
}

// On Enter key when item selected:
func (s *StatisticsView) applyFilter() tea.Cmd {
    item := s.getSelectedItem()
    filter := fmt.Sprintf("host %s", item.Key)
    return ApplyFilterCmd{Filter: filter}
}
```

**Visual feedback:**
```
⬆️  Top Source IPs                        [Enter to filter]

  > 192.168.1.100                   1,234 packets  ◀ selected
    10.0.0.50                         892 packets
    172.16.0.25                       456 packets
```

#### Time Window Selector

```go
type TimeWindow int

const (
    TimeWindow1Min  TimeWindow = iota  // Last 1 minute
    TimeWindow5Min                      // Last 5 minutes
    TimeWindow15Min                     // Last 15 minutes
    TimeWindowAll                       // All time (session)
)
```

**Display in header:**
```
📊 Statistics                    [1m] 5m  15m  All    (press t to cycle)
```

#### Export

```go
func (s *StatisticsView) exportJSON() error {
    data := StatisticsExport{
        Timestamp:    time.Now(),
        TimeWindow:   s.timeWindow,
        Overview:     s.stats.Overview(),
        Protocols:    s.stats.ProtocolCounts.GetAll(),
        TopSources:   s.stats.SourceCounts.GetTopN(20),
        TopDests:     s.stats.DestCounts.GetTopN(20),
        Rates:        s.rateTracker.GetStats(),
        Drops:        s.dropStats,
    }
    return json.MarshalIndent(data, "", "  ")
}
```

**Keybinding:** `e` to export

### 6. Sub-Views Architecture

Navigate between sections with `v` or `1-5`:

```go
type StatsSubView int

const (
    SubViewOverview    StatsSubView = iota  // Default: summary of all
    SubViewTraffic                          // Rates, sparklines
    SubViewHealth                           // System health, drops
    SubViewTopTalkers                       // Interactive IP lists
    SubViewDistributed                      // Fleet stats (if remote mode)
)
```

**Footer:**
```
  v overview | 1 traffic | 2 health | 3 talkers | 4 distributed
```

**Alternative:** Single scrollable view with collapsible sections.

## Protocol-Specific Statistics (Optional)

### Architecture

Protocol-specific stats are shown **only when a protocol is selected** in the Protocol Selector.

```go
type ProtocolStatsProvider interface {
    // ProtocolName returns the protocol identifier (e.g., "voip", "http", "dns")
    ProtocolName() string

    // IsActive returns true if this protocol's stats should be shown
    IsActive(selectedProtocol string) bool

    // Render returns the protocol-specific stats section
    Render(width int, theme themes.Theme) string

    // GetMetrics returns protocol-specific metrics for export
    GetMetrics() map[string]interface{}
}
```

### Registry Pattern

```go
type ProtocolStatsRegistry struct {
    providers map[string]ProtocolStatsProvider
}

func (r *ProtocolStatsRegistry) Register(p ProtocolStatsProvider) {
    r.providers[p.ProtocolName()] = p
}

func (r *ProtocolStatsRegistry) GetActiveProvider(selectedProtocol string) ProtocolStatsProvider {
    for _, p := range r.providers {
        if p.IsActive(selectedProtocol) {
            return p
        }
    }
    return nil  // No protocol-specific stats
}
```

### Example: VoIP Stats Provider

```go
type VoIPStatsProvider struct {
    callTracker *voip.CallTracker
}

func (v *VoIPStatsProvider) ProtocolName() string {
    return "voip"
}

func (v *VoIPStatsProvider) IsActive(selected string) bool {
    return selected == "voip" || selected == "VoIP (SIP/RTP)"
}

func (v *VoIPStatsProvider) Render(width int, theme themes.Theme) string {
    stats := v.callTracker.GetStats()

    return fmt.Sprintf(`
📞 VoIP Statistics

  Active Calls:     %d
  Total Calls:      %d  (completed: %d, failed: %d)
  Success Rate:     %.1f%%

  Codec Distribution:
    G.711 (PCMU)    [████████████░░░░░░░░]  62%%
    G.729           [██████░░░░░░░░░░░░░░]  28%%
    Opus            [██░░░░░░░░░░░░░░░░░░]  10%%

  Quality (avg):
    Jitter:   12.3 ms
    Loss:     0.02%%
    MOS:      4.2
`,
        stats.ActiveCalls,
        stats.TotalCalls,
        stats.CompletedCalls,
        stats.FailedCalls,
        stats.SuccessRate,
    )
}
```

### Example: DNS Stats Provider (Future)

```go
type DNSStatsProvider struct{}

func (d *DNSStatsProvider) ProtocolName() string { return "dns" }

func (d *DNSStatsProvider) IsActive(selected string) bool {
    return selected == "dns" || selected == "DNS"
}

func (d *DNSStatsProvider) Render(width int, theme themes.Theme) string {
    return `
🌐 DNS Statistics

  Query Rate:       234 qps
  Response Rate:    231 qps

  Query Types:
    A         [████████████████░░░░]  78%
    AAAA      [████░░░░░░░░░░░░░░░░]  18%
    MX        [░░░░░░░░░░░░░░░░░░░░]   2%
    Other     [░░░░░░░░░░░░░░░░░░░░]   2%

  Response Codes:
    NOERROR   [██████████████████░░]  92%
    NXDOMAIN  [█░░░░░░░░░░░░░░░░░░░]   6%
    SERVFAIL  [░░░░░░░░░░░░░░░░░░░░]   2%
`
}
```

### Example: HTTP Stats Provider (Future)

```go
type HTTPStatsProvider struct{}

func (h *HTTPStatsProvider) Render(width int, theme themes.Theme) string {
    return `
🌍 HTTP Statistics

  Request Rate:     89 req/s

  Methods:
    GET       [████████████████░░░░]  82%
    POST      [███░░░░░░░░░░░░░░░░░]  14%
    PUT       [░░░░░░░░░░░░░░░░░░░░]   3%
    DELETE    [░░░░░░░░░░░░░░░░░░░░]   1%

  Status Codes:
    2xx       [██████████████████░░]  91%
    3xx       [█░░░░░░░░░░░░░░░░░░░]   4%
    4xx       [░░░░░░░░░░░░░░░░░░░░]   3%
    5xx       [░░░░░░░░░░░░░░░░░░░░]   2%
`
}
```

### Integration with Protocol Selector

The Statistics tab queries the current protocol selection:

```go
func (s *StatisticsView) renderContent() string {
    var result strings.Builder

    // Always render protocol-agnostic stats
    result.WriteString(s.renderOverview())
    result.WriteString(s.renderRates())
    result.WriteString(s.renderHealth())
    result.WriteString(s.renderTopTalkers())

    // Conditionally render protocol-specific stats
    if provider := s.registry.GetActiveProvider(s.selectedProtocol); provider != nil {
        result.WriteString("\n")
        result.WriteString(provider.Render(s.width, s.theme))
    }

    return result.String()
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (Foundation)

- [ ] Add `RateTracker` for time-series sampling
- [ ] Add `DropStats` aggregation
- [ ] Integrate existing metrics into Statistics struct
- [ ] Add time window support

### Phase 2: Visualization (Quick Wins)

- [ ] Add ntcharts dependency
- [ ] Implement sparklines for packet/byte rates
- [ ] Add progress bars for buffer/queue utilization
- [ ] Add health indicator (green/yellow/red)

### Phase 3: Interactivity

- [ ] Add sub-view navigation (`v` key)
- [ ] Add click-to-filter for top talkers
- [ ] Add time window selector (`t` key)
- [ ] Add export functionality (`e` key)

### Phase 4: Distributed Mode

- [ ] Aggregate stats from all hunters
- [ ] Add load distribution visualization
- [ ] Add fleet health summary
- [ ] Integrate with processor stats collector

### Phase 5: Protocol-Specific (Extensible)

- [ ] Create `ProtocolStatsProvider` interface
- [ ] Create registry and integration points
- [ ] Implement VoIP stats provider
- [ ] Document pattern for future protocols

## File Changes Summary

### New Files

| File | Purpose |
|------|---------|
| `internal/pkg/tui/components/rate_tracker.go` | Time-series rate sampling |
| `internal/pkg/tui/components/sparkline.go` | Sparkline wrapper for ntcharts |
| `internal/pkg/tui/components/progressbar.go` | Progress bar component |
| `internal/pkg/tui/components/protocol_stats.go` | Protocol stats registry/interface |
| `internal/pkg/tui/components/voip_stats_provider.go` | VoIP-specific stats |

### Modified Files

| File | Changes |
|------|---------|
| `internal/pkg/tui/components/statistics.go` | Major rewrite with new sections |
| `internal/pkg/tui/components/footer.go` | Add Statistics tab keybindings |
| `internal/pkg/tui/store/ui_state.go` | Add selectedProtocol tracking |
| `go.mod` | Add ntcharts dependency |

## Open Questions

1. **Sparkline resolution:** How many data points? 60 (1 min at 1s)? 300 (5 min)?

2. **Sub-views vs scrolling:** Separate sub-views with `v` navigation, or single scrollable view with sections?

3. **Protocol stats location:** Inline in main view, or separate sub-view?

4. **Update frequency:** How often to refresh stats display? Currently tied to packet updates.

5. **Memory budget:** How much history to keep for time windows? (affects memory in long sessions)

## Dependencies

| Dependency | Purpose | License |
|------------|---------|---------|
| `github.com/NimbleMarkets/ntcharts` | Sparklines, bar charts | MIT |

Already using: `bubbletea`, `bubbles`, `lipgloss`

## References

- [ntcharts GitHub](https://github.com/NimbleMarkets/ntcharts)
- [asciigraph](https://pkg.go.dev/github.com/guptarohit/asciigraph)
- Previous conversation on statistics improvements
- `internal/pkg/tui/CLAUDE.md` - TUI architecture
- `internal/pkg/hunter/stats/collector.go` - Hunter metrics
- `internal/pkg/processor/stats/collector.go` - Processor metrics
