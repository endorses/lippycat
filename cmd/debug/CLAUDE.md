# Debug Command - Architecture & Implementation

This document describes the architecture and implementation patterns for the `debug` command - TCP SIP diagnostics and monitoring.

## Purpose

The debug command provides **runtime introspection** into TCP SIP processing:
- Health monitoring
- Performance metrics
- Resource utilization
- Alert management
- Configuration inspection

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Debug Command                           │
├─────────────────────────────────────────────────────────────┤
│  cmd/                                                       │
│    └── debug.go         - Debug command with 7 subcommands  │
├─────────────────────────────────────────────────────────────┤
│  Queries internal/pkg/voip:                                 │
│    ├── tcp_health.go    - Health monitoring                 │
│    ├── tcp_metrics.go   - Metrics collection                │
│    ├── tcp_alerts.go    - Alert system                      │
│    └── tcp_config.go    - Configuration state               │
└─────────────────────────────────────────────────────────────┘
```

## Build Tags

**Build Tag:** `cli` or `all`

```go
//go:build cli || all
```

Debug command is included in:
- `cli` builds (CLI-only binary)
- `all` builds (complete suite)

**Why?** Debug is diagnostic tool for local sniff operations, not needed in distributed mode binaries.

## Command Structure

### Main Command: `debug.go`

**File:** `cmd/debug.go`

**Pattern:** Single parent command with 7 subcommands

```go
debugCmd
├── health     - TCP assembler health status
├── metrics    - Comprehensive TCP metrics
├── alerts     - Active alerts and history
├── buffers    - TCP buffer statistics
├── streams    - Stream processing metrics
├── config     - Current configuration
└── summary    - Overall system status
```

**Why subcommands?** Modularity - each diagnostic has specific focus.

## Subcommand Patterns

### 1. Health Command

**File:** `cmd/debug.go:124-184`

**Purpose:** Quick health check

**Output Format:** Human-readable with visual indicators

```
✅ Status: HEALTHY
🔄 Goroutines: 12/50 (24.0%)
📋 Queue: 15/250 (6.0%)
```

**Pattern:** Thresholds with warnings

```go
if utilization > 90 {
    fmt.Println("   ⚠️  HIGH: Consider increasing max_goroutines")
} else if utilization > 70 {
    fmt.Println("   ⚠️  MODERATE: Monitor for potential capacity issues")
}
```

**Data Source:** `voip.GetTCPAssemblerHealth()` - returns `map[string]interface{}`

### 2. Metrics Command

**File:** `cmd/debug.go:186-255`

**Purpose:** Comprehensive metrics dump

**Output Format:** Human-readable OR JSON

```bash
lc debug metrics        # Human-readable
lc debug metrics --json # JSON for monitoring systems
```

**Pattern:** Dual output mode

```go
if jsonOutput {
    data, _ := json.MarshalIndent(metrics, "", "  ")
    fmt.Println(string(data))
    return
}
// ... human-readable formatting
```

**Data Source:** `voip.GetTCPAssemblerMetrics()` - structured metrics

### 3. Alerts Command

**File:** `cmd/debug.go:257-331`

**Purpose:** Alert monitoring and history

**Flags:**
- `--active-only` - Show only active alerts
- `--json` - JSON output

**Pattern:** Tabular output with sorting

```go
// Sort by timestamp (newest first)
sort.Slice(alerts, func(i, j int) bool {
    return alerts[i].Timestamp.After(alerts[j].Timestamp)
})

// Tabwriter for alignment
w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
fmt.Fprintln(w, "LEVEL\tCOMPONENT\tSTATUS\tTIME\tMESSAGE")
```

**Alert Levels:** Critical (🔴), Warning (🟡), Info (🔵)

**Data Source:** `voip.GetAlertManager().GetActiveAlerts()`

### 4. Buffers Command

**File:** `cmd/debug.go:333-368`

**Purpose:** TCP buffer statistics

**Key Metrics:**
- Total buffers
- Total packets
- Buffers dropped
- Average packets per buffer
- Drop rate

**Pattern:** Calculated metrics with warnings

```go
if stats.TotalBuffers > 0 {
    avgPacketsPerBuffer := float64(stats.TotalPackets) / float64(stats.TotalBuffers)
    fmt.Printf("Avg Packets/Buffer: %.1f\n", avgPacketsPerBuffer)
}

if dropRate > 5 {
    fmt.Println("⚠️  HIGH drop rate - consider increasing max_tcp_buffers")
}
```

### 5. Streams Command

**File:** `cmd/debug.go:370-411`

**Purpose:** Stream processing statistics

**Key Metrics:**
- Active streams
- Success/failure/drop rates
- Performance indicators

**Pattern:** Percentage calculations

```go
successRate := float64(completed) / float64(created) * 100
failureRate := float64(failed) / float64(created) * 100
dropRate := float64(dropped) / float64(created) * 100
```

### 6. Config Command

**File:** `cmd/debug.go:413-453`

**Purpose:** Display current configuration

**Pattern:** Formatted output with recommendations

```go
switch config.TCPPerformanceMode {
case "throughput":
    fmt.Println("📈 Optimized for high-volume processing")
case "latency":
    fmt.Println("⚡ Optimized for low-latency real-time processing")
}
```

**Shows:** All TCP configuration parameters and active profile

### 7. Summary Command

**File:** `cmd/debug.go:455-542`

**Purpose:** Quick overview of system status

**Pattern:** Dashboard-style aggregation

```
🟢 Overall Status: HEALTHY
🔄 Goroutine Utilization: 24.0%
📋 Queue Utilization: 6.0%
✅ Active Alerts: None
📦 TCP Buffers: 3421
🔗 Active Streams: 12
```

**Includes:** Health + metrics + alerts in single view

## Data Flow Pattern

All debug commands follow same pattern:

```
Debug Command → Query voip Package → Return Data → Format & Display
     ↓                  ↓                  ↓              ↓
debug.go          internal/pkg/voip   Struct/Map      Stdout
                  tcp_*.go files
```

**No State in Debug Command:** Commands are stateless queries.

## Key Implementation Patterns

### 1. Global State Access Pattern

Debug commands access global state in voip package:

```go
health := voip.GetTCPAssemblerHealth()  // Global function
alertMgr := voip.GetAlertManager()      // Singleton pattern
config := voip.GetConfig()              // Current config
```

**Why global?** TCP assembler is singleton per process.

### 2. Type Assertion Pattern

Health data returned as `map[string]interface{}`:

```go
if status, ok := health["status"].(string); ok && status == "not_initialized" {
    fmt.Println("⚠️  TCP processing not active")
    return
}
```

**Defensive:** Always check type assertions to avoid panics.

### 3. JSON Marshaling Pattern

Metrics use structured types for JSON output:

```go
type TCPStreamMetrics struct {
    ActiveStreams           int64     `json:"active_streams"`
    TotalStreamsCreated     int64     `json:"total_created"`
    TotalStreamsCompleted   int64     `json:"total_completed"`
    LastMetricsUpdate       time.Time `json:"last_update"`
}
```

### 4. Emoji Indicator Pattern

Visual indicators for better readability:

```go
const (
    iconHealthy   = "✅"
    iconUnhealthy = "❌"
    iconWarning   = "⚠️"
    iconCritical  = "🔴"
    iconInfo      = "🔵"
)
```

### 5. Tabwriter Pattern

Aligned columnar output:

```go
w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
fmt.Fprintln(w, "LEVEL\tCOMPONENT\tSTATUS\tTIME\tMESSAGE")
fmt.Fprintln(w, "-----\t---------\t------\t----\t-------")
for _, alert := range alerts {
    fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ...)
}
w.Flush()
```

## Monitoring Integration

### JSON Output Mode

All metrics commands support `--json` for monitoring systems:

```bash
# Prometheus exporter integration
lc debug metrics --json | jq '.streams.active_streams'

# Grafana data source
*/5 * * * * lc debug metrics --json > /var/metrics/lippycat.json

# Alert monitoring
lc debug alerts --active-only --json | jq '.[] | select(.level=="CRITICAL")'
```

### Watch Integration

Real-time monitoring with `watch`:

```bash
# Dashboard
watch -n 2 'lc debug summary'

# Health monitoring
watch -n 5 'lc debug health'

# Alert watching
watch -n 10 'lc debug alerts --active-only'
```

## Error Handling Patterns

### Not Initialized Pattern

```go
if status == "not_initialized" {
    fmt.Println("⚠️  TCP factory not initialized - no active VoIP capture running")
    return
}
```

**Why?** Debug commands only work when VoIP capture is active.

### Graceful Degradation

```go
if err := json.MarshalIndent(data, "", "  "); err != nil {
    fmt.Printf("Error marshaling: %v\n", err)
    return
}
```

**Never panic** - debug commands should be non-invasive.

## Performance Considerations

### No Impact on Capture

Debug commands are **read-only queries** - they don't affect running capture.

**Locking:** RW mutexes ensure safe concurrent access:

```go
// In voip package
func GetTCPAssemblerMetrics() TCPMetrics {
    metricsMu.RLock()
    defer metricsMu.RUnlock()
    return currentMetrics
}
```

### Minimal Overhead

Metrics collection happens regardless of debug commands - no additional overhead.

## Testing Considerations

### Unit Testing

Mock voip package functions:

```go
// In tests
voip.GetTCPAssemblerHealth = func() map[string]interface{} {
    return map[string]interface{}{
        "status": "healthy",
        "active_streams": int64(10),
    }
}
```

### Integration Testing

Run debug commands during VoIP capture tests:

```bash
# Start capture
lc sniff voip --read-file test.pcap &
PID=$!

# Query debug commands
lc debug summary
lc debug metrics --json > metrics.json

kill $PID
```

## Common Development Tasks

### Adding a New Subcommand

1. Create cobra command:
```go
var debugNewCmd = &cobra.Command{
    Use:   "new",
    Short: "New diagnostic",
    Run:   func(cmd *cobra.Command, args []string) {
        showNewDiagnostic()
    },
}
```

2. Register in init:
```go
debugCmd.AddCommand(debugNewCmd)
```

3. Implement query function:
```go
func showNewDiagnostic() {
    data := voip.GetNewData()
    // Format and display
}
```

### Adding a New Metric

1. Add to struct in `internal/pkg/voip/tcp_metrics.go`:
```go
type TCPMetrics struct {
    NewMetric int64 `json:"new_metric"`
}
```

2. Collect in metrics updater

3. Display in `debugMetricsCmd`

## Dependencies

**External:**
- `github.com/spf13/cobra` - CLI framework
- `encoding/json` - JSON marshaling
- `text/tabwriter` - Aligned output

**Internal:**
- `internal/pkg/voip` - TCP metrics and health

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../sniff/CLAUDE.md](../sniff/CLAUDE.md) - Sniff command architecture
- [../../docs/tcp-troubleshooting.md](../../docs/tcp-troubleshooting.md) - TCP troubleshooting guide
