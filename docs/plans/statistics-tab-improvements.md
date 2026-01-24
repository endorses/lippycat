# Statistics Tab Improvements

**Date:** 2026-01-24
**Status:** Pending
**Research:** [docs/research/statistics-tab-improvements.md](../research/statistics-tab-improvements.md)

## Overview

Enhance the Statistics tab with time-series metrics, system health visualization, interactivity, distributed mode aggregates, and an extensible protocol-specific stats framework.

## Tasks

### Phase 1: Core Infrastructure

- [x] Create `internal/pkg/tui/components/rate_tracker.go`:
  - `RateTracker` struct with configurable sample count and interval
  - `RateSample` (timestamp, packets, bytes) ring buffer
  - `RateStats` (current/avg/peak rates for packets and bytes)
- [x] Create `internal/pkg/tui/components/drop_stats.go`:
  - `DropStats` aggregating kernel, buffer, queue, hunter, and network drops
  - Calculate drop percentages and rates
- [x] Integrate existing metrics from `hunter/stats`, `processor/stats`, and `voip/capture_engine.go` into Statistics struct
- [x] Add time window support (`TimeWindow1Min`, `TimeWindow5Min`, `TimeWindow15Min`, `TimeWindowAll`)

### Phase 2: Visualization

- [x] Add `github.com/NimbleMarkets/ntcharts` dependency to `go.mod`
- [x] Create `internal/pkg/tui/components/sparkline.go` - ntcharts wrapper for styled sparklines
- [x] Create `internal/pkg/tui/components/progressbar.go` - progress bar component for utilization metrics
- [x] Update `statistics.go`:
  - Add sparkline for packet/byte rate trends
  - Add progress bars for buffer utilization, queue depth, memory
  - Add health indicator (green/yellow/red) with threshold logic

### Phase 3: Interactivity

- [ ] Add sub-view navigation in `statistics.go`:
  - `v` key cycles views: Overview → Traffic → Health → Top Talkers → Distributed
  - `1`-`5` for direct access to sub-views
- [ ] Implement click-to-filter for top talkers:
  - Track selected section/index
  - Enter key applies filter (e.g., `host 192.168.1.100`)
- [ ] Add time window selector (`t` key cycles through windows)
- [ ] Add JSON export functionality (`e` key)
- [ ] Update `footer.go` with Statistics tab keybindings

### Phase 4: Distributed Mode

- [ ] Create `DistributedStats` struct in `statistics.go`:
  - Fleet overview (total/healthy hunters, processors)
  - Combined throughput (aggregate packet/byte rates)
  - Per-hunter contribution percentages
- [ ] Add load distribution visualization (horizontal bar chart per hunter)
- [ ] Add fleet health summary with color-coded indicators
- [ ] Wire up processor stats collector to TUI via EventHandler

### Phase 5: Protocol-Specific Stats (Extensible)

- [ ] Create `internal/pkg/tui/components/protocol_stats.go`:
  - `ProtocolStatsProvider` interface (`ProtocolName`, `IsActive`, `Render`, `GetMetrics`)
  - `ProtocolStatsRegistry` for provider registration and lookup
- [ ] Create `internal/pkg/tui/components/voip_stats_provider.go`:
  - Active/total/completed/failed calls
  - Success rate
  - Codec distribution (bar chart)
  - Quality metrics (jitter, loss, MOS)
- [ ] Integrate with Protocol Selector in `statistics.go` - show provider section when protocol active
- [ ] Document pattern for adding future protocol providers (DNS, HTTP, etc.)

## File Summary

**New files (Phase 1 complete):**
- `internal/pkg/tui/components/rate_tracker.go` - time-series rate sampling
- `internal/pkg/tui/components/rate_tracker_test.go` - rate tracker tests
- `internal/pkg/tui/components/drop_stats.go` - drop statistics aggregation
- `internal/pkg/tui/components/drop_stats_test.go` - drop stats tests
- `internal/pkg/tui/components/time_window.go` - time window type and methods
- `internal/pkg/tui/components/time_window_test.go` - time window tests

**New files (Phase 2 complete):**
- `internal/pkg/tui/components/sparkline.go` - ntcharts sparkline wrapper
- `internal/pkg/tui/components/sparkline_test.go` - sparkline tests
- `internal/pkg/tui/components/progressbar.go` - progress bar component with health indicators
- `internal/pkg/tui/components/progressbar_test.go` - progress bar tests

**New files (Phase 3-5 pending):**
- `internal/pkg/tui/components/protocol_stats.go` - provider interface/registry
- `internal/pkg/tui/components/voip_stats_provider.go` - VoIP-specific stats

**Modified files (Phase 1 complete):**
- `internal/pkg/tui/components/statistics.go` - added RateTracker, DropStats, TimeWindow integration

**Modified files (Phase 2-5 pending):**
- `go.mod` - ntcharts dependency
- `internal/pkg/tui/components/footer.go` - Statistics tab keybindings
- `internal/pkg/tui/store/ui_state.go` - time window, selected protocol tracking

## Design Decisions

1. **ntcharts over asciigraph:** Purpose-built for Bubbletea with Lipgloss integration
2. **Sub-views over scrolling:** Separate views with keyboard navigation reduce visual clutter
3. **Protocol-agnostic by default:** Core stats always shown; protocol-specific only when filter active
4. **Registry pattern for protocols:** Extensible without modifying core statistics code
5. **300 samples (5 min @ 1s):** Balance between history depth and memory usage
