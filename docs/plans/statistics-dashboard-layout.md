# Statistics Dashboard Layout

**Date:** 2026-01-24
**Status:** Planning
**Branch:** `feat/statistics-tab-improvements`

## Overview

Redesign the Statistics tab Overview sub-view to use a responsive grid/card layout that makes better use of horizontal space and displays all key information without scrolling. Add TUI process metrics (CPU/RAM) to the dashboard.

## Problem Statement

Current issues with the Overview sub-view:
1. Single-column vertical layout wastes horizontal space (see screenshot)
2. Content requires scrolling to see all sections
3. Fixed-width components (30-char bars) don't scale with terminal width
4. No visibility into TUI process resource usage

## Goals

- [ ] Display all key stats without scrolling on typical terminals (≥100 chars wide)
- [ ] Responsive layout that adapts to terminal width
- [ ] Modern "card-based" dashboard appearance
- [ ] Include TUI CPU and RAM metrics
- [ ] Maintain compatibility with narrow terminals (<80 chars)

## Design

### Target Layout (Wide Terminal ≥120 chars)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ View: [1:Ovw] 2:Trf  3:Hlt  4:Top  5:Dst           Time: [1m] 5m  15m  All  │
├───────────────────────────────────┬─────────────────────────────────────────┤
│ 📊 CAPTURE                        │ 📈 TRAFFIC RATE                         │
│ ┌─────────┬─────────┬──────────┐  │                                         │
│ │ 17,487  │ 12.0 MB │  4m 50s  │  │  Current: 143 pkt/s   │   110.5 KB/s    │
│ │ packets │  bytes  │ duration │  │  Average: 137 pkt/s   │    95.9 KB/s    │
│ └─────────┴─────────┴──────────┘  │  Peak:    490 pkt/s   │   250.7 KB/s    │
│   716 avg  •  42-1553 bytes       │                                         │
│                                   │  [▁▂▃▅█▆▄▃▂▁▃▄▅▆▄▃▂▁▃▄▅▆▇▅▄▃▂▁]         │
├───────────────────────────────────┼─────────────────────────────────────────┤
│ 🖥 TUI PROCESS                    │ 🔌 PROTOCOL DISTRIBUTION                │
│   CPU: 2.3%    RAM: 45.2 MB       │  TLS  [██████████████████████░░] 86.5%  │
│                                   │  QUIC [███░░░░░░░░░░░░░░░░░░░░░]  9.3%  │
│                                   │  TCP  [█░░░░░░░░░░░░░░░░░░░░░░░]  2.9%  │
│  [▁▂▃▅█▆▄▃▂▁▃▄▅▆▄▃▂▁▃▄▅▆▇▅▄▃▂▁]   │  ICMP [░░░░░░░░░░░░░░░░░░░░░░░░]  0.4%  │
│                                   │  UDP  [░░░░░░░░░░░░░░░░░░░░░░░░]  0.4%  │
├───────────────────────────────────┴─────────────────────────────────────────┤
│ ⬆ TOP SOURCES                     │ ⬇ TOP DESTINATIONS                      │
│  192.168.0.107            8,055   │  192.168.0.107                    9,314 │
│  188.72.235.98            6,978   │  188.72.235.98                    6,978 │
│  142.251.168.136          1,131   │  142.251.168.136                  1,131 │
│  34.36.57.103               362   │  34.36.57.103                       362 │
│  192.168.0.124               71   │  192.168.0.124                       71 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Medium Terminal (80-119 chars)

- 2-column layout
- Top Sources and Top Destinations side-by-side
- Protocol distribution uses narrower bars
- TUI metrics inline with capture stats

### Narrow Terminal (<80 chars)

- Falls back to current single-column layout
- Maintains scrolling behavior

## Tasks

### Phase 1: TUI System Metrics

- [x] Add `sysmetrics.Collector` to TUI model
  - Initialize in `New()` with `sysmetrics.New()`
  - Start collector in `Init()`
  - Stop collector in cleanup/quit handler
- [x] Add `TUIMetrics` field to `StatisticsView`
  - `CPUPercent float64`
  - `MemoryRSSBytes uint64`
- [x] Create `UpdateTUIMetrics(m sysmetrics.Metrics)` method on `StatisticsView`
- [x] Wire up periodic updates (every 1s tick) from model to statistics view
- [x] Create `renderTUIMetrics()` function in `statistics.go`
- [x] Create `CPUTracker` for CPU history sparkline (cpu_tracker.go)
- [x] Create `RenderCPUSparkline()` helper function (sparkline.go)
- [x] Add CPU tracker tests (cpu_tracker_test.go)

### Phase 2: Layout Infrastructure

- [x] Create `internal/pkg/tui/components/dashboard/` package:
  - `card.go` - Card component with border, title, content
  - `grid.go` - Grid layout helper (rows, columns, gaps)
  - `stat_box.go` - Compact stat display (value + label)
- [x] Add width breakpoint constants to `responsive/breakpoints.go`:
  - `DashboardNarrowMax = 80`
  - `DashboardMediumMax = 120`
  - `DashboardWideMin = 160`
- [x] Create `LayoutMode` type: `LayoutNarrow`, `LayoutMedium`, `LayoutWide`
- [x] Add `GetLayoutMode(width int) LayoutMode` helper

### Phase 3: Card Components

- [x] Implement `Card` struct:
  ```go
  type Card struct {
      Title    string
      Icon     string
      Width    int
      Content  string
      Style    lipgloss.Style
  }
  func (c Card) Render() string
  ```
- [x] Implement `StatBox` for compact metrics:
  ```go
  type StatBox struct {
      Value string
      Label string
      Width int
  }
  func (s StatBox) Render() string
  ```
- [x] Implement `Grid` for layout:
  ```go
  type Grid struct {
      Columns int
      Gap     int
      Items   []string
  }
  func (g Grid) Render(width int) string
  ```

### Phase 4: Overview Refactoring

- [x] Refactor `renderOverviewSubView()` to use layout mode:
  ```go
  func (s *StatisticsView) renderOverviewSubView() string {
      mode := getLayoutMode(s.width)
      switch mode {
      case LayoutWide:
          return s.renderOverviewWide()
      case LayoutMedium:
          return s.renderOverviewMedium()
      default:
          return s.renderOverviewNarrow()
      }
  }
  ```
- [x] Implement `renderOverviewWide()`:
  - Row 1: Capture card (left) + Traffic Rate card (right)
  - Row 2: TUI Process card (left) + Protocol Distribution card (right)
  - Row 3: Top Sources (left) + Top Destinations (right)
- [x] Implement `renderOverviewMedium()`:
  - Row 1: Capture stats + TUI metrics (inline)
  - Row 2: Traffic Rate with sparkline
  - Row 3: Protocol Distribution
  - Row 4: Top Sources (left) + Top Destinations (right)
- [x] Keep `renderOverviewNarrow()` as current implementation (single column)

### Phase 5: Dynamic Bar Widths

- [x] Update `renderProtocolDistribution()` to calculate bar width from available space:
  ```go
  func (s *StatisticsView) renderProtocolDistribution(count int, availableWidth int) string {
      labelWidth := 8  // "UNKNOWN " max
      percentWidth := 7 // " 100.0%"
      barWidth := availableWidth - labelWidth - percentWidth - 4 // borders/padding
      // ...
  }
  ```
- [x] Update `renderTopTalkers()` to use available width for IP/count columns
- [x] Update `renderLoadDistribution()` for distributed mode

### Phase 6: Polish & Testing

- [ ] Test on various terminal sizes (80, 100, 120, 160, 200 chars)
- [ ] Verify narrow fallback works correctly
- [ ] Add unit tests for grid/card components
- [ ] Update `internal/pkg/tui/CLAUDE.md` with dashboard component documentation

## File Summary

**New files:**
- `internal/pkg/tui/components/dashboard/card.go`
- `internal/pkg/tui/components/dashboard/grid.go`
- `internal/pkg/tui/components/dashboard/stat_box.go`
- `internal/pkg/tui/components/dashboard/card_test.go`
- `internal/pkg/tui/components/dashboard/grid_test.go`

**Modified files:**
- `internal/pkg/tui/model.go` - Add sysmetrics.Collector
- `internal/pkg/tui/components/statistics.go` - TUIMetrics, layout modes, refactored rendering
- `internal/pkg/tui/components/responsive/breakpoints.go` - Dashboard breakpoints
- `internal/pkg/tui/update_handlers.go` - Wire TUI metrics updates

## Design Decisions

1. **Card-based layout:** Provides visual separation and modern dashboard appearance
2. **Three breakpoints:** Narrow (<80), Medium (80-119), Wide (≥120) covers common terminal sizes
3. **Existing sysmetrics package:** Reuse existing CPU/RAM collection rather than adding new dependency
4. **Lipgloss borders:** Use existing styling framework for consistency
5. **Graceful degradation:** Wide layout → Medium → Narrow based on terminal width
6. **TUI metrics placement:** Small card that doesn't dominate but provides visibility

## Dependencies

- Existing: `github.com/charmbracelet/lipgloss` (borders, styling)
- Existing: `internal/pkg/sysmetrics` (CPU/RAM collection)
- No new external dependencies required
