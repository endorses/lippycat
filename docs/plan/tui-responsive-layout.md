# TUI Responsive Layout Implementation

**Date:** 2026-01-17
**Status:** Planned

## Overview

Fix resize re-rendering bugs and implement progressive disclosure for TUI components (tabs, footer, header) to gracefully adapt to different terminal widths.

## Tasks

### Phase 1: Fix Resize Re-rendering Bugs ✓

**NodesView** (`internal/pkg/tui/components/nodesview.go`):
- [x] In `SetSize()`: Call `updateViewportContent()` when width changes (not just on initial setup)
- [x] Bug: Empty state centering uses `n.width` but viewport content isn't refreshed on resize

**HelpView** (`internal/pkg/tui/components/helpview.go`):
- [x] In `SetSize()`: Re-render content when width changes (glamour uses `WordWrap(width-4)`)
- [x] Track previous width to detect when re-render is needed
- [x] Return a `tea.Cmd` from `SetSize()` to trigger async re-render

### Phase 2: Shared Responsive Utilities

- [ ] Create `internal/pkg/tui/responsive/breakpoints.go`:
  - Define `WidthClass` type (Narrow, Medium, Wide)
  - `GetWidthClass(width int) WidthClass` function
  - Shared constants for breakpoint thresholds

## Breakpoints

| Name | Width | Description |
|------|-------|-------------|
| Narrow | < 80 | Minimal display, icons/abbreviations |
| Medium | 80-119 | Abbreviated labels |
| Wide | >= 120 | Full display |

### Phase 3: Tabs Component

**File:** `internal/pkg/tui/components/tabs.go`

- [ ] Add responsive label rendering:
  - Wide: Full labels (e.g., "Live Capture", "Statistics")
  - Medium: Short labels (e.g., "Capture", "Stats")
  - Narrow: Icons only (e.g., just the emoji)
- [ ] Handle overflow when tabs exceed width:
  - Detect total tab width vs available width
  - Force narrower mode if needed regardless of breakpoint
- [ ] Add `shortLabel` field to `Tab` struct

### Phase 4: Footer Component

**File:** `internal/pkg/tui/components/footer.go`

- [ ] Add 4th responsive tier for narrow terminals:
  - Show only essential keybindings (2-3 max)
  - Use single-char descriptions or omit descriptions
- [ ] Implement abbreviated descriptions:
  - Wide: "filter", "details", "pause"
  - Medium: "flt", "det", "pse"
  - Narrow: keys only, no descriptions
- [ ] Add responsive method: `getResponsiveKeybinds(width int) []TabKeybind`

### Phase 5: Header Component

**File:** `internal/pkg/tui/components/header.go`

- [ ] Make section widths proportional:
  - Replace hardcoded `leftWidth := 25`, `rightWidth := 20`
  - Use percentages: left 20%, middle 60%, right 20%
  - Enforce minimum widths (left: 12, right: 12)
- [ ] Add text truncation for middle section:
  - Truncate long interface names with ellipsis
  - At narrow: hide "Interface:" label, show only name
- [ ] Simplify packet display at narrow widths:
  - Wide: "Packets: 1,234"
  - Narrow: "1,234"

### Phase 6: Integration & Testing

- [ ] Verify all components receive width updates in `update_handlers.go`
- [ ] Test at multiple terminal widths: 60, 80, 100, 120, 160
- [ ] Ensure no visual overflow or wrapping at any width

## File Summary

**New files:**
- `internal/pkg/tui/responsive/breakpoints.go`

**Modified files:**
- `internal/pkg/tui/components/nodesview.go`
- `internal/pkg/tui/components/helpview.go`
- `internal/pkg/tui/components/tabs.go`
- `internal/pkg/tui/components/footer.go`
- `internal/pkg/tui/components/header.go`

## Verification

1. Run TUI: `sudo go run . watch`
2. **Nodes tab**: Empty state message stays centered when resizing
3. **Help tab**: Content re-wraps to fit new width when resizing
4. Resize terminal to various widths and verify:
   - At 60 chars: icons-only tabs, minimal footer keybinds
   - At 80 chars: short labels, abbreviated keybinds
   - At 120+ chars: full display
5. Ensure no horizontal overflow or wrapping at any width
