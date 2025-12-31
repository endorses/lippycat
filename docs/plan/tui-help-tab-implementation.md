# TUI Help Tab Implementation

**Date:** 2025-12-31
**Status:** Planned
**Research:** [docs/research/tui-help-tab.md](../research/tui-help-tab.md)

## Overview

Add a Help tab (index 4) to the TUI with embedded markdown documentation, searchable via `/` key.

## Tasks

### Phase 1: Dependencies & Content

- [ ] Add `github.com/charmbracelet/glamour` dependency
- [ ] Create `internal/pkg/tui/help/` directory
- [ ] Write `keybindings.md` - global and per-tab keybindings
- [ ] Write `commands.md` - CLI command reference (sniff, tap, watch, hunt, process, list, show)
- [ ] Write `workflows.md` - common usage patterns

### Phase 2: HelpView Component

- [ ] Create `internal/pkg/tui/components/helpview.go`:
  - Embed help files via `go:embed`
  - Viewport for scrollable content
  - Glamour rendering with dark theme
  - Search mode (`/` to enter, `n`/`N` for next/prev match, `Esc` to exit)
  - Section navigation (`1`-`3` for keybindings/commands/workflows)

### Phase 3: Tab Integration

- [ ] Add Help tab to `tabs.go` (index 4, icon `?`, label "Help")
- [ ] Update `keyboard_navigation.go`: `totalTabs = 5`, add `Alt+5` binding
- [ ] Add `?` global shortcut to jump to Help tab (when not in input mode)
- [ ] Add `HelpView` field to `store/ui_state.go`
- [ ] Add case 4 to `view_renderer.go`
- [ ] Add `SetSize` call in `update_handlers.go`
- [ ] Add Help tab keybindings to `footer.go`

### Phase 4: Polish

- [ ] Test search functionality
- [ ] Verify viewport scrolling with rendered markdown
- [ ] Test tab navigation (Tab/Shift+Tab cycles through 5 tabs)
- [ ] Verify `?` shortcut works from all tabs

## File Summary

**New files:**
- `internal/pkg/tui/help/keybindings.md`
- `internal/pkg/tui/help/commands.md`
- `internal/pkg/tui/help/workflows.md`
- `internal/pkg/tui/components/helpview.go`

**Modified files:**
- `go.mod` - glamour dependency
- `internal/pkg/tui/store/ui_state.go` - HelpView field
- `internal/pkg/tui/components/tabs.go` - Help tab
- `internal/pkg/tui/keyboard_navigation.go` - totalTabs, Alt+5
- `internal/pkg/tui/keyboard_handler.go` - `?` shortcut
- `internal/pkg/tui/view_renderer.go` - case 4
- `internal/pkg/tui/update_handlers.go` - SetSize
- `internal/pkg/tui/components/footer.go` - Help keybindings

## Design Decisions

1. **Single document vs sections:** Use section navigation (`1`-`3`) within Help tab rather than sub-tabs
2. **Search:** Simple case-insensitive substring search (fuzzy search can be added later)
3. **Icon:** `?` matches the global shortcut
4. **Content:** Embedded at build time via `go:embed` for single-binary deployment
