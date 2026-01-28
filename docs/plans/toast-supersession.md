# Toast Supersession

**Date:** 2026-01-28
**Status:** Complete

## Overview

Add optional supersession keys to toasts. When a new toast with a key arrives, it removes all queued toasts with the same key and dismisses the current toast if it shares that key. This prevents obsolete messages (e.g., "paused" followed immediately by "resumed").

## Behavior

- Toasts without a key behave as before (simple FIFO queue)
- Toasts with a key supersede others with the same key
- Different keys are independent and maintain relative order
- If the currently displayed toast has the same key, it's dismissed immediately

## Supersession Keys

| Key | Toasts | Effect |
|-----|--------|--------|
| `capture-state` | paused, resumed | Resume supersedes pause |
| `connection:<addr>` | disconnected, reconnecting, reconnected | Per-server state collapse |
| `file-save` | "Saving...", saved, error | Result supersedes progress |
| `filter` | applying, applied, error | Result supersedes progress |

## Tasks

### Phase 1: Core Implementation

- [x] Add `supersessionKey` field to `toastQueueItem` in `toast.go`
- [x] Add `currentKey` field to `Toast` struct for active toast's key
- [x] Create `ShowWithKey(message, type, duration, key)` method
- [x] Implement queue filtering: remove items with matching key
- [x] Implement current toast dismissal when key matches

### Phase 2: Apply to Existing Toasts

- [x] `keyboard_handler.go`: pause/resume → key `capture-state`
- [x] `capture_events.go`: connection states → key `connection:<addr>`
- [x] `save_operations.go`: file save → key `file-save`
- [x] `update_handlers.go`: save complete → key `file-save`
- [ ] `filter_operations.go`: filter apply → key `filter` (not needed - filters are independent actions)

### Phase 3: Testing

- [x] Unit test: supersession removes queued items with same key
- [x] Unit test: supersession dismisses current toast with same key
- [x] Unit test: different keys maintain FIFO order
- [x] Unit test: toasts without keys unaffected

## File Changes

**Modified:**
- `internal/pkg/tui/components/toast.go` - core supersession logic, key constants, `ShowWithKey()` method
- `internal/pkg/tui/keyboard_handler.go` - capture-state key for pause/resume
- `internal/pkg/tui/capture_events.go` - connection keys for connect/disconnect/reconnect
- `internal/pkg/tui/save_operations.go` - file-save key for save progress
- `internal/pkg/tui/update_handlers.go` - file-save key for save complete

**New:**
- `internal/pkg/tui/components/toast_test.go` - unit tests for supersession
