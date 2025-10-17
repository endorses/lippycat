# TUI (Terminal User Interface) Architecture

This document describes the architecture and component patterns for lippycat's Terminal User Interface built with the Bubbletea framework.

## Overview

The TUI provides an interactive real-time packet monitoring interface with support for:
- Local interface capture
- Remote monitoring of distributed hunter/processor nodes
- Protocol filtering and hunter subscription management
- File operations (save/open PCAP files, manage node configurations)
- Visual feedback through modals and toast notifications

## Hunter Subscription Management (v0.2.4)

TUI clients can selectively subscribe to specific hunters on a processor:

**Features:**
- Subscribe to all hunters on a processor (default)
- Subscribe to specific hunters by ID (selective monitoring)
- Unsubscribe from hunters to stop receiving packets
- Multi-select interface with visual feedback

**TUI Controls:**
- Press `s` on a processor to select hunters to subscribe to
- Press `d` on a hunter to unsubscribe or on a processor to remove it
- Multi-select with arrow keys and Enter to confirm

**Implementation Details:**
- Uses `has_hunter_filter` boolean to distinguish empty list from nil (Proto3 serialization)
- Prevents subscriber backpressure from affecting hunter flow control
- Packets are filtered at the processor before being sent to TUI clients

## TUI Modal Architecture

**IMPORTANT: All modals in the TUI MUST use the unified modal component.**

The TUI uses a standardized modal architecture to ensure consistency across all modal dialogs. There is ONE modal rendering function that all modal components must use:

**Unified Modal Component:** `cmd/tui/components/modal.go`

The `RenderModal()` function provides consistent modal chrome (border, centering, title, footer) for all modals in the codebase.

### Architecture Pattern

1. **Modal Content Components** manage their own:
   - State (selection, input, navigation)
   - Content rendering (building the modal body as a string)
   - Event handling (keyboard/mouse events)
   - Business logic (search, filtering, CRUD operations)

2. **Modal Content Components** call `RenderModal()` to wrap their content:
   ```go
   func (component *Component) View() string {
       if !component.active {
           return ""
       }

       // Build content string
       var content strings.Builder
       content.WriteString("My modal content...")

       // Use unified modal rendering
       return RenderModal(ModalRenderOptions{
           Title:      "My Modal Title",
           Content:    content.String(),
           Footer:     "Enter: Select | Esc: Cancel",
           Width:      component.width,
           Height:     component.height,
           Theme:      component.theme,
           ModalWidth: 60, // Optional: specific width
       })
   }
   ```

3. **Parent (model.go)** handles:
   - Checking if modal is active (`IsActive()`)
   - Routing events to the modal
   - Overlaying the modal on the main view

### Current Modal Components

All components use unified `RenderModal()`:
- `ProtocolSelector` - Protocol filter selection (`cmd/tui/components/protocolselector.go`)
- `HunterSelector` - Hunter subscription selection (`cmd/tui/components/hunterselector.go`)
- `NodesView.renderAddNodeModal` - Add processor/hunter node (`cmd/tui/components/nodesview.go`)

### When Creating New Modals

- ✅ DO: Create a component that manages state and content
- ✅ DO: Call `RenderModal()` in your component's `View()` method
- ✅ DO: Follow the same lifecycle pattern (Activate/Deactivate/IsActive/View/Update)
- ❌ DON'T: Render modal chrome (border, centering) yourself
- ❌ DON'T: Create custom modal styling - use RenderModal for consistency
- ❌ DON'T: Duplicate modal rendering logic

### Benefits

- Consistent look and feel across all modals
- Centralized styling and theming
- Easy to maintain and update modal appearance
- Reduces code duplication
- Clear separation of concerns (content vs. chrome)

## FileDialog Component

`FileDialog` (`cmd/tui/components/filedialog.go`) - Modal for file/directory operations with navigation and filtering.

**Architecture:**
- Uses unified `RenderModal()` for consistent chrome
- Returns `FileSelectedMsg` on confirmation
- Four input modes: Navigation, Filename (save), Filter, CreateFolder
- Supports save/open modes with single/multiple file selection

**Key Features:**
- Vim-style navigation (hjkl) + arrow keys + home/end/pgup/pgdown
- Real-time filtering (press `/`) with file type and text matching
- Inline folder creation (press `n`)
- Details toggle (press `d`) - permissions and file sizes
- Filename validation and extension enforcement
- Fixed-height scrollable viewport

**Usage:**
```go
// Create dialog
dialog := NewSaveFileDialog("~/captures", "capture.pcap", []string{".pcap"})
dialog := NewOpenFileDialog("~/captures", []string{".yaml"}, allowMultiple)

// Handle selection
case FileSelectedMsg:
    path := msg.Path()  // Single file
```

## Toast Notifications

`Toast` (`cmd/tui/components/toast.go`) - Non-blocking temporary notifications at bottom-center of screen.

**Architecture:**
- Overlay component (NOT a modal)
- Queue-based: only one toast visible at a time
- Auto-dismiss with `ToastTickMsg` lifecycle
- Click-to-dismiss functionality
- Types: Success (✓), Error (✗), Info (ℹ), Warning (⚠)
- Durations: Short (2s), Normal (3s), Long (5s)

**Usage:**
```go
// Show toast
cmd := toast.Show("File saved!", ToastSuccess, ToastDurationLong)

// Always update in parent's Update()
cmd := m.toast.Update(msg)
```

**Best Practices:**
- Use for transient status, not critical errors requiring action
- Keep messages concise (one line)
- Let queue handle multiple toasts - don't show simultaneously
