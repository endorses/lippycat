# TUI (Terminal User Interface) Architecture

This document describes the architecture and component patterns for lippycat's Terminal User Interface built with the Bubbletea framework.

## Overview

The TUI provides an interactive real-time packet monitoring interface with support for:
- Local interface capture
- Remote monitoring of distributed hunter/processor nodes
- Protocol filtering and hunter subscription management
- File operations (save/open PCAP files, manage node configurations)
- Visual feedback through modals and toast notifications
- Secure TLS connections or insecure mode for development/testing

## Security: TLS Configuration

**TLS (Transport Layer Security)** can be configured for remote processor connections using either:
1. Command-line flags (override config file)
2. Configuration file (`~/.config/lippycat/config.yaml`)
3. The `--insecure` flag to explicitly disable TLS for testing/development

### Configuration Options

#### Command-Line Flags
```bash
# Enable TLS with CA certificate (server verification only)
lc tui --remote --tls --tls-ca /path/to/ca.crt

# Enable TLS with mutual authentication (client cert + CA)
lc tui --remote --tls --tls-ca /path/to/ca.crt \
  --tls-cert /path/to/client.crt --tls-key /path/to/client.key
```

#### Configuration File
```yaml
tui:
  tls:
    enabled: true
    ca_file: "/etc/lippycat/certs/ca.crt"
    cert_file: "/etc/lippycat/certs/client.crt"  # Optional: for mutual TLS
    key_file: "/etc/lippycat/certs/client.key"   # Optional: for mutual TLS
```

#### Flag Priority
Command-line flags override config file settings:
- `--tls` enables TLS (overrides config)
- `--tls-ca <path>` sets CA certificate path
- `--tls-cert <path>` sets client certificate path (for mutual TLS)
- `--tls-key <path>` sets client key path (for mutual TLS)
- `--insecure` disables TLS (overrides all TLS settings)

### Secure Mode Examples

**Server verification only:**
```bash
lc tui --remote --tls --tls-ca ca.crt
```
- TUI verifies processor's certificate using CA
- Processors shown with 🔒 icon in Nodes tab
- Connection toast: "Connected to <address>"

**Mutual TLS (recommended for production):**
```bash
lc tui --remote --tls --tls-ca ca.crt \
  --tls-cert client.crt --tls-key client.key
```
- Both TUI and processor verify each other's certificates
- Highest security level
- Prevents unauthorized TUI connections

### Insecure Mode (Testing/Development Only)
```bash
lc tui --remote --insecure
```
- Connections do NOT use TLS encryption
- Processors shown with 🚫 icon in Nodes tab
- Connection toast: "⚠ Connected to <address> (INSECURE - no TLS)"

**IMPORTANT:** The `--insecure` flag should only be used for testing/development. Production deployments should always use TLS for security.

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

## Reconnection Resilience (v0.2.8)

TUI survives network interruptions with intelligent reconnection:

**Features:**
- Exponential backoff prevents resource exhaustion during outages
- Lenient keepalive settings tolerate temporary delays (laptop standby)
- Max retry limit prevents infinite reconnection loops
- Manual reconnection available after max retries

**Behavior:**
- First attempts: Quick retries (2s, 4s, 8s) for transient issues
- Extended outages: Longer waits (up to 10 min) between attempts
- After 10 failures (~17 min total): Stop auto-reconnect, show warning
- User can manually reconnect from Nodes view (press `r` on processor)

**Keepalive Settings:**
- TCP keepalive: 10s idle, 5s interval, 3 probes (25s detection)
- gRPC keepalive: 30s ping, 20s timeout
- Combined tolerance: ~50s network interruption before disconnect

**Use Cases:**
- Laptop suspend/resume
- Brief network outages (WiFi handoff, etc.)
- Processor restarts
- Network maintenance windows

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
