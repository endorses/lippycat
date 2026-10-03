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
    cert_file: "/etc/lippycat/certs/client.crt" # Optional: for mutual TLS
    key_file: "/etc/lippycat/certs/client.key" # Optional: for mutual TLS
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

## Dialog Interaction

Click a button to perform its action. Tab and Shift+Tab move between fields,
lists, and enabled buttons; Enter or Space activates a focused button. Existing
list and text-editing shortcuts remain available when those controls have focus.
Disabled buttons cannot be activated. The action bar wraps in narrow terminals;
use the wheel over a list to scroll its contents.

Click a protocol row to select it, then choose **Apply**; double-clicking a row
also applies it. In file dialogs, single-click selects, **Open** opens a file or
enters a directory, and double-click performs the same navigation in open mode.
Click breadcrumbs or **Up** to change directories, and click the search or
filename field to edit it. **New folder** and **Show details** provide the
corresponding file-browser controls.

In save mode, selecting an existing file fills its filename; double-clicking
focuses that name without saving. Choose **Save** to submit it. An existing
destination requires **Replace** confirmation; **Keep editing** returns to the
filename. **Cancel edit** leaves the current inline edit, while **Cancel** closes
the file dialog. These controls also apply to Settings file pickers.

The filter manager provides **New**, **Edit**, **Delete**, and **Close** buttons.
Click a filter row to select it, or its checkbox to toggle it. Search, Type,
Status, editor fields, and hunter targets are clickable. Hunter selectors have
**All**, **None**, **Confirm**, and **Cancel** controls. Target choices remain
local until confirmed; filter targets only offer compatible hunters. An empty
filter target list means all compatible hunters, while an empty subscription
means receiving packets from none.

Clicking outside a dialog cancels only its visible layer. Offline opening and
filtering dialogs also have **Cancel** buttons and stay open while cleanup
finishes. If cleanup fails, use **Retry cleanup** or **Quit** where offered.

## TUI Modal Architecture

All dialogs use `RenderModal(ModalOptions())`. `ModalRenderOptions` contains a
stable layer `ID`, content, informational footer text, explicit `ModalAction`
buttons, content-local `ModalTarget` rectangles, and the owner's `ModalState`.
`LayoutModal` is the shared source for rendering and screen-space hit geometry,
including terminal-cell widths, clipping, scrolling, and wrapped action bars.
`View` and layout calculation are read-only; hit testing works before rendering
following a resize. Use `ModalContentWidth` to size content without duplicating
chrome offsets.

Interactive owners implement `ModalOptions`, `HandleModalAction`, and
`HandleModalFocus` in addition to `View` and `Dismiss`. Call `HandleModalInput`
from `Update` before contextual keyboard handling. Keyboard shortcuts and button
clicks invoke the same explicit action handlers, which revalidate current state.
`HandleModalFocus` focuses or blurs owned inputs; `ModalState` tracks focus,
scroll position, and double-click identity. Reset click state when navigation,
resizing, dismissal, or list replacement changes the target context.

The host resolves the visible layer with `activeModal` and `VisibleModal`.
Composite owners expose nested dialogs through `ActiveModal`, including file
overwrite and filter deletion confirmations. The host routes modal mouse input
before the underlying UI and consumes gestures that close or replace a layer.
`Dismiss` preserves result payloads and cleanup; progress owners request
cancellation and remain visible until workers finish. Asynchronous results still
reach their owners while a modal is visible.

The same contract covers protocol selection, hunter subscriptions, file dialogs,
filter lists/editors/target selectors, generic confirmations, add-node input, and
offline progress. Concrete actions belong in `Actions`; navigation hints remain
in `Footer`. Content owners supply local targets; the shared layout owns border,
padding, centering, and viewport transformations.

## FileDialog Component

`FileDialog` (`internal/pkg/tui/components/filedialog.go`) - Modal for file/directory operations with navigation and filtering.

**Architecture:**

- Uses unified `RenderModal()` for consistent chrome
- Returns `FileSelectedMsg` on confirmation
- Four input modes: Navigation, Filename (save), Filter, CreateFolder
- Supports save/open modes with single-file selection

**Key Features:**

- Vim-style navigation (hjkl) + arrow keys + home/end/pgup/pgdown
- Real-time filtering (press `/`) with file type and text matching
- Inline folder creation (press `n`)
- Details toggle (press `d`) - permissions and file sizes
- Filename validation and extension enforcement
- Scrollable content viewport with persistent action buttons
- Explicit overwrite confirmation before returning an existing save destination

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

`Toast` (`internal/pkg/tui/components/toast.go`) - Non-blocking temporary notifications at bottom-center of screen.

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

## Remote Nodes change cues

CPU and RAM use persistent text colors based on utilization: the normal theme
foreground below 70%, Solarized orange (`#cb4b16`) from 70%, and Solarized red
(`#dc322f`) from 90%. Escalation requires three distinct actual metrics samples;
repeated snapshots and redraws do not count. Elevated color clears below 65% and
high color below 85%. These presentation thresholds do not change node health.
CPU/RAM values no longer flash or show change arrows.

The displayed CPU percentage remains raw process usage: 100% means one core, so
values can exceed 100%. Color classification divides that percentage by the
reported effective CPU capacity in cores, including fractional quotas. Capacity
reflects visible CPU affinity and cgroup quota constraints, including restrictive
ancestors; it is not a guaranteed CPU reservation. RAM color compares process RSS
with the reported cgroup memory limit. This is an approximate process-to-limit
ratio: it excludes other memory charged to the cgroup.

Both metrics share the validated percentage thresholds
`watch.nodes_resources.elevated` (default 70) and `watch.nodes_resources.high`
(default 90). Values must be finite and satisfy 0 < elevated < high <= 100;
invalid pairs are logged and replaced by both defaults. The default clearing gap
is five percentage points. For low or closely spaced custom thresholds, the gap
shrinks to half the elevated threshold or half the distance between thresholds,
whichever is smaller. Missing capacity or memory limits, invalid metrics, and disconnected
nodes use neutral text. Additive capacity and sample-timestamp telemetry fields
preserve compatibility: older clients ignore them, while older nodes or
intermediaries may omit them. Without an actual metrics sample timestamp,
resource colors stay neutral even when values can still be displayed.

Packet totals share one subtle activity marker per node. Advancing captured or
forwarded totals briefly use a green (`#859900`) background only when the rounded
displayed total changes; counter resets establish a new baseline without a
highlight. Filter changes use a neutral blue (`#268bd2`) background with a signed
delta. These temporary cells use Solarized base3 (`#fdf6e3`) text. `NEW` and
`RECOVERED` mark observed lifecycle transitions. Initial snapshots and
subscription changes establish a baseline without join alerts. Idle counters do
not imply stale or disconnected nodes.

The table and graph share the same cues. A stationary recent-event line shows the
latest lifecycle or health transition, its age, and any additional events in the
preceding 30 seconds. It disappears after 30 seconds and is omitted on very short
terminals. Counter and filter cues last about one second and lifecycle markers
about five seconds, expiring on the next UI tick even while capture is paused.

In remote **Settings**, select **Nodes highlighting** and press `Enter` to switch
between `normal` (default) and `quiet`. Quiet mode retains persistent CPU/RAM
foreground colors, labels, status, and recent events while suppressing temporary
counter, filter, and lifecycle backgrounds and border accents. The change takes
effect immediately without restarting capture and is saved as
`watch.nodes_highlighting` in the configuration file.
