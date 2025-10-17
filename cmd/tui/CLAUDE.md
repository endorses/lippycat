# TUI - Architecture & Implementation

This document describes the architecture and implementation patterns for the TUI (Terminal User Interface) built with the Bubbletea framework.

## Purpose

The TUI provides **interactive real-time monitoring** in three modes:
1. **Live Mode** - Local interface capture with VoIP analysis
2. **Offline Mode** - PCAP file playback
3. **Remote Mode** - Monitor distributed hunter/processor nodes

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                          TUI Application                         │
├──────────────────────────────────────────────────────────────────┤
│  cmd/tui/                                                        │
│    ├── tui.go           - Command entry point                    │
│    ├── model.go         - Bubbletea model (app state)            │
│    ├── view_renderer.go - Main view rendering                    │
│    └── components/      - Reusable UI components                 │
│         ├── header.go      - Header bar                          │
│         ├── footer.go      - Context-aware footer                │
│         ├── modal.go       - Unified modal chrome                │
│         ├── toast.go       - Toast notifications                 │
│         ├── filedialog.go  - File picker                         │
│         ├── protocolselector.go - Protocol filter modal          │
│         ├── hunterselector.go   - Hunter subscription modal      │
│         └── nodesview.go        - Remote nodes management        │
├──────────────────────────────────────────────────────────────────┤
│  Three Capture Modes (polymorphic):                              │
│    ├── live_capture.go     - Local interface capture             │
│    ├── offline_capture.go  - PCAP file playback                  │
│    └── remote_capture.go   - Distributed node monitoring         │
│        Uses: internal/pkg/remotecapture (EventHandler pattern)   │
└──────────────────────────────────────────────────────────────────┘
```

## Build Tags

**Build Tag:** `tui` or `all`

```go
//go:build tui || all
```

The TUI is included in:
- `tui` builds (TUI-only binary)
- `all` builds (complete suite)

NOT included in `hunter`, `processor`, or `cli` specialized builds.

## Bubbletea Architecture (Elm Architecture)

### The Model-View-Update Pattern

```
┌─────────────────────────────────────────────────┐
│  User Input (keyboard/mouse) → Msg              │
│         ↓                                       │
│  Update(model, msg) → (model, Cmd)              │
│         ↓                                       │
│  View(model) → string                           │
│         ↓                                       │
│  Render to terminal                             │
└─────────────────────────────────────────────────┘
```

### Core Components

**File:** `cmd/tui/model.go`

```go
type model struct {
    // Capture mode (polymorphic)
    captureMode    CaptureMode  // Live/Offline/Remote
    liveCapture    *LiveCapture
    offlineCapture *OfflineCapture
    remoteCapture  *RemoteCapture

    // UI state
    width, height  int
    packets        []types.PacketDisplay
    selectedPacket int
    filterText     string

    // Components
    toast              *Toast
    fileDialog         *FileDialog
    protocolSelector   *ProtocolSelector
    hunterSelector     *HunterSelector
    nodesView          *NodesView
}
```

**Polymorphic Capture:** Single interface, three implementations.

## Capture Mode Pattern (Polymorphism)

### Interface Design

Each capture mode implements common lifecycle:

```go
type CaptureMode interface {
    Start(ctx context.Context) error
    Stop() error
    GetPackets() []types.PacketDisplay
    GetStats() Stats
}
```

### Live Mode

**File:** `cmd/tui/live_capture.go`

**Flow:**
```
Interface → gopacket → VoIP Analysis → Display
```

**Implementation:**
```go
type LiveCapture struct {
    iface      string
    packets    []types.PacketDisplay
    packetChan chan types.PacketDisplay
}

func (lc *LiveCapture) Start(ctx context.Context) error {
    // Start gopacket capture
    // Feed packets to packetChan
    // TUI receives via tea.Cmd
}
```

### Offline Mode

**File:** `cmd/tui/offline_capture.go`

**Flow:**
```
PCAP File → gopacket → Replay → Display
```

**Challenge:** Timing control (pause/resume/seek)

### Remote Mode

**File:** `cmd/tui/remote_capture.go`

**Flow:**
```
gRPC Client → EventHandler → Display
```

**Uses:** `internal/pkg/remotecapture` package

**EventHandler Pattern:**

```go
// TUI implements EventHandler interface
func (m *model) OnPacketBatch(packets []types.PacketDisplay) {
    m.packets = append(m.packets, packets...)
    // Trigger re-render
}

func (m *model) OnHunterStatus(hunters []types.HunterInfo, processorID string) {
    m.nodesView.UpdateHunters(hunters)
}

func (m *model) OnDisconnect(address string, err error) {
    m.toast.Show(fmt.Sprintf("Disconnected from %s", address), ToastError)
}
```

**Why EventHandler?** Decouples gRPC client from TUI framework.

## Component Architecture

### Unified Modal Pattern

**File:** `cmd/tui/components/modal.go`

**IMPORTANT:** All modals MUST use `RenderModal()` for consistency.

```go
func RenderModal(opts ModalRenderOptions) string {
    // Renders:
    // - Border
    // - Title
    // - Content (provided by caller)
    // - Footer
    // - Centering
}
```

**Component Responsibility:**
- Build content string
- Call `RenderModal()` to wrap
- Handle input events
- Manage own state

**Parent Responsibility:**
- Check `IsActive()`
- Route events to modal
- Overlay on main view

### Modal Components

All follow same lifecycle pattern:

```go
type ModalComponent interface {
    Activate(opts Options)
    Deactivate()
    IsActive() bool
    View() string
    Update(msg tea.Msg) tea.Cmd
}
```

**Examples:**
- `ProtocolSelector` - Protocol filter selection
- `HunterSelector` - Hunter subscription selection
- `FileDialog` - File/directory picker
- `NodesView.renderAddNodeModal` - Add node modal

### Overlay Components

**Toast Notifications:**

**File:** `cmd/tui/components/toast.go`

**Pattern:** Queue-based, auto-dismiss

```go
type Toast struct {
    queue    []ToastMessage
    current  *ToastMessage
    visible  bool
}

// Show adds to queue
toast.Show("Saved!", ToastSuccess, ToastDurationLong)

// Auto-dismiss via tea.Cmd
toast.Update(ToastTickMsg{})  // Decrements timer
```

**NOT a modal** - overlay at bottom of screen.

### Context-Aware Footer

**File:** `cmd/tui/components/footer.go`

**Pattern:** Tab-specific keybindings with two sections

```go
type Footer struct {
    activeTab            int
    hasProtocolSelection bool
    filterMode           bool
    hasFilter            bool
    // ...
}
```

**Architecture:** Two-section layout

```
┌────────────────────────────────────────────────────────────┐
│ [Tab-specific keybinds]  [General keybinds]  [Version]     │
│  (colored background)      (violet keys)                   │
└────────────────────────────────────────────────────────────┘
```

**Tab-specific keybinds:**
- Tab 0 (Capture): `/` filter, `w` save, `d` toggle details
- Tab 1 (Nodes): `f` filters, `s` hunters, `v` view
- Tab 2 (Statistics): `v` view
- Tab 3 (Settings): `Enter` edit/toggle, `Esc` cancel, `←/→` switch mode

**General keybinds:** Always visible (Space, n, p, q)

**Color-coding:** Each tab has its own background color matching tab theme:
```go
func (f *Footer) getTabColor(tabIndex int) lipgloss.Color {
    tabColors := []lipgloss.Color{
        f.theme.ErrorColor,   // Tab 0: Capture (red)
        f.theme.DNSColor,     // Tab 1: Nodes (yellow)
        f.theme.SuccessColor, // Tab 2: Statistics (green)
        f.theme.InfoColor,    // Tab 3: Settings (blue)
    }
}
```

**Responsive layout:** Gracefully degrades when terminal width is limited (version → general → tab-specific).

## Message Flow Pattern

### Custom Messages

```go
type PacketMsg struct {
    Packets []types.PacketDisplay
}

type FileSelectedMsg struct {
    Path string
}

type ToastTickMsg struct {
    ID int
}
```

### Message Routing

**File:** `cmd/tui/model.go`

```go
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    // Route to active modal first
    if m.fileDialog.IsActive() {
        cmd := m.fileDialog.Update(msg)
        return m, cmd
    }

    // Route to main view
    switch msg := msg.(type) {
    case PacketMsg:
        m.packets = append(m.packets, msg.Packets...)
    case FileSelectedMsg:
        m.loadPCAP(msg.Path)
    }

    return m, nil
}
```

**Priority:** Active modal > Main view

## Key Implementation Patterns

### 1. EventHandler Integration Pattern

**File:** `cmd/tui/remote_capture.go`

TUI implements `types.EventHandler` interface:

```go
type model struct implements types.EventHandler {
    // ...
}

// EventHandler methods
func (m *model) OnPacketBatch(packets []types.PacketDisplay) {
    m.packets = append(m.packets, packets...)
}

// Use with remote capture client
client := remotecapture.NewClient(config, m)  // m is EventHandler
```

**Benefit:** Clean separation between gRPC logic and UI logic.

### 2. Channel-to-Cmd Pattern

Convert Go channels to Bubbletea Cmds:

```go
func waitForPackets(packetChan chan []types.PacketDisplay) tea.Cmd {
    return func() tea.Msg {
        packets := <-packetChan
        return PacketMsg{Packets: packets}
    }
}
```

**Why?** Bubbletea event loop requires tea.Msg, not direct channel access.

### 3. Component Lifecycle Pattern

All components follow:

```go
// Create
component := NewComponent(options)

// Activate (show)
component.Activate()

// Check if active before routing
if component.IsActive() {
    cmd := component.Update(msg)
}

// Render if active
if component.IsActive() {
    view += component.View()
}

// Deactivate (hide)
component.Deactivate()
```

### 4. Selective Hunter Subscription Pattern

**File:** `cmd/tui/components/hunterselector.go`

**Challenge:** Proto3 can't distinguish empty list from nil.

**Solution:** `has_hunter_filter` boolean

```protobuf
message SubscribeRequest {
    repeated string hunter_ids = 1;
    bool has_hunter_filter = 2;  // true = filter active, false = all hunters
}
```

```go
// Subscribe to all hunters
req := &pb.SubscribeRequest{
    HunterIDs:        nil,
    HasHunterFilter:  false,
}

// Subscribe to specific hunters
req := &pb.SubscribeRequest{
    HunterIDs:        []string{"hunter-1", "hunter-2"},
    HasHunterFilter:  true,
}

// Subscribe to none (empty list means "none" when filter active)
req := &pb.SubscribeRequest{
    HunterIDs:        []string{},
    HasHunterFilter:  true,
}
```

### 5. Theme Pattern

**File:** `cmd/tui/components/modal.go`

Centralized styling:

```go
type Theme struct {
    BorderColor    lipgloss.Color
    TitleColor     lipgloss.Color
    ContentColor   lipgloss.Color
    SelectedColor  lipgloss.Color
}

var DefaultTheme = Theme{
    BorderColor:   lipgloss.Color("63"),
    TitleColor:    lipgloss.Color("86"),
    ContentColor:  lipgloss.Color("252"),
    SelectedColor: lipgloss.Color("212"),
}
```

## State Management Patterns

### Packet Buffer Management

Limited buffer to prevent memory growth:

```go
const maxPackets = 1000

func (m *model) addPackets(packets []types.PacketDisplay) {
    m.packets = append(m.packets, packets...)

    if len(m.packets) > maxPackets {
        // Keep most recent
        m.packets = m.packets[len(m.packets)-maxPackets:]
    }
}
```

### Node Management

**File:** `cmd/tui/components/nodesview.go`

Nodes loaded from YAML file:

```yaml
processors:
  - name: "central"
    address: "processor:50051"
    tls:
      enabled: true
      ca_file: "ca.crt"

hunters:
  - name: "edge-01"
    address: "hunter:50051"
```

**In-memory state:**
```go
type NodesView struct {
    processors []ProcessorNode
    hunters    []HunterNode
    nodesFile  string  // Path to YAML
}
```

**Persistence:** Changes written back to YAML file.

## Performance Considerations

### Rendering Optimization

**Viewport pattern** - only render visible rows:

```go
viewportHeight := m.height - headerHeight - footerHeight
startIdx := m.scrollOffset
endIdx := min(startIdx + viewportHeight, len(m.packets))

for i := startIdx; i < endIdx; i++ {
    view += renderPacket(m.packets[i])
}
```

### Packet Display Filtering

Filter before rendering:

```go
filtered := make([]types.PacketDisplay, 0, len(m.packets))
for _, pkt := range m.packets {
    if m.matchesFilter(pkt) {
        filtered = append(filtered, pkt)
    }
}
```

## Error Handling Patterns

### Graceful Degradation

```go
if err := m.remoteCapture.Connect(); err != nil {
    m.toast.Show("Failed to connect: " + err.Error(), ToastError)
    // Fall back to offline mode
    m.switchToOfflineMode()
}
```

### User Feedback

Always show errors via Toast:

```go
if err != nil {
    m.toast.Show(err.Error(), ToastError, ToastDurationLong)
}
```

## Testing Considerations

### Unit Testing

Mock EventHandler:

```go
type mockEventHandler struct {
    packets []types.PacketDisplay
}

func (m *mockEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
    m.packets = append(m.packets, packets...)
}
```

### Component Testing

Test components in isolation:

```go
func TestProtocolSelector(t *testing.T) {
    ps := NewProtocolSelector()
    ps.Activate()

    // Simulate key press
    cmd := ps.Update(tea.KeyMsg{Type: tea.KeyDown})

    // Verify state
    assert.True(t, ps.IsActive())
}
```

## Common Development Tasks

### Adding a New Modal

1. Create component file in `components/`:
```go
type NewModal struct {
    active bool
    // ... state
}

func (nm *NewModal) IsActive() bool { return nm.active }
func (nm *NewModal) Activate() { nm.active = true }
func (nm *NewModal) Deactivate() { nm.active = false }

func (nm *NewModal) View() string {
    if !nm.active {
        return ""
    }

    content := buildContent()

    return RenderModal(ModalRenderOptions{
        Title:   "New Modal",
        Content: content,
        Footer:  "Enter: OK | Esc: Cancel",
    })
}
```

2. Add to model:
```go
type model struct {
    newModal *NewModal
}
```

3. Route events in Update()

4. Render in View()

### Adding a Capture Mode

1. Implement CaptureMode interface
2. Add to model as field
3. Add mode selection logic
4. Update view renderer

## Dependencies

**External:**
- `github.com/charmbracelet/bubbletea` - TUI framework
- `github.com/charmbracelet/lipgloss` - Styling
- `github.com/google/gopacket` - Packet capture (live/offline)
- `google.golang.org/grpc` - Remote mode

**Internal:**
- `internal/pkg/remotecapture` - Remote capture client
- `internal/pkg/types` - Shared types (PacketDisplay, EventHandler)
- `internal/pkg/voip` - VoIP analysis (live mode)

## Related Documentation

- [README.md](README.md) - User-facing TUI documentation
- [../process/CLAUDE.md](../process/CLAUDE.md) - Processor architecture (remote mode target)
- [../../internal/pkg/remotecapture/CLAUDE.md](../../internal/pkg/remotecapture/CLAUDE.md) - Remote capture client (if exists)
- [../../docs/TUI_REMOTE_CAPTURE.md](../../docs/TUI_REMOTE_CAPTURE.md) - Remote capture guide
