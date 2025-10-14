# Settings Architecture

This package implements a polymorphic mode-based architecture for the settings component, replacing conditional mode logic with object-oriented delegation.

## Overview

The settings component supports three capture modes:
- **Live**: Capture from network interfaces in real-time
- **Offline**: Read from a PCAP file
- **Remote**: Connect to remote processor/hunter nodes

Each mode has different fields, validation rules, and behavior. The traditional approach would use conditional logic (`if mode == Live`), but this package uses **polymorphism** via the `ModeSettings` interface.

## Architecture

### Core Interface: `ModeSettings`

All capture modes implement the `ModeSettings` interface:

```go
type ModeSettings interface {
    Validate() error
    ToRestartMsg() RestartCaptureMsg
    Render(params RenderParams) []string
    HandleKey(key string, params KeyHandlerParams) KeyHandlerResult
    GetFocusableFieldCount() int
    GetBufferSize() int
    GetBPFFilter() string
    SetSize(width, height int)
    UpdateTheme(theme themes.Theme)
    Update(msg tea.Msg, focusIndex int) tea.Cmd
}
```

### Mode Implementations (Phase 1.5)

Each mode is a self-contained struct:

- **`LiveSettings`**: Encapsulates interface list, promiscuous mode, buffer, filter
- **`OfflineSettings`**: Encapsulates PCAP file path, buffer, filter
- **`RemoteSettings`**: Encapsulates nodes file path, buffer (no filter)

### Factory Pattern

The `ModeFactory` centralizes mode creation:

```go
factory := NewModeFactory(theme)
mode := factory.CreateMode(CaptureModeLive, bufferSize, ...)
```

This enables:
- Easy mode switching with preserved settings
- Centralized initialization logic
- Testable mode creation

### Parent Component: `SettingsView` (Phase 1.6)

The parent `SettingsView` becomes a thin coordinator:

```go
type SettingsView struct {
    currentMode ModeSettings  // Polymorphic mode reference
    modeType    CaptureMode
    factory     *ModeFactory
    // ... other fields (file dialogs, viewport, theme, etc.)
}
```

The parent handles:
- Mode switching
- Mode selector UI
- Common UI chrome (title, help text, errors)
- File dialogs
- Window resizing

The parent **delegates** to the mode:
- Validation: `currentMode.Validate()`
- Rendering: `currentMode.Render(params)`
- Input handling: `currentMode.HandleKey(key, params)`

## Benefits

### 1. Eliminates Conditionals

**Before:**
```go
func (s *SettingsView) View() string {
    if s.captureMode == CaptureModeLive {
        // 100 lines of live mode rendering
    } else if s.captureMode == CaptureModeOffline {
        // 80 lines of offline mode rendering
    } else if s.captureMode == CaptureModeRemote {
        // 60 lines of remote mode rendering
    }
}
```

**After:**
```go
func (s *SettingsView) View() string {
    sections := []string{title, modeSelector}
    sections = append(sections, s.currentMode.Render(params)...)
    sections = append(sections, helpText)
    return joinSections(sections)
}
```

### 2. Testable in Isolation

Each mode can be tested independently:

```go
func TestLiveSettingsValidation(t *testing.T) {
    mode := NewLiveSettings("eth0", 10000, false, "", theme)
    err := mode.Validate()
    assert.NoError(t, err)
}
```

No need to set up the entire SettingsView component!

### 3. Easy to Extend

Adding a new capture mode (e.g., "Cloud" mode):

1. Create `CloudSettings` struct
2. Implement `ModeSettings` interface
3. Add case to factory
4. Done!

No changes needed in SettingsView.

### 4. Clear Separation of Concerns

- **Mode implementations**: Know how to validate, render, and handle their specific fields
- **SettingsView**: Knows how to coordinate modes, handle mode switching, and manage UI chrome
- **Factory**: Knows how to create and transition between modes

## File Structure

```
cmd/tui/components/settings/
├── README.md        # This file - architecture documentation
├── mode.go          # ModeSettings interface and common types
├── factory.go       # ModeFactory for creating modes
├── live.go          # LiveSettings implementation (Phase 1.5)
├── offline.go       # OfflineSettings implementation (Phase 1.5)
└── remote.go        # RemoteSettings implementation (Phase 1.5)
```

## Implementation Phases

### Phase 1.4 (Complete)
- ✅ Design `ModeSettings` interface
- ✅ Define supporting types (`RenderParams`, `KeyHandlerResult`, etc.)
- ✅ Design `ModeFactory` pattern
- ✅ Document architecture

### Phase 1.5 (Next)
- Implement `LiveSettings` (~400 lines)
- Implement `OfflineSettings` (~250 lines)
- Implement `RemoteSettings` (~200 lines)
- Add unit tests for each mode

### Phase 1.6 (Final)
- Refactor `SettingsView` to delegate to modes
- Remove mode-specific conditionals
- Reduce `settings.go` from 1,562 to ~350 lines
- Achieve 78% code reduction with better architecture

## Why This Approach?

### Previous Attempt (Failed)

The first attempt extracted "rendering helpers" and "key handlers" into separate files:
- Created `live_mode.go`, `offline_mode.go`, `remote_mode.go` with helper functions
- Helper functions took massive parameter structs
- Still had tight coupling to parent state
- **Net result**: +754 lines of wrapper code, minimal benefit

### Current Approach (Correct)

This approach creates **self-contained mode objects** that:
- Own their state (fields, inputs, selections)
- Own their behavior (validation, rendering, input handling)
- Hide implementation details from parent
- **Net result**: Better architecture, fewer lines, easier to test

## Usage Example

```go
// In SettingsView initialization
factory := NewModeFactory(theme)
currentMode := factory.CreateMode(CaptureModeLive, 10000, "", "any", false, "", "")

// In View()
sections := s.currentMode.Render(RenderParams{
    Width: s.width,
    FocusIndex: s.focusIndex,
    Editing: s.editing,
    Theme: s.theme,
    // ... styles
})

// In Update()
result := s.currentMode.HandleKey("enter", KeyHandlerParams{
    FocusIndex: s.focusIndex,
    Editing: s.editing,
})
if result.TriggerRestart {
    msg := s.currentMode.ToRestartMsg()
    // ... restart capture
}

// Mode switching
if userSwitchedMode {
    s.currentMode = s.factory.SwitchMode(newModeType, s.currentMode)
}
```

## Design Principles

1. **Polymorphism over conditionals**: Use interface methods, not `if mode ==`
2. **Encapsulation**: Modes own their state and hide implementation details
3. **Single Responsibility**: Each mode handles only its own logic
4. **Open/Closed**: Easy to extend (add modes) without modifying existing code
5. **Dependency Inversion**: Parent depends on interface, not concrete modes

## References

- REFACTOR.md Phases 1.4-1.6
- Original settings.go: cmd/tui/components/settings.go (1,562 lines)
