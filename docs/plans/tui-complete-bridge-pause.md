# TUI Complete Bridge Pause

## Problem

When capture is paused in `lc watch live`, only the UI stops pulling packets. The entire upstream pipeline continues running, wasting CPU and memory:

- Capture source keeps reading from network
- Bridge keeps converting packets
- Consumer keeps buffering

**Goal**: Paused capture should be basically idle.

## Current vs Target

```
                    CURRENT (paused)              TARGET (paused)
Network          →  still read                 →  still read (unavoidable)
PacketBuffer     →  still sending              →  BLOCKED
Bridge           →  still converting           →  BLOCKED
Consumer         →  still buffering            →  IDLE
pendingPackets   →  capped at 5000 (quick fix) →  IDLE
```

## Design

Use a **pause channel signal** passed through the pipeline. When closed, goroutines block. On resume, create a new open channel.

```go
type PauseSignal struct {
    mu       sync.RWMutex
    ch       chan struct{}
    paused   bool
}

func (p *PauseSignal) Pause()           // closes ch, sets paused=true
func (p *PauseSignal) Resume()          // creates new ch, sets paused=false
func (p *PauseSignal) IsPaused() bool   // returns paused state
func (p *PauseSignal) C() <-chan struct{} // returns current channel for select
func (p *PauseSignal) Wait()            // blocks until resumed
```

## Implementation

### Phase 1: Add PauseSignal Type

**File**: `internal/pkg/tui/pause_signal.go` (new)

```go
type PauseSignal struct {
    mu     sync.RWMutex
    ch     chan struct{}
    paused bool
}

func NewPauseSignal() *PauseSignal {
    return &PauseSignal{ch: make(chan struct{})}
}

func (p *PauseSignal) Pause() {
    p.mu.Lock()
    defer p.mu.Unlock()
    if !p.paused {
        close(p.ch)
        p.paused = true
    }
}

func (p *PauseSignal) Resume() {
    p.mu.Lock()
    defer p.mu.Unlock()
    if p.paused {
        p.ch = make(chan struct{})
        p.paused = false
    }
}

func (p *PauseSignal) IsPaused() bool {
    p.mu.RLock()
    defer p.mu.RUnlock()
    return p.paused
}

// C returns channel for use in select. Closed when paused.
func (p *PauseSignal) C() <-chan struct{} {
    p.mu.RLock()
    defer p.mu.RUnlock()
    return p.ch
}

// Wait blocks until resumed. Call only when paused.
func (p *PauseSignal) Wait() {
    p.mu.RLock()
    ch := p.ch
    p.mu.RUnlock()

    // Wait for new channel (resume creates new one)
    for {
        p.mu.RLock()
        newCh := p.ch
        paused := p.paused
        p.mu.RUnlock()

        if !paused && newCh != ch {
            return
        }
        time.Sleep(10 * time.Millisecond)
    }
}
```

### Phase 2: Wire PauseSignal to CaptureState

**File**: `internal/pkg/tui/capture_state.go`

```go
type CaptureState struct {
    mu          sync.RWMutex
    handle      *captureHandle
    program     *tea.Program
    pauseSignal *PauseSignal  // ADD
}

func (cs *CaptureState) GetPauseSignal() *PauseSignal  // ADD
```

### Phase 3: Modify Bridge to Block on Pause

**File**: `internal/pkg/tui/bridge.go`

Change `StartPacketBridge` signature:
```go
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program, pause *PauseSignal)
```

Modify main loop:
```go
for {
    // Check pause first
    if pause.IsPaused() {
        sendBatch() // Flush current batch
        pause.Wait() // Block until resumed
        continue
    }

    select {
    case <-pause.C():
        // Pause signaled mid-select
        continue // Will hit IsPaused() check above

    case pktInfo, ok := <-packetChan:
        if !ok {
            sendBatch()
            close(tuiBatchChan)
            <-consumerDone
            return
        }
        // ... existing packet processing ...

    case <-ticker.C:
        sendBatch()
    }
}
```

### Phase 4: Modify Consumer Goroutine

**File**: `internal/pkg/tui/bridge.go`

In consumer goroutine:
```go
go func() {
    defer close(consumerDone)
    for {
        select {
        case msg, ok := <-tuiBatchChan:
            if !ok {
                return
            }
            if !pause.IsPaused() {
                pendingPackets.addPackets(msg.Packets)
            }
            // When paused, discard (bridge already blocked, so minimal packets)
        }
    }
}()
```

### Phase 5: Modify Capture Source (Optional Enhancement)

**File**: `internal/pkg/capture/capture.go`

For deeper pause, modify `captureFromInterface` to accept pause signal:
```go
func captureFromInterface(ctx context.Context, iface pcaptypes.PcapInterface,
    filter string, buffer *PacketBuffer, pauseSignal <-chan struct{})
```

Add pause check before `buffer.Send()`:
```go
select {
case <-pauseSignal:
    continue // Drop packet when paused
default:
    buffer.Send(pktInfo)
}
```

**Note**: This requires changing `capture.InitWithContext` signature to pass pause signal. Consider if the added complexity is worth it - the bridge-level pause may be sufficient.

### Phase 6: Wire Keyboard Handler

**File**: `internal/pkg/tui/keyboard_handler.go`

Replace `SetBridgePaused()` calls with:
```go
case " ":
    m.uiState.Paused = !m.uiState.Paused
    if m.uiState.Paused {
        globalCaptureState.GetPauseSignal().Pause()
    } else {
        globalCaptureState.GetPauseSignal().Resume()
    }
    // ... toast messages ...
```

### Phase 7: Initialize on Capture Start

**File**: `internal/pkg/tui/capture_lifecycle.go`

In `handleStartCaptureMsg`:
```go
// Reset pause state when starting capture
globalCaptureState.GetPauseSignal().Resume()
```

## Files Modified

| File | Changes |
|------|---------|
| `internal/pkg/tui/pause_signal.go` | New file |
| `internal/pkg/tui/capture_state.go` | Add PauseSignal field |
| `internal/pkg/tui/bridge.go` | Add pause signal param, modify main loop & consumer |
| `internal/pkg/tui/keyboard_handler.go` | Call Pause()/Resume() |
| `internal/pkg/tui/capture_lifecycle.go` | Pass pause signal to bridge, reset on start |
| `internal/pkg/capture/capture.go` | (Optional) Add pause signal to source |

## Testing

- [ ] Pause during active capture - verify CPU drops to near-idle
- [ ] Resume after pause - verify packets flow again
- [ ] Pause → Stop → Start new capture - verify clean state
- [ ] Pause during high traffic - verify no memory growth
- [ ] Rapid pause/resume toggling - verify no deadlock
- [ ] Pause in offline mode (PCAP playback) - verify works correctly

## Cleanup

After implementation, remove the quick-fix code:
- Remove `bridgePaused` global variable from `bridge.go`
- Remove `SetBridgePaused()`/`IsBridgePaused()` functions
- Remove pause check from `addPackets()` (pause happens upstream now)

## Limitations

- **OS kernel still buffers**: Cannot prevent libpcap/kernel from queuing packets during pause. On resume, there may be a burst of queued packets.
- **Packet loss during pause**: Expected behavior - pause means "stop monitoring", not "buffer everything".
