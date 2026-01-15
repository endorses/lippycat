# TUI Live Capture Packet Freeze Analysis

**Date:** 2025-01-15
**Status:** Analysis Complete
**Severity:** High

## Executive Summary

During high-volume live capture, the TUI stops receiving packets after running for a variable period. The capture appears frozen but is still running internally. Restarting the capture (switching modes or changing BPF filter) temporarily resolves the issue until it recurs.

**Root Cause:** A producer-consumer deadlock caused by `tea.Program.Send()` blocking when the TUI's `Update()` loop falls behind packet ingestion rate.

## Symptom Description

- TUI works correctly at startup
- After variable duration (depends on packet rate), packets stop appearing
- Status bar may still show activity, but packet list freezes
- Restarting capture temporarily fixes the issue
- Issue recurs under sustained high packet rates

## Architecture Overview

```
┌─────────────────┐    packetChan     ┌─────────────────┐   program.Send()  ┌─────────────────┐
│  Capture        │ ───────────────▶  │  Bridge         │ ───────────────▶  │  TUI Update()   │
│  Goroutine      │                   │  Goroutine      │                   │  Loop           │
│  (gopacket)     │                   │  (bridge.go)    │                   │  (Bubbletea)    │
└─────────────────┘                   └─────────────────┘                   └─────────────────┘
```

**Data Flow:**
1. Capture goroutine reads packets from network interface via gopacket
2. Packets are sent to `packetChan` (buffered channel)
3. Bridge goroutine reads from `packetChan`, batches packets, converts to `PacketDisplay`
4. Bridge calls `program.Send(PacketBatchMsg{...})` to deliver to TUI
5. TUI's `Update()` processes batches via `handlePacketBatchMsg()`

## Root Cause Analysis

### Primary Issue: Blocking `tea.Program.Send()`

**Location:** `internal/pkg/tui/bridge.go:175`

```go
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program) {
    // ...
    sendBatch := func() {
        if len(batch) > 0 {
            program.Send(PacketBatchMsg{Packets: batch})  // <-- BLOCKS HERE
            // ...
        }
    }
    // ...
}
```

**Problem:**
`tea.Program.Send()` is synchronous. It sends messages to Bubbletea's internal message channel. When the TUI's `Update()` handler is slow, this channel fills up and `Send()` blocks indefinitely.

**Impact:**
When `Send()` blocks, the bridge goroutine stops reading from `packetChan`. This causes:
1. `packetChan` to fill up
2. Capture goroutine to block on channel send
3. Entire packet pipeline to stall

### Secondary Issue: Expensive `Update()` Processing

**Location:** `internal/pkg/tui/capture_events.go:24-121`

The `handlePacketBatchMsg()` function performs extensive synchronous work:

```go
func (m Model) handlePacketBatchMsg(msg PacketBatchMsg) (Model, tea.Cmd) {
    if !m.uiState.Paused {
        for _, packet := range msg.Packets {
            // Per-packet operations (lines 27-96):
            m.packetStore.AddPacket(packet)           // Mutex lock + filter eval
            m.offlineCallAggregator.ProcessPacket()   // VoIP state tracking
            parseDNSFromRawData()                     // Expensive parsing
            parseHTTPFromRawData()                    // Expensive parsing
            m.updateStatistics(packet)               // Statistics update
        }

        // Throttled but still expensive (lines 98-118):
        if now.Sub(m.lastPacketListUpdate) >= interval {
            m.uiState.PacketList.SetPackets(m.getPacketsInOrder())  // O(n) copy
        }

        if m.uiState.ShowDetails {
            m.updateDetailsPanel()  // Potentially expensive rendering
        }
    }
    return m, nil
}
```

**Cost Breakdown per Batch:**

| Operation | Location | Complexity | Notes |
|-----------|----------|------------|-------|
| `AddPacket()` | Line 49 | O(1) per packet | Mutex lock + filter chain evaluation |
| `ProcessPacket()` | Lines 52-60 | O(1) per packet | VoIP call state machine updates |
| DNS parsing | Lines 64-70 | O(payload) | Full packet re-parsing from raw bytes |
| HTTP parsing | Lines 79-86 | O(payload) | Full packet re-parsing from raw bytes |
| `updateStatistics()` | Line 95 | O(1) per packet | Counter updates |
| `GetPacketsInOrder()` | Line 103 | **O(buffer_size)** | Full circular buffer copy every 100ms |
| `updateDetailsPanel()` | Line 116 | O(packet_size) | Hex dump rendering |

### Tertiary Issue: Rolling Window Memory Growth

**Location:** `internal/pkg/tui/bridge.go:166, 233`

```go
var recentPackets []time.Time  // Line 166

// In the loop:
recentPackets = append(recentPackets, time.Now())  // Line 233
```

**Problem:**
The `recentPackets` slice tracks packet timestamps for rate calculation. While old entries are trimmed periodically (every 100ms), the slice's underlying capacity is never reduced. Over time:
- Slice capacity grows to peak packet count
- Memory is retained even after traffic decreases
- GC pressure increases due to large retained allocations

### Quaternary Issue: Inefficient Packet Store Operations

**Location:** `internal/pkg/tui/store/packet_store.go:64-97`

```go
func (ps *PacketStore) GetPacketsInOrder() []components.PacketDisplay {
    ps.mu.RLock()
    defer ps.mu.RUnlock()

    // Always creates full copy of buffer
    result := make([]components.PacketDisplay, bufferSize)
    for i := range bufferSize {
        result[i] = ps.Packets[(ps.PacketsHead+i)%bufferSize]
    }
    return result
}
```

**Problem:**
Every packet list update (at 10Hz by default) creates a complete copy of the circular buffer. With default buffer size of 10,000 packets:
- 10,000 allocations + copies per update
- 100,000 allocations per second
- Significant GC pressure

## The Deadlock Sequence

```
1. High packet rate begins
         ↓
2. Update() takes longer than batch interval
         ↓
3. Bubbletea message queue fills up
         ↓
4. program.Send() blocks in bridge goroutine
         ↓
5. Bridge stops reading from packetChan
         ↓
6. packetChan fills up (default buffer: 1000)
         ↓
7. Capture goroutine blocks on channel send
         ↓
8. No new packets reach TUI
         ↓
9. User perceives "freeze" - UI responsive but no new data
```

## Why Restart Temporarily Fixes It

When user changes BPF filter or switches capture mode:

1. `globalCaptureState.StopCapture()` is called
2. Capture context is cancelled
3. Capture goroutine exits, closing `packetChan`
4. Bridge goroutine receives channel close, exits loop (`bridge.go:224-228`)
5. `program.Send()` unblocks (goroutine exits)
6. New capture creates fresh channels with empty buffers
7. Cycle repeats when Update() falls behind again

## Recommendations

### Fix 1: Non-Blocking Send with Backpressure (Critical)

Replace direct `program.Send()` with non-blocking channel send:

```go
// bridge.go - proposed change
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program) {
    // Add metrics for monitoring
    var droppedBatches int64

    sendBatch := func() {
        if len(batch) > 0 {
            // Non-blocking send with backpressure handling
            select {
            case tuiBatchChan <- PacketBatchMsg{Packets: batch}:
                // Successfully queued
            default:
                // TUI behind - drop oldest batch to prevent blocking
                atomic.AddInt64(&droppedBatches, 1)
                // Optionally: try to drain one old batch and send new one
            }
            displayedCount += int64(len(batch))
            batch = make([]components.PacketDisplay, 0, 100)
        }
    }
    // ...
}
```

**Alternative:** Use `program.Send()` in a separate goroutine with timeout:

```go
sendBatch := func() {
    if len(batch) > 0 {
        batchCopy := batch
        batch = make([]components.PacketDisplay, 0, 100)

        go func() {
            // Send with timeout to prevent indefinite blocking
            done := make(chan struct{})
            go func() {
                program.Send(PacketBatchMsg{Packets: batchCopy})
                close(done)
            }()

            select {
            case <-done:
                // Sent successfully
            case <-time.After(100 * time.Millisecond):
                // TUI too slow, batch dropped
                atomic.AddInt64(&droppedBatches, 1)
            }
        }()
    }
}
```

### Fix 2: Reduce Update() Processing Time (High Priority)

Move expensive operations off the hot path:

```go
// capture_events.go - proposed changes

func (m Model) handlePacketBatchMsg(msg PacketBatchMsg) (Model, tea.Cmd) {
    if m.uiState.Paused {
        return m, nil
    }

    // Batch add packets (single lock acquisition)
    m.packetStore.AddPacketBatch(msg.Packets)

    // Queue async processing for non-critical operations
    if m.asyncProcessor != nil {
        m.asyncProcessor.QueueBatch(msg.Packets)
    }

    // Only update UI at throttled rate (already exists, but make it stricter)
    now := time.Now()
    if now.Sub(m.lastPacketListUpdate) >= m.packetListUpdateInterval {
        // Use incremental update instead of full copy
        m.uiState.PacketList.AppendPackets(msg.Packets)
        m.lastPacketListUpdate = now
    }

    return m, nil
}
```

### Fix 3: Incremental Packet List Updates (Medium Priority)

Replace full buffer copy with incremental updates:

```go
// packet_store.go - proposed addition

// AppendRecent returns only packets added since last call
func (ps *PacketStore) AppendRecent(lastSeenIndex int) ([]components.PacketDisplay, int) {
    ps.mu.RLock()
    defer ps.mu.RUnlock()

    if ps.PacketsCount <= lastSeenIndex {
        return nil, lastSeenIndex
    }

    newCount := ps.PacketsCount - lastSeenIndex
    result := make([]components.PacketDisplay, newCount)
    // Copy only new packets
    // ...
    return result, ps.PacketsCount
}
```

### Fix 4: Fix Rolling Window Memory (Low Priority)

Periodically compact the slice:

```go
// bridge.go - proposed change

// In getSamplingRatio():
if now.Sub(lastRateCheck) > constants.TUITickInterval {
    cutoff := now.Add(-rateWindowSize)
    i := 0
    for i < len(recentPackets) && recentPackets[i].Before(cutoff) {
        i++
    }

    // Compact slice to reclaim memory
    if i > 0 {
        copy(recentPackets, recentPackets[i:])
        recentPackets = recentPackets[:len(recentPackets)-i]

        // Periodically reallocate to reduce capacity
        if cap(recentPackets) > 10000 && len(recentPackets) < cap(recentPackets)/4 {
            newSlice := make([]time.Time, len(recentPackets))
            copy(newSlice, recentPackets)
            recentPackets = newSlice
        }
    }
    lastRateCheck = now
}
```

### Fix 5: Add Monitoring/Diagnostics (Recommended)

Add visibility into backpressure:

```go
// Add to bridge.go
type BridgeStats struct {
    PacketsReceived   int64
    PacketsDisplayed  int64
    BatchesSent       int64
    BatchesDropped    int64
    SendBlockTimeNs   int64
    CurrentRate       float64
}

// Expose via statistics view in TUI
```

## Implementation Priority

| Priority | Fix | Effort | Impact |
|----------|-----|--------|--------|
| **Critical** | Non-blocking Send | Medium | Eliminates deadlock |
| **High** | Reduce Update() time | Medium | Reduces backpressure |
| **Medium** | Incremental list updates | High | Reduces CPU/memory |
| **Low** | Rolling window fix | Low | Reduces memory over time |
| **Recommended** | Diagnostics | Low | Improves debugging |

## Testing Recommendations

1. **Reproduce consistently:** Use `tcpreplay` to replay a high-rate PCAP at 10,000+ pps
2. **Add instrumentation:** Log `Send()` duration and queue depths
3. **Monitor GC:** Run with `GODEBUG=gctrace=1` to observe GC pressure
4. **Stress test:** Run for extended periods (30+ minutes) at various rates

## Related Files

- `internal/pkg/tui/bridge.go` - Packet bridge (primary fix location)
- `internal/pkg/tui/capture_events.go` - Update() handler (secondary fix location)
- `internal/pkg/tui/store/packet_store.go` - Packet storage
- `internal/pkg/tui/capture_state.go` - Capture lifecycle management

## References

- [Bubbletea Program.Send() documentation](https://pkg.go.dev/github.com/charmbracelet/bubbletea#Program.Send)
- Go channel semantics and blocking behavior
- Producer-consumer patterns in concurrent systems
