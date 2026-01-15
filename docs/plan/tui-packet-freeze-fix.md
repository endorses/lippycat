# TUI Packet Freeze Fix Implementation Plan

**Reference:** [Research Analysis](../research/tui-packet-freeze-analysis.md)
**Created:** 2025-01-15

## Overview

Fix the producer-consumer deadlock in TUI live capture that causes packets to stop flowing under high load.

## Phase 1: Critical - Eliminate Deadlock

### 1.1 Non-Blocking Send in Bridge

**File:** `internal/pkg/tui/bridge.go`

- [x] Add intermediate buffered channel between bridge and TUI (capacity ~10 batches)
- [x] Replace direct `program.Send()` with non-blocking channel send
- [x] Add dropped batch counter for diagnostics
- [x] Start consumer goroutine that reads from buffer and calls `program.Send()`
- [x] Handle graceful shutdown of consumer goroutine

```go
// Target pattern:
tuiBatchChan := make(chan PacketBatchMsg, 10)

// In sendBatch():
select {
case tuiBatchChan <- PacketBatchMsg{Packets: batch}:
default:
    droppedBatches++
}

// Separate goroutine:
go func() {
    for msg := range tuiBatchChan {
        program.Send(msg)
    }
}()
```

## Phase 2: High Priority - Reduce Update() Load

### 2.1 Batch Packet Store Operations

**File:** `internal/pkg/tui/store/packet_store.go`

- [x] Add `AddPacketBatch(packets []PacketDisplay)` method
- [x] Single mutex acquisition for entire batch
- [x] Batch filter evaluation

### 2.2 Defer Non-Critical Processing

**File:** `internal/pkg/tui/capture_events.go`

- [x] Move DNS/HTTP parsing to background goroutine
- [x] Move call aggregator processing to background goroutine
- [x] Keep only essential operations in `handlePacketBatchMsg()`:
  - Packet store addition
  - Basic statistics update
  - Throttled UI refresh

### 2.3 Reduce UI Update Frequency Under Load

**File:** `internal/pkg/tui/capture_events.go`

- [x] Implement adaptive throttling based on batch queue depth
- [x] Skip details panel updates when queue is backing up
- [x] Increase packet list update interval under load (100ms → 200ms)

## Phase 3: Medium Priority - Optimize Packet List

### 3.1 Incremental Packet List Updates

**File:** `internal/pkg/tui/store/packet_store.go`

- [ ] Add `GetRecentPackets(sinceIndex int)` method returning only new packets
- [ ] Track high-water mark in packet list component
- [ ] Update `PacketList.AppendPackets()` to use incremental data

### 3.2 Lazy Filtered Packet Generation

**File:** `internal/pkg/tui/store/packet_store.go`

- [ ] Only recompute filtered list when filter changes
- [ ] Incrementally add matching packets to filtered list
- [ ] Avoid full re-filter on every batch

## Phase 4: Low Priority - Memory Optimization

### 4.1 Fix Rolling Window Memory Leak

**File:** `internal/pkg/tui/bridge.go`

- [x] Compact `recentPackets` slice after trimming old entries
- [x] Periodically reallocate when capacity >> length
- [ ] Consider using ring buffer instead of slice

## Phase 5: Diagnostics

### 5.1 Add Bridge Statistics

**File:** `internal/pkg/tui/bridge.go`

- [x] Track packets received, displayed, dropped
- [ ] Track batch queue depth
- [ ] Track send blocking time

### 5.2 Expose in Statistics View

**File:** `internal/pkg/tui/components/statistics.go`

- [ ] Add "Bridge" section showing:
  - Packets received vs displayed
  - Batches dropped (backpressure indicator)
  - Current sampling ratio

## Testing Checklist

- [ ] Test with `tcpreplay` at 1,000 pps - should run indefinitely
- [ ] Test with `tcpreplay` at 10,000 pps - should run indefinitely with sampling
- [ ] Test with `tcpreplay` at 50,000 pps - should run with high drop rate but no freeze
- [ ] Verify restart still works correctly after changes
- [ ] Verify filter changes work correctly
- [ ] Verify mode switching works correctly
- [ ] Run extended test (1+ hour) at moderate rate

## Rollback Plan

If issues arise, changes can be reverted per-phase since each phase is independent. Phase 1 is the critical fix; phases 2-5 are optimizations.

## Dependencies

- No external dependencies
- No API changes
- Internal refactoring only
